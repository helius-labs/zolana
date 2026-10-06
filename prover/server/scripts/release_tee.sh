#!/usr/bin/env bash
# Deploys the prover and a co-hosted Photon to a Phala Cloud TDX CVM and pins it into the SDKs.
set -euo pipefail

usage() {
    echo "usage: $0 <prover-image@sha256:digest> <cvm-name> (--photon <image@sha256:digest> | --external-indexer <https-url>) [--photon-dump-sha256 <digest>] [--gpu] [--update] [--replace] [--plan]" >&2
    exit 1
}
[[ $# -ge 2 ]] || usage
prover_image=$1
name=$2
shift 2
photon_image=""
dump_sha256=""
external=""
gpu=false
update=false
plan=false
replace=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --photon) [[ $# -ge 2 ]] || usage; photon_image=$2; shift ;;
        --photon-dump-sha256) [[ $# -ge 2 ]] || usage; dump_sha256=$2; shift ;;
        --external-indexer) [[ $# -ge 2 ]] || usage; external=$2; shift ;;
        --gpu) gpu=true ;;
        --update) update=true ;;
        --replace) replace=(--replace) ;;
        --plan) plan=true ;;
        *) usage ;;
    esac
    shift
done

pinned() { [[ $1 =~ @sha256:[0-9a-f]{64}$ ]] || { echo "$1 must be pinned by digest" >&2; exit 1; }; }
pinned "$prover_image"
if [[ -n $external ]]; then
    [[ -z $photon_image && -z $dump_sha256 && $external =~ ^https:// ]] || usage
else
    pinned "$photon_image"
    [[ -z $dump_sha256 || $dump_sha256 =~ ^[0-9a-f]{64}$ ]] || usage
fi

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
# shellcheck source=tee_env.sh
source "$here/tee_env.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

postgres=public.ecr.aws/docker/library/postgres:16-bookworm@sha256:efedf3595f1d6f415c08568ba171029bf54052e754cc9f030e3f2412b21f3d67
curl=curlimages/curl:8.16.0@sha256:463eaf6072688fe96ac64fa623fe73e1dbe25d8ad6c34404a669ad3ce1f104b6

if $gpu; then
    instance=${TEE_INSTANCE_TYPE:-h200.small}
    os_image=dstack-nvidia-0.5.9
    gpu_flag=(--gpu-required)
else
    instance=${TEE_INSTANCE_TYPE:-tdx.xlarge}
    os_image=dstack-0.5.9
    gpu_flag=()
fi

# The indexer URL stays in the measured compose, never in the unmeasured env.
{
    cat <<'EOF'
services:
  prover:
    image: @PROVER_IMAGE@
    command:
      - start
      - --require-optimized-build
      - --server-only
      - --auto-download
      - --keys-dir=/proving-keys
      - --prover-address=0.0.0.0:3001
      - --tee=dstack
      - --indexer-url=@INDEXER_URL@
    environment:
      - PROVER_API_KEY
      - PROVER_INDEXER_API_KEY
EOF
    if $gpu; then
        cat <<'EOF'
      - PROVER_BACKEND=aeglos
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
EOF
    fi
    cat <<'EOF'
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
      - proving-keys:/proving-keys
    ports:
      - "3001:3001"
    restart: always
EOF
    if [[ -z $external ]]; then
        cat <<'EOF'
  postgres:
    image: @POSTGRES@
    environment:
      - POSTGRES_DB=photon
      - POSTGRES_USER=photon
      - POSTGRES_PASSWORD=photon
    volumes:
      - photon-db-@DUMP_VOLUME@:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "photon", "-d", "photon"]
      interval: 5s
      retries: 120
    restart: always
  photon-fetch:
    image: @CURL@
    user: "0:0"
    environment:
      - PHOTON_DUMP_URL
    entrypoint: ["/bin/sh", "-ec"]
    command:
      - |
        rm -f /dump/photon.dump
        if [ -z "@DUMP_SHA256@" ]; then
          [ -z "$${PHOTON_DUMP_URL:-}" ] || { echo "no snapshot digest pinned"; exit 1; }
          exit 0
        fi
        [ "$$(cat /dump/restored 2>/dev/null)" != "@DUMP_SHA256@" ] || exit 0
        [ -n "$${PHOTON_DUMP_URL:-}" ] || { echo "snapshot URL required"; exit 1; }
        curl --proto '=https' --proto-redir '=https' -fsS --retry 3 -o /dump/photon.dump "$$PHOTON_DUMP_URL"
    volumes:
      - photon-dump-@DUMP_VOLUME@:/dump
  photon-restore:
    image: @POSTGRES@
    depends_on:
      postgres:
        condition: service_healthy
      photon-fetch:
        condition: service_completed_successfully
    environment:
      - PGPASSWORD=photon
    entrypoint: ["/bin/sh", "-ec"]
    command:
      - |
        [ -f /dump/photon.dump ] || exit 0
        [ -n "@DUMP_SHA256@" ] || { echo "no snapshot digest pinned"; exit 1; }
        echo "@DUMP_SHA256@  /dump/photon.dump" | sha256sum -c -
        pg_restore -h postgres -U photon -d photon --clean --if-exists --single-transaction --exit-on-error --no-owner --no-privileges /dump/photon.dump
        echo "@DUMP_SHA256@" > /dump/restored
        rm /dump/photon.dump
    volumes:
      - photon-dump-@DUMP_VOLUME@:/dump
  photon-migration:
    image: @PHOTON_IMAGE@
    depends_on:
      photon-restore:
        condition: service_completed_successfully
    environment:
      - DATABASE_URL=postgres://photon:photon@postgres:5432/photon
    command: ["photon-migration", "up"]
  photon:
    image: @PHOTON_IMAGE@
    depends_on:
      photon-migration:
        condition: service_completed_successfully
    environment:
      - PHOTON_RPC_URL
    entrypoint: ["/bin/sh", "-ec"]
    command:
      - exec photon --port 8784 --rpc-url "$${PHOTON_RPC_URL:-https://api.devnet.solana.com}" --db-url postgres://photon:photon@postgres:5432/photon --max-db-conn 20 --max-concurrent-block-fetches 10 --logging-format json
    restart: always
EOF
    fi
    echo "volumes:"
    echo "  proving-keys:"
    if [[ -z $external ]]; then
        echo "  photon-db-@DUMP_VOLUME@:"
        echo "  photon-dump-@DUMP_VOLUME@:"
    fi
} > "$work/docker-compose.yml"

# bash 5.2 expands `&` in a replacement, a URL holding one would deploy mangled.
shopt -u patsub_replacement 2>/dev/null || true
compose=$(<"$work/docker-compose.yml")
compose=${compose//@PROVER_IMAGE@/$prover_image}
compose=${compose//@PHOTON_IMAGE@/$photon_image}
compose=${compose//@POSTGRES@/$postgres}
compose=${compose//@CURL@/$curl}
compose=${compose//@DUMP_SHA256@/$dump_sha256}
compose=${compose//@DUMP_VOLUME@/${dump_sha256:-chain}}
compose=${compose//@INDEXER_URL@/${external:-http://photon:8784}}
if $plan; then
    printf '%s\n' "$compose"
    exit 0
fi
printf '%s\n' "$compose" > "$work/docker-compose.yml"
: "${PHALA_KEY:?}" "${PROVER_API_KEY:?}"

# One pre-launch login covers every image, so they share the registry the env names.
for image in "$prover_image" ${photon_image:+"$photon_image"}; do
    [[ ${image%%/*} == "${TEE_REGISTRY_HOST:-${prover_image%%/*}}" ]] \
        || { echo "$image is not in ${TEE_REGISTRY_HOST:-${prover_image%%/*}}" >&2; exit 1; }
done
TEE_REGISTRY_HOST=${TEE_REGISTRY_HOST:-${prover_image%%/*}}
tee_env
deploy=(npx -y phala@1.1.22 deploy --api-key "$PHALA_KEY" --json --wait
    -c "$work/docker-compose.yml" "${TEE_ENV[@]}"
    --no-public-logs --public-sysinfo --public-tcbinfo --no-listed --no-dev-os)
if $update; then
    deploy+=(--cvm-id "$name")
else
    deploy+=(-n "$name" -t "$instance" --image "$os_image" --kms phala --disk-size 200G)
fi
"${deploy[@]}" > "$work/deploy.json"

npx -y phala@1.1.22 cvms get "$name" --api-key "$PHALA_KEY" --json > "$work/cvm.json"
# `deploy` keeps an existing CVM's Trust Center listing, the API turns it off.
if jq -e '.listed' "$work/cvm.json" > /dev/null; then
    curl -fsS -o /dev/null -X PATCH -H "X-API-Key: $PHALA_KEY" -H "Content-Type: application/json" \
        -d '{"listed": false}' "https://cloud-api.phala.network/api/v1/cvms/$(jq -r '.id' "$work/cvm.json")/listed"
    npx -y phala@1.1.22 cvms get "$name" --api-key "$PHALA_KEY" --json > "$work/cvm.json"
fi
app_id=$(jq -er '.app_id' "$work/cvm.json")
base_domain=$(jq -er '.gateway.base_domain' "$work/cvm.json")
jq -e '.public_logs == false and .listed == false' "$work/cvm.json" > /dev/null \
    || { echo "CVM still has public logs or a listing, fix it before pinning" >&2; exit 1; }
prover="https://$app_id-3001.$base_domain"
healthy=false
for _ in $(seq 120); do
    if curl -fsS -o /dev/null "$prover/health"; then
        healthy=true
        break
    fi
    sleep 5
done
$healthy || { echo "prover $prover never became healthy" >&2; exit 1; }

(cd "$root" && cargo run -q -p xtask -- tee-policy "$prover" ${gpu_flag[@]+"${gpu_flag[@]}"} ${replace[@]+"${replace[@]}"})
(cd "$root/sdk-libs/ts" && npx oxfmt --write src/client/prover/tee/default.ts > /dev/null)
echo "prover $prover pinned, commit the policy files with the release"
