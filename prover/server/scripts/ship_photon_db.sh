#!/usr/bin/env bash
# Ships a Photon database into the co-hosted Photon of a TEE CVM, restored on its next boot.
set -euo pipefail

usage() {
    echo "usage: $0 <cvm-name> [--dump-url <https-url>] [--stack <name>] [--source-cluster <cluster>] [--source-service <service>]" >&2
    exit 1
}
[[ $# -ge 1 ]] || usage
name=$1
shift
dump_url=""
stack=tee-photon
source_args=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --dump-url) [[ $# -ge 2 ]] || usage; dump_url=$2; shift ;;
        --stack) [[ $# -ge 2 ]] || usage; stack=$2; shift ;;
        --source-cluster | --source-service) [[ $# -ge 2 ]] || usage; source_args+=("$1" "$2"); shift ;;
        *) usage ;;
    esac
    shift
done
: "${PHALA_KEY:?}" "${PROVER_API_KEY:?}"

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
# shellcheck source=tee_env.sh
source "$here/tee_env.sh"
region=${TEE_EXPORT_REGION:-eu-central-1}

if [[ -n $dump_url ]]; then
    [[ $dump_url =~ ^https:// ]] || usage
    PHOTON_DUMP_URL=$dump_url
    PHOTON_DUMP_ID=$(date -u +%Y%m%dT%H%M%SZ)
else
    object=$(python3 "$root/tools/gpu/aws.py" export "$stack" --region "$region" ${source_args[@]+"${source_args[@]}"} | tail -n 1)
    [[ $object =~ ^s3://([^/]+)/(.+)$ ]] || { echo "export printed no object" >&2; exit 1; }
    PHOTON_DUMP_ID=$(aws s3api head-object --region "$region" --bucket "${BASH_REMATCH[1]}" --key "${BASH_REMATCH[2]}" --query ETag --output text | tr -d '"')
    PHOTON_DUMP_URL=$(aws s3 presign "$object" --region "$region" --expires-in 7200)
fi
export PHOTON_DUMP_URL PHOTON_DUMP_ID

: "${TEE_REGISTRY_HOST:?TEE_REGISTRY_HOST names the registry the CVM pulls from}"
tee_env
npx -y phala@1.1.22 envs update "$name" --api-key "$PHALA_KEY" "${TEE_ENV[@]}"
npx -y phala@1.1.22 cvms restart "$name" --api-key "$PHALA_KEY"
echo "dump $PHOTON_DUMP_ID shipped, the CVM restores it on boot and Photon resumes from its last slot"
