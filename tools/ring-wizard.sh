#!/usr/bin/env bash
# Custom ring wizard driver. It prepares what cargo-generate cannot, the program
# keypair, the per-clone service URLs and the pinned zolana revision, runs the
# template, and places the keypair in the generated ring.
#
#   tools/ring-wizard.sh [destination-dir] [cargo generate args...]
#
# RING_NAME skips the name prompt. Extra arguments reach `cargo generate`, for
# example `--silent -d authority_keypair=...` runs without prompts. The generated
# ring clones zolana into `.zolana` at this checkout's HEAD. RING_ZOLANA_PATH=checkout
# points it at this checkout instead, for local development.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
dest="${1:-$(cd "$root/.." && pwd)}"
if [ $# -gt 0 ]; then shift; fi

if ! command -v cargo-generate >/dev/null 2>&1; then
    if [ -t 0 ]; then
        read -rp "cargo-generate is not installed. Install it with cargo now? [Y/n] " answer
        case "${answer:-Y}" in
            [Yy]*) ;;
            *) echo "cargo-generate is required" >&2; exit 1 ;;
        esac
    fi
    cargo install cargo-generate --locked
fi
for tool in solana-keygen just; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required" >&2; exit 1; }
done

name="${RING_NAME:-}"
while [ -z "$name" ]; do
    read -rp "Ring name (kebab-case, becomes the repository name): " name
    if ! [[ "$name" =~ ^[a-z][a-z0-9-]*$ ]]; then
        echo "  use lowercase letters, digits and dashes"
        name=""
    fi
done
if [[ "$name" == */* ]]; then
    echo "name must not contain a path separator" >&2
    exit 2
fi
if [ -e "$dest/$name" ]; then
    echo "destination $dest/$name already exists" >&2
    exit 2
fi

# The program keypair decides the deploy address, so it exists before the
# template renders the program id. It is staged next to the ring, never in a
# system temp dir, and moved into the ring once generated.
mkdir -p "$dest"
keys="$dest/.$name.keys"
rm -rf "$keys"
mkdir -p "$keys"
trap 'rm -rf "$keys"' EXIT
solana-keygen new --no-bip39-passphrase --silent --force -o "$keys/program-keypair.json"
program_id="$(solana-keygen pubkey "$keys/program-keypair.json")"

revision="$(git -C "$root" rev-parse HEAD)"
# Without it the wizard asks, default ~/.config/solana/id.json.
authority=()
if [ -n "${CUSTOM_RING_AUTHORITY_KEYPAIR:-}" ]; then
    authority=(-d authority_keypair="$CUSTOM_RING_AUTHORITY_KEYPAIR")
fi
zolana_path=".zolana"
if [ "${RING_ZOLANA_PATH:-}" = "checkout" ]; then
    zolana_path="$root"
fi

# Service URLs come from the justfile (`just ring-new`), which resolves the
# per-clone port offset and every explicit override; a direct call falls back to
# the offset alone.
offset="${ZOLANA_PORT_OFFSET:-0}"
rpc_url="${ZOLANA_LOCALNET_URL:-http://127.0.0.1:$((8899 + offset))}"
indexer_url="${ZOLANA_LOCALNET_PHOTON_URL:-http://127.0.0.1:$((8784 + offset))}"
prover_url="${ZOLANA_PROVER_URL:-http://127.0.0.1:$((3001 + offset))}"
ring_rpc_port="${ZOLANA_LOCALNET_RING_RPC_PORT:-$((8785 + offset))}"

# Non-interactive runs (`--silent`, or no terminal) answer every question with
# its default; the hook learns that through `silent`.
silent=()
wants_silent=false
for arg in "$@"; do
    [ "$arg" = "--silent" ] && wants_silent=true
done
if [ "$wants_silent" = true ]; then
    silent=(-d silent=true)
elif [ ! -t 0 ]; then
    silent=(-d silent=true --silent)
fi

cargo generate --path "$root/templates/custom-ring" --destination "$dest" --name "$name" \
    ${silent[@]+"${silent[@]}"} \
    ${authority[@]+"${authority[@]}"} \
    -d program_id="$program_id" \
    -d zolana_path="$zolana_path" \
    -d zolana_repository=https://github.com/helius-labs/zolana.git \
    -d zolana_revision="$revision" \
    -d default_rpc_url="$rpc_url" \
    -d default_indexer_url="$indexer_url" \
    -d default_prover_url="$prover_url" \
    -d default_ring_rpc_port="$ring_rpc_port" \
    "$@"

mkdir -p "$dest/$name/keys"
mv "$keys/program-keypair.json" "$dest/$name/keys/program-keypair.json"
# The ring resolves its dependencies exactly as this checkout does.
cp "$root/Cargo.lock" "$dest/$name/Cargo.lock"

cat <<MSG

Generated $dest/$name for program $program_id at zolana $revision.

Next:
  cd $dest/$name
  just localnet     # validator, photon, prover from the zolana source, ring.toml target = localnet
  just devnet       # or photon and prover against devnet, ring.toml target = devnet
  just pipeline     # build, deploy, init, ring rpc, transact on that target
MSG
