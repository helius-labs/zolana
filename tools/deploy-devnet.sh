#!/usr/bin/env bash
# Deploy (or upgrade) the on-chain programs to devnet using the local `solana`
# CLI config (--url / default keypair). Requires the program .so files to
# already exist in target/deploy (run `just build-programs` first) and that
# the local config keypair is the current upgrade authority for each program.
#
# A program's first-ever deploy to its fixed address needs that address's
# private keypair (not just the pubkey), since the account has to be created
# at that exact address. Set ZOLANA_DEVNET_KEYS_DIR to a directory laid out
# as `<dir>/program-id/<pubkey>.json` to supply it; otherwise the script
# falls back to the pubkey alone, which only works once the program already
# exists on-chain (upgrade, not initial deploy).
#
# Avoids bash 4+ features (associative arrays) since macOS ships bash 3.2.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

known_programs="shielded-pool user-registry"

program_so() {
    case "$1" in
        shielded-pool) echo "target/deploy/shielded_pool_program.so" ;;
        user-registry) echo "target/deploy/zolana_user_registry.so" ;;
        *) return 1 ;;
    esac
}

program_id() {
    case "$1" in
        shielded-pool) echo "sppzgEd25DF4PC1FgNerLWVZndUAV82LV9Dy5yCvRVA" ;;
        user-registry) echo "EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc" ;;
        *) return 1 ;;
    esac
}

# --program-id value to actually pass to `solana program deploy`: the
# keypair file when available (works for both initial deploy and upgrade),
# otherwise the bare pubkey (upgrade only).
program_id_arg() {
    local pid
    pid=$(program_id "$1")
    local keypair_path="${ZOLANA_DEVNET_KEYS_DIR:-}/program-id/$pid.json"
    if [[ -n "${ZOLANA_DEVNET_KEYS_DIR:-}" && -f "$keypair_path" ]]; then
        echo "$keypair_path"
    else
        echo "$pid"
    fi
}

if [[ $# -eq 0 ]]; then
    targets="$known_programs"
else
    targets="$*"
fi

for target in $targets; do
    if ! program_so "$target" >/dev/null; then
        echo "unknown program '$target' (known: $known_programs)" >&2
        exit 1
    fi
done

cluster_url=$(solana config get | awk -F': ' '/^RPC URL/ {print $2}')
if [[ "$cluster_url" != *devnet* ]]; then
    echo "solana config RPC URL is '$cluster_url', not devnet." >&2
    echo "Run 'solana config set --url devnet' first, or pass --url explicitly to a manual 'solana program deploy'." >&2
    exit 1
fi

deploy_authority=$(solana address)
echo "Cluster:   $cluster_url"
echo "Authority: $deploy_authority"
echo "Programs:  $targets"
echo

deploy_with_retry() {
    local so_path="$1"
    local pid="$2"
    local max_retries=5
    local attempt=1

    while (( attempt <= max_retries )); do
        echo "Deploying $so_path -> $pid (attempt $attempt/$max_retries)..."
        if solana program deploy "$so_path" --program-id "$pid"; then
            return 0
        fi
        echo "Deploy attempt $attempt failed."
        ((attempt++))
        sleep 2
    done

    echo "Deploy failed after $max_retries attempts: $so_path -> $pid" >&2
    return 1
}

for target in $targets; do
    so_path=$(program_so "$target")
    pid=$(program_id "$target")
    pid_arg=$(program_id_arg "$target")

    if [[ ! -f "$so_path" ]]; then
        echo "missing $so_path -- run 'just build-programs' first" >&2
        exit 1
    fi

    deploy_with_retry "$so_path" "$pid_arg"
    echo "Deployed $target to https://explorer.solana.com/address/$pid?cluster=devnet"
    echo
done
