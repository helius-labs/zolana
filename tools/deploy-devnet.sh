#!/usr/bin/env bash
# Deploy (or upgrade) the on-chain programs to devnet using the local `solana`
# CLI config (--url / default keypair). Requires the program .so files to
# already exist in target/deploy (run `just build-programs` first).
#
# DEPLOYMENT NOTES for the protocol-config initialization gate
# (INV-CREATE-PC-10):
# - Run `cargo run -p xtask -- init-protocol` BEFORE renouncing the upgrade
#   authority or migrating away from loader-v3. Immutable, zero-authority and
#   non-loader-v3 deployments all fail closed and cannot initialize the config.
# - Before the Squads handoff, the local config keypair performs direct
#   deploys/upgrades. After the protocol vault becomes the shielded-pool
#   upgrade authority, set ZOLANA_PROTOCOL_SIGNER_1 and
#   ZOLANA_PROTOCOL_SIGNER_2 to two protocol-member keypair paths. This script
#   then writes a loader buffer and executes the upgrade through Squads.
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

deploy_temp_dir=""
cleanup() {
    if [[ -n "$deploy_temp_dir" && -d "$deploy_temp_dir" ]]; then
        rm -rf -- "$deploy_temp_dir"
    fi
}
trap cleanup EXIT

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
        shielded-pool) echo "sppXZU59VoYodv9Accs4hHNTjYiuYmDFyFVjUjPxFsG" ;;
        user-registry) echo "regyS5rkAcw2YzDJCmTwCTHs2s246FXxbmuRZ42u2PD" ;;
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
payer_keypair=$(solana config get | awk -F': ' '/^Keypair Path/ {print $2}')
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

program_authority() {
    local pid="$1"
    local info
    if ! info=$(solana program show "$pid" --output json-compact 2>/dev/null); then
        return 1
    fi
    printf '%s\n' "$info" \
        | sed -n 's/.*"authority"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

upgrade_shielded_pool_via_squads() {
    local so_path="$1"
    local vault="$2"
    local signer_1="${ZOLANA_PROTOCOL_SIGNER_1:-}"
    local signer_2="${ZOLANA_PROTOCOL_SIGNER_2:-}"
    if [[ -z "$signer_1" || -z "$signer_2" ]]; then
        echo "shielded-pool upgrade authority is Squads vault $vault" >&2
        echo "set ZOLANA_PROTOCOL_SIGNER_1 and ZOLANA_PROTOCOL_SIGNER_2 to two protocol-member keypair paths" >&2
        return 1
    fi
    if [[ ! -f "$payer_keypair" || ! -f "$signer_1" || ! -f "$signer_2" ]]; then
        echo "Squads upgrade requires filesystem keypairs for the payer and both protocol signers" >&2
        return 1
    fi

    # Verify the loader authority is exactly the configured protocol vault and
    # that its Squads settings can be recovered before funding a buffer.
    cargo run -q -p xtask -- upgrade-shielded-pool \
        --cluster devnet --rpc-url "$cluster_url" --payer "$payer_keypair" \
        --protocol-signer "$signer_1" --protocol-signer "$signer_2" \
        --check-only

    deploy_temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/zolana-squads-upgrade.XXXXXX")
    local buffer_keypair="$deploy_temp_dir/buffer.json"
    solana-keygen new --no-bip39-passphrase --silent --force --outfile "$buffer_keypair"
    local buffer
    buffer=$(solana-keygen pubkey "$buffer_keypair")

    echo "Writing loader buffer $buffer..."
    solana program write-buffer "$so_path" \
        --url "$cluster_url" --keypair "$payer_keypair" --fee-payer "$payer_keypair" \
        --buffer "$buffer_keypair" --buffer-authority "$payer_keypair"
    solana program set-buffer-authority "$buffer" \
        --url "$cluster_url" --keypair "$payer_keypair" \
        --buffer-authority "$payer_keypair" --new-buffer-authority "$vault"

    echo "Executing loader upgrade through protocol Squads vault $vault..."
    echo "If execution is interrupted, rerun the xtask with --buffer $buffer; the on-chain buffer remains vault-controlled."
    cargo run -q -p xtask -- upgrade-shielded-pool \
        --cluster devnet --rpc-url "$cluster_url" --payer "$payer_keypair" \
        --protocol-signer "$signer_1" --protocol-signer "$signer_2" \
        --buffer "$buffer"
}

for target in $targets; do
    so_path=$(program_so "$target")
    pid=$(program_id "$target")
    pid_arg=$(program_id_arg "$target")

    if [[ ! -f "$so_path" ]]; then
        echo "missing $so_path -- run 'just build-programs' first" >&2
        exit 1
    fi

    current_authority=""
    if current_authority=$(program_authority "$pid"); then
        if [[ -z "$current_authority" ]]; then
            echo "$target program $pid is immutable; it cannot be upgraded" >&2
            exit 1
        fi
    fi

    if [[ -z "$current_authority" || "$current_authority" == "$deploy_authority" ]]; then
        deploy_with_retry "$so_path" "$pid_arg"
    elif [[ "$target" == "shielded-pool" ]]; then
        upgrade_shielded_pool_via_squads "$so_path" "$current_authority"
    else
        echo "$target upgrade authority is $current_authority, not local signer $deploy_authority" >&2
        exit 1
    fi
    echo "Deployed $target to https://explorer.solana.com/address/$pid?cluster=devnet"
    echo
done
