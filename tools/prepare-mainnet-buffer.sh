#!/usr/bin/env bash
# Adapted from light-protocol/scripts/deploy/deploy.sh. Uploads a buffer only.
set -euo pipefail
umask 077

if [[ $# != 2 ]]; then
    echo "Usage: $0 PROGRAM_SO BUFFER_KEYPAIR_PATH" >&2
    exit 2
fi
program_so="$1"
buffer_keypair="$2"
program_id=ring1GaLCuJnkUMVkX2JeZLTTX17wKsV4fZmPVzXANW
# Vault 0 of Squads v4 multisig BCurTwuvnYmGdRQYwomHBVz8VUuk2BBVirXpaGvaxXQR.
multisig_vault=Dhf62DbddAc2uDNqnz13W8Z1MpF5MVJ8dvh3Uvhif7Tr
rpc_url="${MAINNET_RPC_URL:-${SOLANA_MAINNET_RPC_URL:-https://api.mainnet-beta.solana.com}}"

[[ -f "$program_so" ]]
[[ $(solana genesis-hash --url "$rpc_url") == 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d ]]
program_info=$(solana program show "$program_id" --url "$rpc_url" --output json)
upgrade_authority=$(printf '%s' "$program_info" | python3 -c 'import json,sys; print(json.load(sys.stdin)["authority"] or "")')
capacity=$(printf '%s' "$program_info" | python3 -c 'import json,sys; print(json.load(sys.stdin)["dataLen"])')
if [[ "$upgrade_authority" != "$multisig_vault" ]]; then
    echo 'error: mainnet upgrade authority differs from the verified multisig vault' >&2
    exit 1
fi
program_size=$(wc -c < "$program_so")
if (( program_size > capacity )); then
    echo "ProgramData must grow by $((program_size - capacity)) bytes before the later upgrade."
fi

local_hash=$(solana-verify get-executable-hash "$program_so")
mkdir -p "$(dirname "$buffer_keypair")"
if [[ ! -f "$buffer_keypair" ]]; then
    solana-keygen new --outfile "$buffer_keypair" --no-bip39-passphrase --silent
fi
buffer=$(solana-keygen pubkey "$buffer_keypair")
printf 'Mainnet buffer: %s\nUpgrade authority: %s\nArtifact hash: %s\n' "$buffer" "$upgrade_authority" "$local_hash"

uploaded=false
for attempt in 1 2 3 4 5; do
    echo "Writing buffer (attempt $attempt/5)..."
    if solana program write-buffer "$program_so" --url "$rpc_url" \
        --buffer "$buffer_keypair"; then
        uploaded=true
        break
    fi
    sleep 2
done
if [[ "$uploaded" != true ]]; then
    echo "error: buffer upload incomplete; resume using $buffer_keypair" >&2
    exit 1
fi

buffer_hash=$(solana-verify get-buffer-hash "$buffer" --url "$rpc_url")
if [[ "$local_hash" != "$buffer_hash" ]]; then
    echo "error: buffer hash $buffer_hash differs from artifact $local_hash" >&2
    exit 1
fi
solana program set-buffer-authority "$buffer" --url "$rpc_url" \
    --new-buffer-authority "$upgrade_authority"
solana program show "$buffer" --url "$rpc_url" --output json
