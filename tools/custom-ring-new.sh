#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage custom-ring-new NAME DESTINATION" >&2
    exit 2
fi

name="$1"
destination_input="$2"
if [[ "$name" == */* ]]; then
    echo "name must not contain a path separator" >&2
    exit 2
fi
if [[ -e "$destination_input" ]]; then
    echo "destination already exists" >&2
    exit 2
fi

root="$(git rev-parse --show-toplevel)"
revision="$(git -C "$root" rev-parse HEAD)"
authority="${CUSTOM_RING_AUTHORITY_KEYPAIR:-~/.config/solana/id.json}"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
solana-keygen new --no-bip39-passphrase --silent --outfile "$temporary/program-keypair.json"
program_id="$(solana-keygen pubkey "$temporary/program-keypair.json")"
parent_input="$(dirname "$destination_input")"
mkdir -p "$parent_input"
parent="$(cd "$parent_input" && pwd -P)"
destination="$parent/$(basename "$destination_input")"
generated="$parent/$name"
if [[ -e "$generated" && "$generated" != "$destination" ]]; then
    echo "generated project path already exists" >&2
    exit 2
fi
cargo generate \
    --path "$root/templates/custom-ring" \
    --name "$name" \
    --destination "$parent" \
    --define "program_id=$program_id" \
    --define "authority_keypair=$authority" \
    --define "zolana_path=.zolana" \
    --define "zolana_repository=https://github.com/helius-labs/zolana.git" \
    --define "zolana_revision=$revision"
if [[ "$generated" != "$destination" ]]; then
    mv "$generated" "$destination"
fi
mkdir -p "$destination/keys"
mv "$temporary/program-keypair.json" "$destination/keys/program-keypair.json"
