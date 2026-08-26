#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

keys_dir="${1:-./proving-keys}"
mkdir -p "$keys_dir"

go build -o light-prover .

output="${keys_dir}/custom_ring.key"
echo "Generating custom-ring -> ${output}"
./light-prover setup-custom-ring --output "$output" \
    --pk-out "${keys_dir}/auditor_key_encryption_pk.bin" \
    --vk-out "${keys_dir}/auditor_key_encryption_vk.bin"

echo "Done. Custom ring proving key and its release assets written to ${keys_dir}"
