#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

keys_dir="${1:-./proving-keys}"
mkdir -p "$keys_dir"

go build -o light-prover .

output="${keys_dir}/custom_ring_audit_transfer.key"
echo "Generating auditor-key-encryption -> ${output}"
./light-prover setup-auditor-key-encryption --output "$output"

echo "Done. Custom ring proving key written to ${keys_dir}"
