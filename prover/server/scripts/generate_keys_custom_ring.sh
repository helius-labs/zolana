#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

keys_dir="${1:-./proving-keys}"
mkdir -p "$keys_dir"

go build -o light-prover .

audit_output="${keys_dir}/custom_ring_audit_transfer.key"
echo "Generating custom-ring-audit -> ${audit_output}"
./light-prover setup-custom-ring-audit --output "$audit_output"

policy_output="${keys_dir}/custom_ring_policy_transfer.key"
echo "Generating custom-ring-policy -> ${policy_output}"
./light-prover setup-custom-ring-policy --output "$policy_output"

echo "Done. Custom ring proving keys written to ${keys_dir}"
