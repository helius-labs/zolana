#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

keys_dir="${1:-./proving-keys}"
mkdir -p "$keys_dir"

go build -o light-prover .

# The merge circuit has a single fixed 8-in/1-out shape. The key-file name
# mirrors the verifying-key module name: merge_8_1.
output="${keys_dir}/merge_8_1.key"
echo "Generating merge 8x1 -> ${output}"
./light-prover setup-merge --output "$output"

echo "Done. Merge proving key written to ${keys_dir}"
