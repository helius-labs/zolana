#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

keys_dir="${1:-./proving-keys}"
mkdir -p "$keys_dir"

go build -o light-prover .

# The merge circuit has a single fixed 8-in/1-out shape, in two variants: the
# default merge (merge_transact) and the policy-ring merge (merge_ring). The
# key-file names mirror the verifying-key module names: merge_8_1 / merge_ring_8_1.
output="${keys_dir}/merge_8_1.key"
echo "Generating merge 8x1 -> ${output}"
./light-prover setup-merge --circuit merge --output "$output"

ring_output="${keys_dir}/merge_ring_8_1.key"
echo "Generating merge-ring 8x1 -> ${ring_output}"
./light-prover setup-merge --circuit merge-ring --output "$ring_output"

echo "Done. Merge proving keys written to ${keys_dir}"
