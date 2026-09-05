#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

keys_dir="${1:-./proving-keys}"
mkdir -p "$keys_dir"

# The prover binary must be rebuilt immediately before setup: a stale binary
# compiles a different constraint system than the running server, and the only
# symptom is gnark's "invalid witness size" at proving time.
go build -o light-prover .

# One key per supported merge input count per variant: the default merge
# (merge_transact) and the policy-ring merge (merge_ring). Merge always produces
# one output, so the shape is the input count alone. Keep in sync with
# mergeshared.SupportedInputCounts and MERGE_SUPPORTED_INPUT_COUNTS.
input_counts=(8 36)

# "<setup-merge --circuit flag> <key-file prefix>". The prefix mirrors the
# verifying-key module name.
variants=(
    "merge merge"
    "merge-ring merge_ring"
)

for entry in "${variants[@]}"; do
    read -r circuit prefix <<<"$entry"
    for n_inputs in "${input_counts[@]}"; do
        output="${keys_dir}/${prefix}_${n_inputs}_1.key"
        echo "Generating ${circuit} ${n_inputs}x1 -> ${output}"
        ./light-prover setup-merge \
            --circuit "$circuit" \
            --n-inputs "$n_inputs" \
            --output "$output"
    done
done

echo "Done. Merge proving keys written to ${keys_dir}"
