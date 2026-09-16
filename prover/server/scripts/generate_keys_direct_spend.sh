#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

keys_dir="${1:-./proving-keys}"
mkdir -p "$keys_dir"

go build -o light-prover .

shapes=(
    "input-certificate 36 0"
    "nullifier-freshness 36 0"
    "spend-balance 16 2"
    "direct-payment 512 2"
)

for shape in "${shapes[@]}"; do
    read -r circuit n_inputs n_outputs <<<"$shape"
    output="${keys_dir}/${circuit}_${n_inputs}_${n_outputs}.key"
    echo "Generating ${circuit} ${n_inputs}x${n_outputs} -> ${output}"
    ./light-prover setup-direct-spend \
        --circuit "$circuit" \
        --n-inputs "$n_inputs" \
        --n-outputs "$n_outputs" \
        --output "$output"
done

echo "Done. Direct-spend proving keys written to ${keys_dir}"
