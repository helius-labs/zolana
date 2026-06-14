#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

keys_dir="${1:-./proving-keys}"
mkdir -p "$keys_dir"

go build -o light-prover .

shapes=(
    "2 3"
)

for rail in transfer transfer-eddsa; do
    for shape in "${shapes[@]}"; do
        read -r n_inputs n_outputs <<<"$shape"
        output="${keys_dir}/${rail}_${n_inputs}_${n_outputs}.key"
        echo "Generating ${rail} ${n_inputs}x${n_outputs} -> ${output}"
        ./light-prover setup-transfer \
            --circuit "$rail" \
            --n-inputs "$n_inputs" \
            --n-outputs "$n_outputs" \
            --output "$output"
    done
done

echo "Done. Transfer proving keys written to ${keys_dir}"
