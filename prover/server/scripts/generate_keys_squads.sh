#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

keys_dir="${1:-./proving-keys}"
mkdir -p "$keys_dir"

go build -o light-prover .

# Squads zone circuit shapes: (1,1) withdrawal and (2,2) transfer.
# Mirrors zoneSupportedShapes in prover/common/lazy_key_manager.go.
zone_shapes=(
    "1 1"
    "2 2"
)

for shape in "${zone_shapes[@]}"; do
    read -r n_inputs n_outputs <<<"$shape"
    output="${keys_dir}/squads_zone_${n_inputs}_${n_outputs}.key"
    echo "Generating squads-zone ${n_inputs}x${n_outputs} -> ${output}"
    ./light-prover setup-zone \
        --n-inputs "$n_inputs" \
        --n-outputs "$n_outputs" \
        --output "$output"
done

# Squads key encryption recipient-count set (recovery + auditor).
# Mirrors keyEncryptionSupportedKeys in prover/common/lazy_key_manager.go.
key_encryption_keys=(1 2 3)

for num_keys in "${key_encryption_keys[@]}"; do
    output="${keys_dir}/squads_key_encryption_${num_keys}.key"
    echo "Generating squads-key-encryption num-keys=${num_keys} -> ${output}"
    ./light-prover setup-key-encryption \
        --num-keys "$num_keys" \
        --output "$output"
done

echo "Done. Squads proving keys written to ${keys_dir}"
