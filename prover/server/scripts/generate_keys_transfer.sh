#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

keys_dir="${1:-./proving-keys}"
mkdir -p "$keys_dir"

go build -o light-prover .

# P256 ownership circuits were removed. Drop their generated artifacts before
# rebuilding so vkey generation and the proving-key lockfile cannot retain the
# retired rails.
find "$keys_dir" -maxdepth 1 -type f -name 'transfer_p256_*.key' -delete

shapes=(
    "1 1"
    "1 2"
    "2 2"
    "2 3"
    "3 3"
    "4 3"
    "4 4"
    "5 3"
    "5 4"
    "1 8"
)

# "<setup-transfer --circuit flag> <key-file prefix>". The key-file prefix
# mirrors the verifying-key module name. Both the default and custom-zone forms
# are confidential and bind public output owner tags.
rails=(
    "transfer-confidential transfer_confidential"
    "transfer-zone transfer_zone"
)

for entry in "${rails[@]}"; do
    read -r circuit prefix <<<"$entry"
    for shape in "${shapes[@]}"; do
        read -r n_inputs n_outputs <<<"$shape"
        output="${keys_dir}/${prefix}_${n_inputs}_${n_outputs}.key"
        echo "Generating ${circuit} ${n_inputs}x${n_outputs} -> ${output}"
        ./light-prover setup-transfer \
            --circuit "$circuit" \
            --n-inputs "$n_inputs" \
            --n-outputs "$n_outputs" \
            --output "$output"
    done
done

# The zone-authority rail (transfer_zone_authority) re-owns N inputs into N
# outputs (freeze / thaw / permanent-delegate), so only the square shapes the
# on-chain verifier supports are generated.
authority_shapes=(
    "1 1"
    "2 2"
    "3 3"
    "4 4"
)
for shape in "${authority_shapes[@]}"; do
    read -r n_inputs n_outputs <<<"$shape"
    output="${keys_dir}/transfer_zone_authority_${n_inputs}_${n_outputs}.key"
    echo "Generating transfer-zone-authority ${n_inputs}x${n_outputs} -> ${output}"
    ./light-prover setup-transfer \
        --circuit "transfer-zone-authority" \
        --n-inputs "$n_inputs" \
        --n-outputs "$n_outputs" \
        --output "$output"
done

echo "Done. Transfer proving keys written to ${keys_dir}"
