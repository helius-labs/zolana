#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

keys_dir="${1:-./proving-keys}"
mkdir -p "$keys_dir"

go build -o light-prover .

# Set SKIP_AUTHORITY_KEYS=1 when rotating only the owner-authorized rails. This
# preserves the existing authority keys when its circuit fingerprint is unchanged.

# Keep in sync with SPP_SUPPORTED_SHAPES.
shapes=(
    "1 2"
    "1 4"
    "1 8"
    "2 2"
    "2 4"
    "1 16"
    "2 8"
    "3 2"
    "3 4"
    "2 16"
    "3 8"
    "4 2"
    "4 4"
    "4 8"
    "5 2"
    "5 4"
    "4 16"
    "5 8"
    "6 2"
    "6 4"
    "5 16"
    "6 8"
    "8 2"
    "8 4"
    "8 8"
    "8 16"
    "12 2"
    "12 4"
    "12 8"
    "16 2"
    "16 4"
    "16 8"
    "24 2"
    "24 4"
    "32 2"
    "40 2"
    "48 2"
    "51 2"
)

# "<setup-transfer --circuit flag> <key-file prefix>". The key-file prefix
# mirrors the verifying-key module name. The default rail binds every output
# owner tag; owner-signed custom-ring rails bind the confidential-marker-masked
# public owner vector.
rails=(
    "transfer-confidential transfer_confidential"
    "transfer-ring transfer_ring"
    "transfer-p256-ring transfer_p256_ring"
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

# The ring-authority rail (transfer_ring_authority) re-owns N inputs into N
# outputs (freeze / thaw / permanent-delegate), so only the square shapes the
# on-chain verifier supports are generated.
if [[ "${SKIP_AUTHORITY_KEYS:-0}" != "1" ]]; then
    authority_shapes=(
        "2 2"
        "4 4"
    )
    for shape in "${authority_shapes[@]}"; do
        read -r n_inputs n_outputs <<<"$shape"
        output="${keys_dir}/transfer_ring_authority_${n_inputs}_${n_outputs}.key"
        echo "Generating transfer-ring-authority ${n_inputs}x${n_outputs} -> ${output}"
        ./light-prover setup-transfer \
            --circuit "transfer-ring-authority" \
            --n-inputs "$n_inputs" \
            --n-outputs "$n_outputs" \
            --output "$output"
    done
fi

echo "Done. Transfer proving keys written to ${keys_dir}"
