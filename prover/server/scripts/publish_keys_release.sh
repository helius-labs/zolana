#!/usr/bin/env bash
set -euo pipefail

# Publishes the transfer proving keys as assets on a GitHub release so the
# prover server can download them at startup (see common.TransferKeysBaseURL).
#
# The tag MUST match common.TransferKeysReleaseTag in
# prover/server/prover/common/key_downloader.go.

cd "$(dirname "$0")/.."

tag="${1:-transfer-keys-v1}"
keys_dir="${2:-./proving-keys}"
repo="helius-labs/zolana"

assets=(
    "${keys_dir}/transfer_2_3.key"
    "${keys_dir}/transfer-eddsa_2_3.key"
    "${keys_dir}/CHECKSUM"
)

for asset in "${assets[@]}"; do
    if [[ ! -f "$asset" ]]; then
        echo "Missing asset: $asset" >&2
        echo "Run scripts/generate_keys_transfer.sh and scripts/generate_checksums.py first." >&2
        exit 1
    fi
done

# Regenerate CHECKSUM so it matches the keys being uploaded.
python3 scripts/generate_checksums.py

if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
    echo "Release $tag exists; uploading/overwriting assets"
    gh release upload "$tag" "${assets[@]}" --repo "$repo" --clobber
else
    echo "Creating release $tag"
    gh release create "$tag" "${assets[@]}" \
        --repo "$repo" \
        --title "Transfer proving keys ($tag)" \
        --notes "Groth16 proving keys for the transfer and transfer-eddsa circuits. Downloaded by the prover server at startup."
fi

echo "Done. Assets published to https://github.com/${repo}/releases/tag/${tag}"
