#!/usr/bin/env bash
set -euo pipefail

# Publishes the transfer proving keys as assets on a GitHub release so the
# prover server can download them at startup (see common.TransferKeysBaseURL).
#
# The tag MUST match common.TransferKeysReleaseTag in
# prover/server/prover/common/key_downloader.go.

cd "$(dirname "$0")/.."

tag="${1:-transfer-keys-v3}"
keys_dir="${2:-./proving-keys}"
repo="helius-labs/zolana"

key_assets=(
    "${keys_dir}/transfer_2_3.key"
    "${keys_dir}/transfer_p256_2_3.key"
    "${keys_dir}/merge_8_1.key"
)

for asset in "${key_assets[@]}"; do
    if [[ ! -f "$asset" ]]; then
        echo "Missing asset: $asset" >&2
        echo "Run scripts/generate_keys_transfer.sh and scripts/generate_keys_merge.sh first." >&2
        exit 1
    fi
done

# Regenerate CHECKSUM so it matches exactly the keys being uploaded. The shared
# generate_checksums.py hashes the whole proving-keys directory (squads keys,
# the CHECKSUM file itself); here we want a release manifest of only the keys
# served from this release.
checksum_file="${keys_dir}/CHECKSUM"
: > "$checksum_file"
for asset in "${key_assets[@]}"; do
    shasum -a 256 "$asset" | awk -v name="$(basename "$asset")" '{print $1 "  " name}' >> "$checksum_file"
done

assets=("${key_assets[@]}" "$checksum_file")

if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
    echo "Release $tag exists; uploading/overwriting assets"
    gh release upload "$tag" "${assets[@]}" --repo "$repo" --clobber
else
    echo "Creating release $tag"
    gh release create "$tag" "${assets[@]}" \
        --repo "$repo" \
        --title "Transfer proving keys ($tag)" \
        --notes "Groth16 proving keys for the transfer (eddsa) and transfer_p256 circuits. Downloaded by the prover server at startup."
fi

echo "Done. Assets published to https://github.com/${repo}/releases/tag/${tag}"
