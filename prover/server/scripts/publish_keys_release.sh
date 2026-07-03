#!/usr/bin/env bash
set -euo pipefail

# Publishes Zolana-specific proving keys as assets on a GitHub release so the
# prover server can download them at startup.
#
# The tag MUST match common.ProvingKeysReleaseTag in
# prover/server/prover/common/key_downloader.go.

cd "$(dirname "$0")/.."

tag="${1:-transfer-keys-v10}"
keys_dir="${2:-./proving-keys}"
repo="helius-labs/zolana"
split_threshold_bytes=$((1900 * 1024 * 1024))

# Every regenerated transfer/merge proving key (all rails and shapes) plus the
# batched-merkle nullifier-tree keys the prover fetches from this release. The
# lazy key manager downloads each on demand, so the release must carry the full
# set the supported shapes can request.
key_assets=()
while IFS= read -r asset; do
    key_assets+=("$asset")
done < <(find "$keys_dir" -maxdepth 1 -type f \
    \( -name 'transfer_*.key' -o -name 'merge_*.key' \) | sort)

# Batched-address keys are unchanged by transfer-circuit work; include whichever
# are present locally (mirrors the previous release).
for batch in batch_address-append_40_10 batch_address-append_40_250; do
    if [[ -f "${keys_dir}/${batch}.key" ]]; then
        key_assets+=("${keys_dir}/${batch}.key")
    fi
done

if [[ ${#key_assets[@]} -eq 0 ]]; then
    echo "No transfer/merge proving keys in $keys_dir" >&2
    echo "Run scripts/generate_keys_transfer.sh and generate_keys_merge.sh first." >&2
    exit 1
fi

for asset in "${key_assets[@]}"; do
    if [[ ! -f "$asset" ]]; then
        echo "Missing asset: $asset" >&2
        echo "Generate the missing proving key before publishing." >&2
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

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

assets=()
for asset in "${key_assets[@]}"; do
    size="$(/usr/bin/wc -c < "$asset" | tr -d '[:space:]')"
    if (( size > split_threshold_bytes )); then
        name="$(basename "$asset")"
        echo "Splitting large asset ${name} (${size} bytes)"
        /usr/bin/split -d -a 3 -b "$split_threshold_bytes" "$asset" "${tmp_dir}/${name}.part-"
        while IFS= read -r part; do
            assets+=("$part")
        done < <(/usr/bin/find "$tmp_dir" -type f -name "${name}.part-*" | /usr/bin/sort)
    else
        assets+=("$asset")
    fi
done
assets+=("$checksum_file")

if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
    echo "Release $tag exists; uploading/overwriting assets"
    gh release upload "$tag" "${assets[@]}" --repo "$repo" --clobber
else
    echo "Creating release $tag"
    gh release create "$tag" "${assets[@]}" \
        --repo "$repo" \
        --title "Zolana proving keys ($tag)" \
        --notes "Groth16 proving keys generated from Zolana circuits. Downloaded by the prover server at startup."
fi

echo "Done. Assets published to https://github.com/${repo}/releases/tag/${tag}"
