#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

keys_dir="${1:-./proving-keys}"
vkey_dir="../../program-libs/interface/src/verifying_keys"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

go build -o light-prover .

keys="$(find "$keys_dir" -maxdepth 1 -type f \( -name 'transfer_*.key' -o -name 'merge_*.key' \) | sort)"
if [ -z "$keys" ]; then
    echo "no transfer or merge proving keys in $keys_dir"
    exit 1
fi

modules=""
for key in $keys; do
    stem="$(basename "$key" .key)"
    module="${stem//-/_}"
    vk_bin="$tmp_dir/${stem}.vkbin"

    echo "exporting raw vk: $stem"
    if ! ./light-prover export-vk --keys-file "$key" --output "$vk_bin" >/dev/null; then
        echo "WARN: export-vk failed, skipping $stem"
        continue
    fi

    if (cd ../.. && cargo run -q -p xtask -- bsb22-vk \
        "$vk_bin" "program-libs/interface/src/verifying_keys" "${module}.rs"); then
        modules="${modules}${module}"$'\n'
    else
        echo "WARN: vk codegen failed, skipping $stem"
    fi
done

{
    echo "$modules" | sort -u | while read -r module; do
        [ -n "$module" ] && echo "pub mod $module;"
    done
} >"$vkey_dir/mod.rs"

echo "Regenerated verifying keys into $vkey_dir"
