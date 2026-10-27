#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
xark_revision=b443d83ea8ec7f2253610887e9690623ad048aef
xark_checkout=${1:-${XARK_SOURCE:-"$repo_root/.tools/xark"}}

if [[ ! -e "$xark_checkout/.git" ]]; then
    mkdir -p "$(dirname "$xark_checkout")"
    git clone --no-checkout https://github.com/blueshift-gg/xark.git "$xark_checkout"
    git -C "$xark_checkout" checkout --detach "$xark_revision"
fi

if [[ $# -eq 0 && -z ${XARK_SOURCE:-} && $(git -C "$xark_checkout" rev-parse HEAD) != "$xark_revision" ]]; then
    echo "Xark checkout must be at $xark_revision: $xark_checkout" >&2
    exit 1
fi

for patch_file in "$repo_root/tools/xark/input-region-indices.patch" "$repo_root/tools/xark/proof-randomness.patch"; do
    if ! git -C "$xark_checkout" apply --reverse --check "$patch_file" 2>/dev/null; then
        git -C "$xark_checkout" apply --check "$patch_file"
        git -C "$xark_checkout" apply "$patch_file"
    fi
done

cargo build --release --manifest-path "$xark_checkout/Cargo.toml" -p xark-cli
"$xark_checkout/target/release/xark" --version
echo "Xark source: $xark_checkout (set XARK_SOURCE to select this checkout for zk compile)"
