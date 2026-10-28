#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
xark_revision=7207a227738abbf4d0dd776ae4e7efe31312dec6
xark_repository=https://github.com/ananas-block/xark.git
xark_checkout=${1:-${XARK_SOURCE:-"$repo_root/.tools/xark"}}
owned=false

# Only a fresh default checkout belongs to this bootstrap. Explicit sources and
# symlinks are read-only, including the developer's separate Xark worktree.
if [[ $# -eq 0 && -z ${XARK_SOURCE:-} && ! -L "$repo_root/.tools" && ! -L "$xark_checkout" ]]; then
    if [[ ! -e "$xark_checkout" ]]; then
        mkdir -p "$repo_root/.tools"
        git clone --no-checkout --single-branch --branch feat/client-wasm "$xark_repository" "$xark_checkout"
        git -C "$xark_checkout" checkout --detach "$xark_revision"
        touch "$xark_checkout/.git/zolana-bootstrap"
        owned=true
    elif [[ -f "$xark_checkout/.git/zolana-bootstrap" ]]; then
        owned=true
    fi
fi

if [[ ! -e "$xark_checkout/.git" ]]; then
    echo "Xark source is missing at $xark_checkout; run tools/xark/build.sh without an external source to create it" >&2
    exit 1
fi
if ! git -C "$xark_checkout" merge-base --is-ancestor "$xark_revision" HEAD; then
    echo "Xark source must descend from $xark_revision: $xark_checkout" >&2
    exit 1
fi
if [[ $owned == true && $(git -C "$xark_checkout" rev-parse HEAD) != "$xark_revision" ]]; then
    echo "Bootstrapped Xark source moved from $xark_revision; refusing to reset it: $xark_checkout" >&2
    exit 1
fi

for patch_file in "$repo_root/tools/xark/input-region-indices.patch" "$repo_root/tools/xark/proof-randomness.patch" "$repo_root/tools/xark/native-integers.patch" "$repo_root/tools/xark/typed-wasm.patch"; do
    if git -C "$xark_checkout" apply --unidiff-zero --reverse --check "$patch_file" 2>/dev/null; then
        continue
    fi
    if [[ $owned != true ]]; then
        echo "External Xark source is missing $(basename "$patch_file"); refusing to modify it: $xark_checkout" >&2
        exit 1
    fi
    git -C "$xark_checkout" apply --unidiff-zero --check "$patch_file"
    git -C "$xark_checkout" apply --unidiff-zero "$patch_file"
done

if [[ $owned == true ]]; then
    cargo build --release --manifest-path "$xark_checkout/Cargo.toml" -p xark-cli
elif [[ ! -x "$xark_checkout/target/release/xark" ]]; then
    echo "Build the compiler in the external Xark source before using it: $xark_checkout" >&2
    exit 1
fi
version=$("$xark_checkout/target/release/xark" --version)
source_revision=$(git -C "$xark_checkout" rev-parse --short=12 HEAD)
if [[ "$version" != *"0.3.0"* || "$version" != *"$source_revision"* ]]; then
    echo "Xark compiler does not match source $source_revision: $version" >&2
    exit 1
fi
echo "$version"
echo "Xark source: $xark_checkout"
