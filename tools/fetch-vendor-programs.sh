#!/usr/bin/env bash
# Fetch and verify vendored third-party SBF programs.

set -euo pipefail

root=$(git rev-parse --show-toplevel)
lock="$root/fixtures/vendor/spl-noop.lock"
dest_dir="$root/target/fixtures/vendor/bin"
dest="$dest_dir/spl_noop.so"

lock_value() {
    awk -F= -v key="$1" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$lock"
}

if [[ ! -f "$lock" ]]; then
    echo "error: missing vendor lock: $lock" >&2
    exit 1
fi

url="${SPL_NOOP_URL:-$(lock_value url)}"
expected_sha=$(lock_value sha256)
repo=$(lock_value repo)
tag=$(lock_value tag)
asset=$(lock_value file)

if [[ -z "$url" || -z "$expected_sha" || -z "$repo" || -z "$tag" || -z "$asset" ]]; then
    echo "error: incomplete vendor lock: $lock" >&2
    exit 1
fi

mkdir -p "$dest_dir"

if [[ -f "$dest" ]]; then
    actual_sha=$(shasum -a 256 "$dest" | awk '{print $1}')
    if [[ "$actual_sha" == "$expected_sha" ]]; then
        echo "vendor spl_noop.so already verified at $dest"
        exit 0
    fi
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "fetching vendored spl_noop.so from $url"
if ! curl -sSfL "$url" -o "$tmp/spl_noop.so"; then
    if ! command -v gh >/dev/null 2>&1; then
        echo "error: curl failed and gh is not available for authenticated release download" >&2
        exit 1
    fi
    echo "curl download failed; trying gh release download"
    gh release download "$tag" \
        --repo "$repo" \
        --pattern "$asset" \
        --dir "$tmp" \
        --clobber
fi

if [[ ! -f "$tmp/spl_noop.so" ]]; then
    echo "error: release download did not produce spl_noop.so" >&2
    exit 1
fi

actual_sha=$(shasum -a 256 "$tmp/spl_noop.so" | awk '{print $1}')
if [[ "$actual_sha" != "$expected_sha" ]]; then
    echo "error: spl_noop.so sha256 mismatch" >&2
    echo "expected: $expected_sha" >&2
    echo "actual  : $actual_sha" >&2
    exit 1
fi

cp "$tmp/spl_noop.so" "$dest"
chmod 0644 "$dest"
printf '%s  bin/spl_noop.so\n' "$expected_sha" > "$root/target/fixtures/vendor/SHA256SUMS"

echo "vendor spl_noop.so verified at $dest"
