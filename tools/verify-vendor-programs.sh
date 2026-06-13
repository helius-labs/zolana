#!/usr/bin/env bash
# Verify vendored third-party SBF programs against their lock files.

set -euo pipefail

root=$(git rev-parse --show-toplevel)
lock="$root/fixtures/vendor/spl-noop.lock"
artifact="${SPL_NOOP_SO:-$root/target/fixtures/vendor/bin/spl_noop.so}"

lock_value() {
    awk -F= -v key="$1" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$lock"
}

expected_sha=$(lock_value sha256)
if [[ -z "$expected_sha" ]]; then
    echo "error: missing sha256 in $lock" >&2
    exit 1
fi
if [[ ! -f "$artifact" ]]; then
    echo "error: missing vendored spl_noop.so: $artifact" >&2
    echo "run: just fetch-vendor-programs" >&2
    exit 1
fi

actual_sha=$(shasum -a 256 "$artifact" | awk '{print $1}')
if [[ "$actual_sha" != "$expected_sha" ]]; then
    echo "error: spl_noop.so sha256 mismatch: $artifact" >&2
    echo "expected: $expected_sha" >&2
    echo "actual  : $actual_sha" >&2
    exit 1
fi

echo "vendor spl_noop.so verified: $artifact"
