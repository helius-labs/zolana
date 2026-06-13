#!/usr/bin/env bash
# Package a verified fixture directory for manual distribution.

set -euo pipefail

root=$(git rev-parse --show-toplevel)
fixtures="${1:-$root/target/fixtures/staging}"
out="$root/target/fixtures"
archive="zolana-fixtures.tar.gz"

"$root/tools/verify-fixtures.sh" "$fixtures" >/dev/null

mkdir -p "$out"
tar --no-xattrs -czf "$out/$archive" \
    -C "$fixtures" \
    $(cd "$fixtures" && find . -type f | sort)

shasum -a 256 "$out/$archive" |
    awk -v name="$archive" '{print $1"  "name}' \
        > "$out/$archive.sha256"

echo "Archive: $out/$archive"
echo "Sha    : $(awk '{print $1}' "$out/$archive.sha256")"
