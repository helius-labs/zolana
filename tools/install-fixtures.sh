#!/usr/bin/env bash
# Install a verified local fixture directory into the zolana cache.

set -euo pipefail

root=$(git rev-parse --show-toplevel)
source_dir="${1:-$root/target/fixtures/staging}"
tag=$(tr -d '[:space:]' < "$root/.fixtures-version")
cache_root="${ZOLANA_CACHE_DIR:-$HOME/.cache/zolana}"
dest="$cache_root/fixtures/$tag"

"$root/tools/verify-fixtures.sh" "$source_dir" >/dev/null

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/fixtures"
cp -R "$source_dir/." "$tmp/fixtures/"

rm -rf "$dest"
mkdir -p "$(dirname "$dest")"
mv "$tmp/fixtures" "$dest"

"$root/tools/verify-fixtures.sh" "$dest" >/dev/null
echo "fixtures ${tag} installed at ${dest}"
