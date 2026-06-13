#!/usr/bin/env bash
# Verify a fixture directory produced by tools/build-fixtures.sh.

set -euo pipefail

root=$(git rev-parse --show-toplevel)
dir="${1:-$root/target/fixtures/staging}"
expected_tag="${FIXTURES_VERSION:-}"
if [[ -z "$expected_tag" && -f "$root/.fixtures-version" ]]; then
    expected_tag=$(tr -d '[:space:]' < "$root/.fixtures-version")
fi

if [[ ! -d "$dir" ]]; then
    echo "error: fixture directory does not exist: $dir" >&2
    exit 1
fi

for path in MANIFEST.json SHA256SUMS accounts; do
    if [[ ! -e "$dir/$path" ]]; then
        echo "error: fixture directory missing $path: $dir" >&2
        exit 1
    fi
done

if [[ -n "$expected_tag" ]]; then
    actual_tag=$(awk -F'"' '/"version"[[:space:]]*:/ { print $4; exit }' "$dir/MANIFEST.json")
    if [[ "$actual_tag" != "$expected_tag" ]]; then
        echo "error: fixture manifest version ${actual_tag:-<missing>} does not match ${expected_tag}: $dir/MANIFEST.json" >&2
        exit 1
    fi
fi

(
    cd "$dir"
    shasum -a 256 -c SHA256SUMS >/dev/null
)

echo "fixtures verified: $dir"
