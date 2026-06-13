#!/usr/bin/env bash
# Build local SBF programs and copy verified fixture programs into target/deploy.

set -euo pipefail

root=$(git rev-parse --show-toplevel)
sbf_tools_version="${SBF_TOOLS_VERSION:-v1.54}"

cd "$root"
cargo build-sbf --tools-version "$sbf_tools_version" \
    --manifest-path programs/shielded-pool/Cargo.toml \
    -- --features bpf-entrypoint
cargo build-sbf --tools-version "$sbf_tools_version" \
    --manifest-path program-tests/zone-test-program/Cargo.toml

fixtures="${ZOLANA_FIXTURES_DIR:-}"
if [[ -z "$fixtures" && -d "$root/target/fixtures/staging" ]]; then
    fixtures="$root/target/fixtures/staging"
fi
if [[ -z "$fixtures" ]]; then
    tag=$(tr -d '[:space:]' < "$root/.fixtures-version")
    fixtures="${ZOLANA_CACHE_DIR:-$HOME/.cache/zolana}/fixtures/${tag}"
fi

"$root/tools/verify-fixtures.sh" "$fixtures" >/dev/null

mkdir -p "$root/target/deploy"
cp "$fixtures/bin/spl_noop.so" "$root/target/deploy/spl_noop.so"
