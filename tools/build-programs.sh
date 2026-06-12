#!/usr/bin/env bash
# Build local SBF programs into target/deploy.

set -euo pipefail

root=$(git rev-parse --show-toplevel)
sbf_tools_version="${SBF_TOOLS_VERSION:-v1.54}"

cd "$root"
cargo build-sbf --tools-version "$sbf_tools_version" \
    --manifest-path programs/user-registry/Cargo.toml
cargo build-sbf --tools-version "$sbf_tools_version" \
    --manifest-path programs/shielded-pool/Cargo.toml \
    -- --features bpf-entrypoint
cargo build-sbf --tools-version "$sbf_tools_version" \
    --manifest-path programs/registry/Cargo.toml
