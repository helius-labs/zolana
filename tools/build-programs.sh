#!/usr/bin/env bash
# Build local SBF programs into target/deploy.

set -euo pipefail

root=$(git rev-parse --show-toplevel)
sbf_tools_version="${SBF_TOOLS_VERSION:-v1.54}"

cd "$root"
mkdir -p target/deploy
cargo build-sbf --tools-version "$sbf_tools_version" \
    --sbf-out-dir target/deploy \
    --manifest-path programs/user-registry/Cargo.toml \
    -- --features bpf-entrypoint
cargo build-sbf --tools-version "$sbf_tools_version" \
    --sbf-out-dir target/deploy \
    --manifest-path programs/shielded-pool/Cargo.toml \
    -- --features bpf-entrypoint
cargo build-sbf --tools-version "$sbf_tools_version" \
    --sbf-out-dir target/deploy \
    --manifest-path programs/registry/Cargo.toml
