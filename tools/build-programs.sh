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
    -- --locked --features bpf-entrypoint
cargo build-sbf --tools-version "$sbf_tools_version" \
    --sbf-out-dir target/deploy \
    --manifest-path programs/shielded-pool/Cargo.toml \
    -- --locked --features bpf-entrypoint
cargo build-sbf --tools-version "$sbf_tools_version" \
    --sbf-out-dir target/deploy \
    --manifest-path program-tests/ring-test-program/Cargo.toml \
    -- --locked
cargo build-sbf --tools-version "$sbf_tools_version" \
    --sbf-out-dir target/deploy \
    --manifest-path sdk-tests/zk-program-swap/program/Cargo.toml \
    -- --locked --features bpf-entrypoint
cargo build-sbf --tools-version "$sbf_tools_version" \
    --sbf-out-dir target/deploy \
    --manifest-path sdk-tests/timelock-escrow/program/Cargo.toml \
    -- --locked --features bpf-entrypoint
cargo build-sbf --tools-version "$sbf_tools_version" \
    --sbf-out-dir target/deploy \
    --manifest-path sdk-tests/dynamic-swap/program/Cargo.toml \
    -- --locked --features bpf-entrypoint
cargo build-sbf --tools-version "$sbf_tools_version" \
    --sbf-out-dir target/deploy \
    --manifest-path sdk-tests/compression/program/Cargo.toml \
    -- --locked --features bpf-entrypoint
cargo build-sbf --tools-version "$sbf_tools_version" \
    --sbf-out-dir target/deploy \
    --manifest-path custom-rings/program/Cargo.toml \
    -- --locked --features bpf-entrypoint

# The policy build is a second artifact, both share one crate name so they
# cannot land in one directory.
cargo build-sbf --tools-version "$sbf_tools_version" \
    --sbf-out-dir target/deploy-policy \
    --manifest-path custom-rings/program/Cargo.toml \
    -- --locked --features bpf-entrypoint,allowlist,blocklist,freeze
mv target/deploy-policy/custom_ring_program.so \
    target/deploy/custom_ring_program_policy.so
rm -rf target/deploy-policy
