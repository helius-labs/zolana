#!/usr/bin/env bash
# Build local SBF programs into target/deploy.

set -euo pipefail

root=$(git rev-parse --show-toplevel)
sbf_tools_version="${SBF_TOOLS_VERSION:-v1.54}"

cd "$root"
mkdir -p target/deploy

log=$(mktemp)
trap 'rm -f "$log"' EXIT

# 1. Preserve compiler diagnostics and the build exit status.
build() {
    cargo build-sbf --tools-version "$sbf_tools_version" --sbf-out-dir target/deploy "$@" 2>&1 | tee -a "$log"
    return "${PIPESTATUS[0]}"
}

build --manifest-path programs/user-registry/Cargo.toml -- --locked --features bpf-entrypoint
build --manifest-path programs/shielded-pool/Cargo.toml -- --locked --features bpf-entrypoint
build --manifest-path program-tests/ring-test-program/Cargo.toml -- --locked
build --manifest-path program-tests/spp-recorder-program/Cargo.toml -- --locked
build --manifest-path sdk-tests/zk-program-swap/program/Cargo.toml -- --locked --features bpf-entrypoint
build --manifest-path sdk-tests/timelock-escrow/program/Cargo.toml -- --locked --features bpf-entrypoint
build --manifest-path sdk-tests/dynamic-swap/program/Cargo.toml -- --locked --features bpf-entrypoint
build --manifest-path sdk-tests/compression/program/Cargo.toml -- --locked --features bpf-entrypoint
build --manifest-path custom-rings/program/Cargo.toml -- --locked --features bpf-entrypoint

# 2. Reject stack diagnostics even when the compiler reports success.
frame_error='overflows the maximum allowed frame space|overwrites values in the frame'
if grep -Eq "$frame_error" "$log"; then
    echo "error: SBF stack frame overflow" >&2
    grep -E "$frame_error" "$log" >&2
    exit 1
fi
