#!/usr/bin/env bash
# Build local SBF programs into target/deploy.

set -euo pipefail

root=$(git rev-parse --show-toplevel)
sbf_tools_version="${SBF_TOOLS_VERSION:-v1.54}"

cd "$root"
mkdir -p target/deploy

log=$(mktemp)
trap 'rm -f "$log"' EXIT

# tee the build output so a frame overflow can be gated below, PIPESTATUS keeps
# a real cargo failure fatal under `set -e`.
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

# The SBF backend prints an over-frame function as a non-fatal Error and exits 0.
# A frame over 4096 bytes is undefined behaviour on a gap-enabled runtime, fail.
if grep -q "overflows the maximum allowed frame space" "$log"; then
    echo "error: SBF stack frame overflow" >&2
    grep "overflows the maximum allowed frame space" "$log" >&2
    exit 1
fi
