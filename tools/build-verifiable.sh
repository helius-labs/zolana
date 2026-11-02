#!/usr/bin/env bash
# Adapted from light-protocol/scripts/deploy/build-verifiable.sh.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
mkdir -p target/deploy

# Pin the image selected by solana-verify 0.5.2 for this Cargo.lock.
image=solanafoundation/solana-verifiable-build@sha256:b970a392e4ad5170680f7d1b37b1f25c75675f095e8309b5cb0a7d18bc314eec
log=target/verifiable-build.log
solana-verify build --library-name shielded_pool_program \
    --base-image "$image" \
    --cargo-build-sbf-args='--tools-version v1.54' \
    -- --features bpf-entrypoint 2>&1 | tee "$log"

# cargo build-sbf can exit successfully after reporting a frame overflow.
if grep -Eq 'overflows the maximum allowed frame space|overwrites values in the frame' "$log"; then
    echo 'error: SBF stack frame overflow' >&2
    exit 1
fi
solana-verify get-executable-hash target/deploy/shielded_pool_program.so
