#!/usr/bin/env bash
# Split-spend experiment: the public half (nullifier-freshness-gkr) alone, then
# both halves of one 512-input spend proven sequentially and concurrently with
# resident keys. Run from prover/server on the benchmark machine.
#
#   scripts/split_nip_bench.sh [inputs=512] [samples=3]
#
# Expects proving-keys/direct-payment-admitted_<inputs>_2.key. Generates
# proving-keys/nullifier-freshness-gkr_<inputs>_0.key when missing.
set -euo pipefail

cd "$(dirname "$0")/.."

inputs="${1:-512}"
samples="${2:-3}"
keys="$PWD/proving-keys"
logs="benchmarks"
mkdir -p "$logs"

export GOMAXPROCS="${GOMAXPROCS:-18}" GOMEMLIMIT="${GOMEMLIMIT:-32GiB}"

if [ ! -f "$keys/nullifier-freshness-gkr_${inputs}_0.key" ]; then
    go build -o light-prover .
    /usr/bin/time ./light-prover setup-direct-spend --circuit nullifier-freshness-gkr \
        --n-inputs "$inputs" --n-outputs 0 \
        --output "$keys/nullifier-freshness-gkr_${inputs}_0.key" \
        --output-vkey "$keys/nullifier-freshness-gkr_${inputs}_0.vk.bin" \
        2>&1 | tee "$logs/split-nip-setup-${inputs}.log"
fi

SPLIT_NIP_KEYS="$keys" SPLIT_NIP_INPUTS="$inputs" \
    go test ./circuits/direct_spend -run '^TestSplitNipProving$' -count=1 -timeout 30m -v \
    2>&1 | tee "$logs/split-nip-proving-${inputs}.log"

SPLIT_NIP_KEYS="$keys" SPLIT_NIP_INPUTS="$inputs" SPLIT_NIP_SAMPLES="$samples" \
    go test ./circuits/direct_spend -run '^TestSplitNipConcurrentProving$' -count=1 -timeout 60m -v \
    2>&1 | tee "$logs/split-nip-concurrent-${inputs}.log"
