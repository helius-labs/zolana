#!/bin/sh
set -eu

export SHIELDED_POOL_PROGRAM_ID=sppU489D7A4U1exNo1oeMGZtLEofq3a6o2fR7UeoWB6
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
export E2E_BENCH_INPUTS=144 E2E_BENCH_WARM_KEYS=1 E2E_BENCH_CONCURRENCY=4
export E2E_BENCH_POLL_MS=25 PROVER_SYNC_CONCURRENCY=4 GOMAXPROCS=18
export CARGO_TARGET_DIR=/Users/tsv/Developer/zolana/zolana-pr320-bench/target

case "${1:-}" in
cache)
    cd /Users/tsv/Developer/zolana/zolana-10x-settlement
    export ZOLANA_LOCALNET_RPC_PORT=9399 ZOLANA_LOCALNET_PHOTON_PORT=9284
    export ZOLANA_LOCALNET_URL=http://127.0.0.1:9399 ZOLANA_INDEXER_URL=http://127.0.0.1:9284
    export ZOLANA_PROVER_URL=http://127.0.0.1:3301
    export ZOLANA_CLI_BIN=/Users/tsv/Developer/zolana/zolana-10x-cache/target/debug/zolana
    export ZOLANA_PHOTON_BIN=/Users/tsv/Developer/zolana/zolana-10x-cache/target/debug/photon
    export ZOLANA_PROVER_BIN=/Users/tsv/Developer/zolana/zolana-10x-cache/target/prover-server
    cargo test --offline -j2 -p spp-test-validator --test proof_cu cached_merge_spend_e2e_benchmark -- --ignored --nocapture
    ;;
direct)
    cd /Users/tsv/Developer/zolana/zolana-10x-settlement-direct
    export ZOLANA_LOCALNET_RPC_PORT=9499 ZOLANA_LOCALNET_PHOTON_PORT=9384
    export ZOLANA_LOCALNET_URL=http://127.0.0.1:9499 ZOLANA_INDEXER_URL=http://127.0.0.1:9384
    export ZOLANA_PROVER_URL=http://127.0.0.1:3302
    export ZOLANA_CLI_BIN=/Users/tsv/Developer/zolana/zolana-direct-spend/target/debug/zolana
    export ZOLANA_PHOTON_BIN=/Users/tsv/Developer/zolana/zolana-direct-spend/target/debug/photon
    export ZOLANA_PROVER_BIN=/Users/tsv/Developer/zolana/zolana-direct-spend/target/prover-server
    cargo test --offline -j2 -p shielded-pool-tests --features localnet,proofs --test direct_spend_localnet -- --ignored --nocapture
    ;;
*)
    echo "usage: $0 cache|direct" >&2
    exit 2
    ;;
esac
