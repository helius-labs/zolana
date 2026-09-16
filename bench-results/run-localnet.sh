#!/bin/sh
set -eu
cd /Users/tsv/Developer/zolana/zolana-10x-direct
export SHIELDED_POOL_PROGRAM_ID=sppU489D7A4U1exNo1oeMGZtLEofq3a6o2fR7UeoWB6
export ZOLANA_LOCALNET_RPC_PORT=8999 ZOLANA_LOCALNET_PHOTON_PORT=8884
export ZOLANA_LOCALNET_URL=http://127.0.0.1:8999 ZOLANA_INDEXER_URL=http://127.0.0.1:8884
export ZOLANA_PROVER_URL="${ZOLANA_PROVER_URL:-http://127.0.0.1:3101}"
export ZOLANA_CLI_BIN=/Users/tsv/Developer/zolana/zolana-direct-spend/target/debug/zolana
export ZOLANA_PHOTON_BIN=/Users/tsv/Developer/zolana/zolana-direct-spend/target/debug/photon
export ZOLANA_PROVER_BIN=/Users/tsv/Developer/zolana/zolana-direct-spend/target/prover-server
export ZOLANA_PROVER_KEYS_DIR=/Users/tsv/Developer/zolana/zolana-direct-spend/prover/server/proving-keys
export DEVELOPER_DIR=/Library/Developer/CommandLineTools
export CARGO_TARGET_DIR=/Users/tsv/Developer/zolana/zolana-direct-spend/target
cargo test -p shielded-pool-tests --features localnet,proofs --test direct_spend_localnet -- --ignored --nocapture
