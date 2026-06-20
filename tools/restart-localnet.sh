#!/usr/bin/env bash
# Restart a fresh local validator + Photon Zolana indexer for one e2e test.
# Each localnet photon test calls this so it runs against clean chain state (the
# protocol config is a global singleton, so tests cannot share a validator).
# Photon is launched directly (the zolana-only-indexer binary has no `--mode`),
# so this bypasses the cli's `--with-photon` launcher.
#
# Reads from the environment (exported by the `test-localnet-e2e-photon` recipe):
#   SHIELDED_POOL_PROGRAM_ID   base58 program id (required)
#   ZOLANA_PHOTON_BIN          photon binary (default: photon on PATH)
#   ZOLANA_LOCALNET_RPC_PORT   default 8899
#   ZOLANA_LOCALNET_PHOTON_PORT default 8784
set -euo pipefail
cd "$(dirname "$0")/.."

rpc_port="${ZOLANA_LOCALNET_RPC_PORT:-8899}"
photon_port="${ZOLANA_LOCALNET_PHOTON_PORT:-8784}"
photon_bin="${ZOLANA_PHOTON_BIN:-photon}"
program_id="${SHIELDED_POOL_PROGRAM_ID:?SHIELDED_POOL_PROGRAM_ID must be set}"
so="target/deploy/shielded_pool_program.so"
ledger="${ZOLANA_TEST_LEDGER:-/tmp/zolana-photon-test-ledger}"

# Stop the validator + photon only, by their ports. The prover server (port 3001)
# is deliberately never touched here: it is started once and must persist across
# all serial tests so its proving keys stay loaded.
stop() {
  lsof -ti "tcp:${rpc_port}" 2>/dev/null | xargs kill -9 2>/dev/null || true
  lsof -ti "tcp:${photon_port}" 2>/dev/null | xargs kill -9 2>/dev/null || true
  pkill -f solana-test-validator 2>/dev/null || true
}

stop
# Wait for the validator to actually die so the fresh one binds a free port.
for _ in $(seq 1 30); do
  lsof -ti "tcp:${rpc_port}" >/dev/null 2>&1 || break
  sleep 1
done
rm -rf "$ledger"

solana-test-validator --reset --quiet --rpc-port "$rpc_port" --bind-address 127.0.0.1 \
  --bpf-program "$program_id" "$so" --ledger "$ledger" >/dev/null 2>&1 &

ready=false
for _ in $(seq 1 90); do
  if curl -fs "http://127.0.0.1:${rpc_port}" -X POST -H 'content-type: application/json' \
       -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' 2>/dev/null | grep -q '"result":"ok"'; then
    ready=true
    break
  fi
  sleep 1
done
[[ "$ready" == true ]] || { echo "validator did not become ready on ${rpc_port}" >&2; exit 1; }

"$photon_bin" --rpc-url "http://127.0.0.1:${rpc_port}" --port "$photon_port" --start-slot latest \
  >/tmp/zolana-photon.log 2>&1 &

ready=false
for _ in $(seq 1 60); do
  if lsof -ti "tcp:${photon_port}" >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
[[ "$ready" == true ]] || { echo "photon did not become ready on ${photon_port}; log:" >&2; tail -20 /tmp/zolana-photon.log >&2; exit 1; }
