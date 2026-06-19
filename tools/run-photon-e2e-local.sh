#!/usr/bin/env bash
# Local photon e2e runner that launches the validator and a locally-built Photon
# (zolana-only-indexer, no `--mode` flag) separately, bypassing the cli's
# `--with-photon` launcher. Pass the test name as $1 (default: localnet_photon_e2e).
set -euo pipefail

cd "$(dirname "$0")/.."

TEST="${1:-localnet_photon_e2e}"
PHOTON_BIN="${ZOLANA_PHOTON_BIN:-photon}"
RPC_PORT=8899
PHOTON_PORT=8784

eval "$(cargo run -q -p xtask -- program-ids)"

cleanup() {
  lsof -ti tcp:${RPC_PORT} 2>/dev/null | xargs kill -9 2>/dev/null || true
  lsof -ti tcp:${PHOTON_PORT} 2>/dev/null | xargs kill -9 2>/dev/null || true
  pkill -f solana-test-validator 2>/dev/null || true
  [[ -n "${PHOTON_PID:-}" ]] && kill -9 "${PHOTON_PID}" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
sleep 1

echo ">>> starting validator"
cargo run -p zolana-cli -- test-validator --skip-prover --no-use-surfpool \
  --rpc-port ${RPC_PORT} \
  --sbf-program "$SHIELDED_POOL_PROGRAM_ID" target/deploy/shielded_pool_program.so \
  --sbf-program "$ZONE_TEST_PROGRAM_ID" target/deploy/zone_test_program.so

echo ">>> starting photon: ${PHOTON_BIN}"
"${PHOTON_BIN}" --rpc-url "http://127.0.0.1:${RPC_PORT}" --port ${PHOTON_PORT} --start-slot latest \
  > test-ledger/photon-local.log 2>&1 &
PHOTON_PID=$!

echo ">>> waiting for photon on ${PHOTON_PORT}"
for _ in $(seq 1 60); do
  if lsof -ti tcp:${PHOTON_PORT} >/dev/null 2>&1; then break; fi
  if ! kill -0 "${PHOTON_PID}" 2>/dev/null; then
    echo "photon exited early; log:"; tail -20 test-ledger/photon-local.log; exit 1
  fi
  sleep 1
done

FILTER="${2:-}"
echo ">>> running test ${TEST} ${FILTER}"
env ZOLANA_LOCALNET_URL="http://127.0.0.1:${RPC_PORT}" \
    ZOLANA_INDEXER_URL="http://127.0.0.1:${PHOTON_PORT}" \
    cargo test -p shielded-pool-tests --features localnet --test "${TEST}" "${FILTER}" -- --nocapture
