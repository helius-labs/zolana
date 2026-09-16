#!/usr/bin/env bash
# Scratch data survives service shutdown.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"
suite="${1:-ring}"
if [[ $# -gt 0 ]]; then shift; fi
case "$suite" in
  ring|shared_sources|policy_rules|policy_repin) ;;
  *) echo "Unknown ring suite $suite" >&2; exit 2 ;;
esac
export SURFPOOL_BIN="${SURFPOOL_BIN:-$repo_root/target/tools/surfpool}"

export ZOLANA_PROCESS_SCOPE_DIR
ZOLANA_PROCESS_SCOPE_DIR="$(mktemp -d -t zolana-ring-tests.XXXXXX)"
export ZOLANA_RING_SURFPOOL_FIXTURE=1
export ZOLANA_CLI_BIN="$repo_root/target/debug/zolana"
export ZOLANA_PHOTON_BIN="$repo_root/target/debug/photon"
export PROVER_BIN="$repo_root/target/prover-server"
for binary in "$ZOLANA_CLI_BIN" "$PROVER_BIN" "$SURFPOOL_BIN"; do
  [[ -x "$binary" ]] || { echo "Missing executable $binary" >&2; exit 1; }
done
for artifact in custom_ring_program shielded_pool_program zolana_user_registry squads_smart_account_program; do
  [[ -s "target/deploy/$artifact.so" ]] || {
    echo "Build target/deploy/$artifact.so with the just localnet test recipe" >&2
    exit 1
  }
done
export ZOLANA_CONFIG_DIR="$ZOLANA_PROCESS_SCOPE_DIR/config"
port_offset="${ZOLANA_PORT_OFFSET:-0}"
export ZOLANA_LOCALNET_RPC_PORT="${RING_TEST_RPC_PORT:-$((40899 + port_offset))}"
export ZOLANA_LOCALNET_PHOTON_PORT="${RING_TEST_PHOTON_PORT:-$((40784 + port_offset))}"
prover_port="${RING_TEST_PROVER_PORT:-$((43001 + port_offset))}"
# DEFAULT_METRICS_PORT minus DEFAULT_PROVER_PORT, cli/src/config.rs.
prover_metrics_offset=6997
metrics_port=$((prover_port + prover_metrics_offset))
for port in "$ZOLANA_LOCALNET_RPC_PORT" "$ZOLANA_LOCALNET_PHOTON_PORT" "$prover_port"; do
  [[ "$port" =~ ^[1-9][0-9]{3,4}$ ]] && ((port >= 3001 && port <= 58538)) || {
    echo "Test ports must be integers from 3001 to 58538 (including room for auxiliary ports)" >&2
    exit 2
  }
done
export ZOLANA_LOCALNET_URL="http://127.0.0.1:$ZOLANA_LOCALNET_RPC_PORT"
export ZOLANA_INDEXER_URL="http://127.0.0.1:$ZOLANA_LOCALNET_PHOTON_PORT"
export ZOLANA_PROVER_URL="http://127.0.0.1:$prover_port"

command -v lsof >/dev/null || { echo "lsof is required to check test ports" >&2; exit 1; }
for port in "$ZOLANA_LOCALNET_RPC_PORT" "$((ZOLANA_LOCALNET_RPC_PORT + 1))" \
  "$((ZOLANA_LOCALNET_RPC_PORT + 2))" "$ZOLANA_LOCALNET_PHOTON_PORT" \
  "$prover_port" "$metrics_port"; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "Port $port is occupied" >&2
    exit 1
  fi
done

# The ring keys are verified in place, the transfer keys download beside them once.
lock="prover/server/prover/provingkeys/proving-keys.lock"
keys_dir="$repo_root/prover/server/proving-keys"
for key in $(jq -r '.keys | keys[] | select(startswith("custom_ring_"))' "$lock"); do
  file="$keys_dir/$key"
  expected="$(jq -er --arg name "$key" '.keys[$name].sha256' "$lock")"
  actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || { echo "$file does not match the key manifest" >&2; exit 1; }
done
export ZOLANA_PROVER_KEYS_DIR="$keys_dir"

# Under the scope dir, --stop signals only recorded receipts.
cleanup() {
  "$ZOLANA_CLI_BIN" dev start --local --stop \
    --rpc-port "$ZOLANA_LOCALNET_RPC_PORT" --photon-port "$ZOLANA_LOCALNET_PHOTON_PORT" \
    --prover-port "$prover_port" || true
  echo "Ring test logs: $ZOLANA_PROCESS_SCOPE_DIR"
}
trap cleanup EXIT

ring_cli_bin="$repo_root/target/debug/zolana-ring"
if [[ -n "${ZOLANA_PREBUILT:-}" ]]; then
  for binary in "$ZOLANA_PHOTON_BIN" "$ring_cli_bin"; do
    [[ -x "$binary" ]] || { echo "Missing prebuilt executable $binary, unset ZOLANA_PREBUILT to build it" >&2; exit 1; }
  done
  tools/ci/nextest-suite.sh -p custom-ring-test-validator --test "$suite" --no-capture "$@"
else
  cargo build --locked -p photon-indexer --bin photon --features surfpool-fixture
  cargo build --locked -p custom-ring-cli
  cargo test --locked -p custom-ring-test-validator --test "$suite" "$@" -- --test-threads=1 --nocapture
fi
