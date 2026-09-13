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
: "${SURFPOOL_BIN:?Set SURFPOOL_BIN to the release-pinned Surfpool binary}"

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
export ZOLANA_PROVER_KEYS_DIR="$ZOLANA_PROCESS_SCOPE_DIR/keys"
export ZOLANA_LOCALNET_RPC_PORT="${RING_TEST_RPC_PORT:-40899}"
export ZOLANA_LOCALNET_PHOTON_PORT="${RING_TEST_PHOTON_PORT:-40784}"
prover_port="${RING_TEST_PROVER_PORT:-43001}"
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
  "$prover_port" "$((prover_port + 6997))"; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "Port $port is occupied" >&2
    exit 1
  fi
done

mkdir -p "$ZOLANA_PROVER_KEYS_DIR"
for key in custom_ring_base custom_ring_policy custom_ring_compressed_policy custom_ring_compressed_register custom_ring_delegate_policy; do
  file="prover/server/proving-keys/$key.key"
  expected="$(jq -er --arg name "$key.key" '.keys[$name].sha256' prover/server/prover/provingkeys/proving-keys.lock)"
  actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || { echo "$file does not match the key manifest" >&2; exit 1; }
  cp "$file" "$ZOLANA_PROVER_KEYS_DIR/$key.key"
done

cleanup() {
  "$ZOLANA_CLI_BIN" dev start --local --stop \
    --rpc-port "$ZOLANA_LOCALNET_RPC_PORT" --photon-port "$ZOLANA_LOCALNET_PHOTON_PORT" \
    --prover-port "$prover_port" || true
  echo "Ring test logs and key cache: $ZOLANA_PROCESS_SCOPE_DIR"
}
trap cleanup EXIT

cargo build --locked -p photon-indexer --bin photon --features surfpool-fixture
cargo build --locked -p custom-ring-cli
cargo test --locked -p custom-ring-test-validator --test "$suite" "$@" -- --test-threads=1 --nocapture
