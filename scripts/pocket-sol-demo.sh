#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

RPC_PORT="${POCKET_SOL_RPC_PORT:-8899}"
FAUCET_PORT="${POCKET_SOL_FAUCET_PORT:-9900}"
GOSSIP_PORT="${POCKET_SOL_GOSSIP_PORT:-9901}"
DYNAMIC_RANGE="${POCKET_SOL_DYNAMIC_PORT_RANGE:-9902-9952}"
RPC_URL="http://127.0.0.1:${RPC_PORT}"
PROGRAM_ID="${SHIELDED_POOL_PROGRAM_ID:-S7exd9VLhvwVWK9wqRGQrg87616fGnyYEvrsuA1D2LG}"
WORKDIR="${POCKET_SOL_WORKDIR:-$(mktemp -d "${TMPDIR:-/tmp}/pocket-sol-demo.XXXXXX")}"
LEDGER_DIR="${WORKDIR}/ledger"
VALIDATOR_LOG="${WORKDIR}/validator.log"

POCKET="${ROOT}/target/debug/pocket"
PROVER="${ROOT}/target/prover-server"
KEYS_FILE="${ROOT}/target/spp/spp_1_2.key"
PROGRAM_SO="${ROOT}/target/deploy/shielded_pool_program.so"

A_KEY="${WORKDIR}/wallet-a.json"
B_KEY="${WORKDIR}/wallet-b.json"
A_STATE="${WORKDIR}/wallet-a.state.json"
B_STATE="${WORKDIR}/wallet-b.state.json"
TREE_KEY="${WORKDIR}/pool-tree.json"

A_AIRDROP_SOL="${A_AIRDROP_SOL:-20}"
B_AIRDROP_SOL="${B_AIRDROP_SOL:-20}"
A_SHIELD_LAMPORTS="${A_SHIELD_LAMPORTS:-1000000000}"
TRANSFER_LAMPORTS="${TRANSFER_LAMPORTS:-400000000}"
B_SHIELD_LAMPORTS="${B_SHIELD_LAMPORTS:-500000000}"

validator_pid=""
cleanup() {
    if [[ -n "$validator_pid" ]]; then
        if kill -0 "$validator_pid" >/dev/null 2>&1; then
            echo
            echo "Validator left running:"
            echo "  pid: $validator_pid"
            echo "  rpc: $RPC_URL"
            echo "  ledger: $LEDGER_DIR"
            echo "  log: $VALIDATOR_LOG"
        fi
    fi
    echo "Workdir preserved: $WORKDIR"
}
trap cleanup EXIT

json_field() {
    local field="$1"
    sed -n "s/.*\"${field}\": \"\\([^\"]*\\)\".*/\\1/p" | head -n 1
}

print_signature() {
    local label="$1"
    local json="$2"
    local sig
    sig="$(printf '%s\n' "$json" | json_field signature)"
    echo "${label} tx signature: ${sig}"
}

run_json() {
    "$@"
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing required command: $1" >&2
        exit 1
    }
}

kill_port_owner() {
    local port="$1"
    local pids
    pids="$(lsof -ti "tcp:${port}" 2>/dev/null || true)"
    if [[ -z "$pids" ]]; then
        return 0
    fi
    echo "Stopping existing process(es) on port ${port}: ${pids//$'\n'/ }"
    for pid in $pids; do
        kill "$pid" >/dev/null 2>&1 || true
    done
    for _ in $(seq 1 20); do
        local still_running=""
        for pid in $pids; do
            if kill -0 "$pid" >/dev/null 2>&1; then
                still_running=1
            fi
        done
        [[ -z "$still_running" ]] && return 0
        sleep 0.25
    done
    for pid in $pids; do
        kill -9 "$pid" >/dev/null 2>&1 || true
    done
}

stop_existing_validator() {
    kill_port_owner "$RPC_PORT"
    kill_port_owner "$FAUCET_PORT"
    kill_port_owner "$GOSSIP_PORT"
}

wait_for_validator() {
    echo "Waiting for validator at ${RPC_URL}"
    for _ in $(seq 1 120); do
        if solana --url "$RPC_URL" block-height >/dev/null 2>&1; then
            return 0
        fi
        if ! kill -0 "$validator_pid" >/dev/null 2>&1; then
            echo "validator exited early; log follows:" >&2
            cat "$VALIDATOR_LOG" >&2 || true
            exit 1
        fi
        sleep 1
    done
    echo "timed out waiting for validator; log follows:" >&2
    cat "$VALIDATOR_LOG" >&2 || true
    exit 1
}

print_balances() {
    local title="$1"
    echo
    echo "== ${title}: wallet SOL balances =="
    "$POCKET" balance --rpc-url "$RPC_URL" --wallet "$A_KEY"
    "$POCKET" balance --rpc-url "$RPC_URL" --wallet "$B_KEY"
    echo "== ${title}: private SOL note balances =="
    "$POCKET" balance --state "$A_STATE" --asset-id 1
    "$POCKET" balance --state "$B_STATE" --asset-id 1
}

require_cmd solana
require_cmd solana-test-validator
require_cmd lsof

echo "Workdir: $WORKDIR"
mkdir -p "$WORKDIR"

echo "Building pocket CLI, prover keys, and shielded-pool SBF"
just build-zolana-cli build-spp-keys
cargo build-sbf --tools-version "${SBF_TOOLS_VERSION:-v1.54}" \
    --manifest-path programs/shielded-pool/Cargo.toml -- --features bpf-entrypoint

echo "Starting solana-test-validator"
stop_existing_validator
solana-test-validator \
    --reset \
    --quiet \
    --ledger "$LEDGER_DIR" \
    --rpc-port "$RPC_PORT" \
    --faucet-port "$FAUCET_PORT" \
    --gossip-port "$GOSSIP_PORT" \
    --dynamic-port-range "$DYNAMIC_RANGE" \
    --bpf-program "$PROGRAM_ID" "$PROGRAM_SO" \
    >"$VALIDATOR_LOG" 2>&1 &
validator_pid="$!"
wait_for_validator

echo
echo "== Creating wallets =="
A_JSON="$(run_json "$POCKET" create-wallet --rpc-url "$RPC_URL" --output "$A_KEY" --force)"
B_JSON="$(run_json "$POCKET" create-wallet --rpc-url "$RPC_URL" --output "$B_KEY" --force)"
echo "Wallet A:"
printf '%s\n' "$A_JSON"
echo "Wallet B:"
printf '%s\n' "$B_JSON"
A_PUBKEY="$(printf '%s\n' "$A_JSON" | json_field pubkey)"
B_PUBKEY="$(printf '%s\n' "$B_JSON" | json_field pubkey)"

echo
echo "== Airdropping SOL =="
solana --url "$RPC_URL" airdrop "$A_AIRDROP_SOL" "$A_PUBKEY"
solana --url "$RPC_URL" airdrop "$B_AIRDROP_SOL" "$B_PUBKEY"

print_balances "Before operations"

echo
echo "== Initializing pool tree =="
TREE="$("$POCKET" init-pool-tree \
    --rpc-url "$RPC_URL" \
    --payer "$A_KEY" \
    --output "$TREE_KEY" \
    --force \
    --pubkey-only)"
echo "Pool tree: $TREE"

echo
echo "== Shield A SOL =="
SHIELD_A_JSON="$("$POCKET" shield \
    --rpc-url "$RPC_URL" \
    --payer "$A_KEY" \
    --state "$A_STATE" \
    --tree "$TREE" \
    --prover-bin "$PROVER" \
    --keys-file "$KEYS_FILE" \
    --amount "$A_SHIELD_LAMPORTS")"
printf '%s\n' "$SHIELD_A_JSON"
print_signature "shield A" "$SHIELD_A_JSON"

echo
echo "== Private transfer A -> B =="
TRANSFER_JSON="$("$POCKET" transfer \
    --rpc-url "$RPC_URL" \
    --payer "$A_KEY" \
    --state "$A_STATE" \
    --recipient-wallet "$B_KEY" \
    --recipient-state "$B_STATE" \
    --tree "$TREE" \
    --prover-bin "$PROVER" \
    --keys-file "$KEYS_FILE" \
    --amount "$TRANSFER_LAMPORTS")"
printf '%s\n' "$TRANSFER_JSON"
print_signature "transfer A to B" "$TRANSFER_JSON"

echo
echo "== Shield B SOL =="
SHIELD_B_JSON="$("$POCKET" shield \
    --rpc-url "$RPC_URL" \
    --payer "$B_KEY" \
    --state "$B_STATE" \
    --tree "$TREE" \
    --prover-bin "$PROVER" \
    --keys-file "$KEYS_FILE" \
    --amount "$B_SHIELD_LAMPORTS")"
printf '%s\n' "$SHIELD_B_JSON"
print_signature "shield B" "$SHIELD_B_JSON"

print_balances "After operations"
