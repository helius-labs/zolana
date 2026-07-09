#!/usr/bin/env bash
#
# Parallel ping-pong: bounce WIDTH "balls" between two wallets, firing WIDTH
# transfers CONCURRENTLY per direction. Relies on reservation-based auto
# input-selection so concurrent transfers each claim a DISTINCT note (no 7002).
# Uses a full-note amount so a ball's value is preserved as it bounces
# (only the sender's public funding pays tx fees; auto-refueled).
#
# Usage:  ./pingpong_parallel.sh [rounds] [amount_sol]
# Env:    WIDTH (concurrent per direction, default 8), ALICE_WALLET, BOB_WALLET,
#         FUNDER, RPC, MIN_FUNDING, REFUND, MAX_RETRIES, RETRY_DELAY
#
# Prereqs: both wallets registered, merging enabled once per wallet
# (`rings wallet merge --enable -w <wallet>`), and the PAIR funded with
# >= 2*WIDTH*amount shielded SOL total. The script then self-heals before every
# batch:
#   - ensure_balance: if the sender is below WIDTH*amount, pull value from the other
#     wallet (rebalances within the pair; warns to deposit if the pair total is low).
#   - ensure_width: reshape the sender to >= WIDTH distinct notes (consolidate dust,
#     then `wallet split WIDTH`) so concurrent transfers each claim a DISTINCT note
#     instead of colliding on one (7002 double-spend).

set -uo pipefail
BIN="${RINGS_BIN:-$(cd "$(dirname "$0")" && pwd)/target/release/rings}"
ALICE="${ALICE_WALLET:-alice}"; BOB="${BOB_WALLET:-bob}"
# WIDTH default 4: ~8 concurrent Groth16 proofs (both directions) overwhelm a
# single local prover (~1.5GB heap each) and stall. Raise only with a beefier /
# horizontally-scaled prover.
WIDTH="${WIDTH:-4}"; ROUNDS="${1:-5}"; AMOUNT="${2:-0.006}"
FUNDER="${FUNDER:-$HOME/.config/solana/id.json}"
RPC="${RPC:-$(python3 -c "import json;print(json.load(open('$HOME/.config/rings/config.json')).get('rpc_url') or '')" 2>/dev/null)}"
MIN_FUNDING="${MIN_FUNDING:-0.02}"; REFUND="${REFUND:-0.1}"
MAX_RETRIES="${MAX_RETRIES:-6}"; RETRY_DELAY="${RETRY_DELAY:-2}"
CLUSTER="${CLUSTER:-devnet}"          # Solana Explorer cluster for tx links
xurl(){ printf 'https://explorer.solana.com/tx/%s?cluster=%s' "$1" "$CLUSTER"; }

log(){ printf '%s  %s\n' "$(date +%H:%M:%S)" "$*" >&2; }  # stderr: keeps $(batch) capture clean
addr(){ "$BIN" wallet address -w "$1" 2>/dev/null; }
sol(){ "$BIN" wallet balance -w "$1" 2>/dev/null | sed -n 's/.*sol=\([0-9.]*\).*/\1/p'; }

# Count a wallet's spendable SOL notes worth >= AMOUNT (SOL has 9 decimals).
usable_notes(){
  local w="$1" min; min="$(awk "BEGIN{printf \"%d\", $AMOUNT*1e9}")"
  "$BIN" wallet utxos -w "$w" 2>/dev/null \
    | sed -n 's/.*amount=\([0-9][0-9]*\).*/\1/p' \
    | awk -v m="$min" 'BEGIN{c=0}$1>=m{c++}END{print c}'
}

# Ensure <wallet> holds >= WIDTH spendable notes >= AMOUNT so a WIDTH-wide batch
# gives every concurrent transfer a DISTINCT note (else the surplus collide on the
# same note -> 7002 double-spend). Reshape by gathering dust (consolidate, needs
# `wallet merge --enable`) then fanning the largest note into WIDTH equal parts.
# A wallet drained below WIDTH*AMOUNT can't be reshaped -> warn (rebalance / lower WIDTH).
ensure_width(){
  local w="$1" have need bal
  have="$(usable_notes "$w")"
  [ "${have:-0}" -ge "$WIDTH" ] && return 0
  need="$(awk "BEGIN{print $WIDTH*$AMOUNT}")"; bal="$(sol "$w")"
  if awk "BEGIN{exit !($bal < $need)}"; then
    log "warn  $w: ${have:-0} usable notes, $bal SOL < WIDTH*AMOUNT=$need -> rebalance it or lower WIDTH"
    return 1
  fi
  log "reshape $w: ${have:-0} usable notes < WIDTH=$WIDTH -> consolidate + split $WIDTH"
  "$BIN" wallet consolidate -w "$w" >/dev/null 2>&1 || true   # best-effort dust gather
  "$BIN" wallet split "$WIDTH" -w "$w" >/dev/null 2>&1 \
    || log "  warn $w split $WIDTH failed (largest note < WIDTH*AMOUNT, or merging not enabled)"
}

# Rebalance shielded value within the alice<->bob pair: if <holder> has less than
# WIDTH*AMOUNT, pull from <other> via a normal transfer (so <other>'s own
# fragmentation is handled by the CLI's auto-consolidate). Targets ~2*WIDTH*AMOUNT
# so it doesn't re-trigger every round, and never drains <other> below WIDTH*AMOUNT.
# Rebalancing moves value, it cannot add it: if the PAIR's total is too low it warns
# to deposit more.
ensure_balance(){
  local holder="$1" other="$2" need hbal obal pull
  need="$(awk "BEGIN{print $WIDTH*$AMOUNT}")"
  hbal="$(sol "$holder")"; hbal="${hbal:-0}"
  awk "BEGIN{exit !($hbal < $need)}" || return 0   # holder already has enough
  obal="$(sol "$other")"; obal="${obal:-0}"
  pull="$(awk "BEGIN{ p=2*$need-$hbal; a=$obal-$need; if(p>a)p=a; if(p<0)p=0; printf \"%.6f\", p }")"
  if awk "BEGIN{exit !($pull > 0)}"; then
    log "rebalance $other -> $holder: $pull SOL ($holder=$hbal < $need)"
    "$BIN" wallet transfer "$pull" "$holder" -w "$other" >/dev/null 2>&1 \
      || log "  warn rebalance $other -> $holder failed"
  else
    log "warn  pair too low to rebalance ($holder=$hbal $other=$obal, need $need each) -> deposit more SOL"
  fi
}

refuel(){ # top up a wallet's funding key from FUNDER when low
  local w="$1" a b; a="$(addr "$w")"
  b="$(solana balance "$a" --url "$RPC" 2>/dev/null | awk '{print $1}')"; [ -z "$b" ] && return 0
  awk "BEGIN{exit !($b < $MIN_FUNDING)}" || return 0
  solana transfer "$a" "$REFUND" --keypair "$FUNDER" --url "$RPC" \
    --allow-unfunded-recipient --commitment confirmed >/dev/null 2>&1 && log "refuel $w +$REFUND SOL"
}

one(){ # one shielded transfer with retries: <to> <from>
  # `mode=shielded` == landed on-chain (success), including the confirmed-but-
  # `(indexing pending)` case where the CLI still exits 0. Retries fire only on a
  # genuine on-chain failure / unconfirmed signature, so a landed transfer is
  # never resent even when the indexer lags under concurrency.
  local to="$1" from="$2" i out sig
  for ((i=1;i<=MAX_RETRIES;i++)); do
    out="$("$BIN" wallet transfer "$AMOUNT" "$to" -w "$from" 2>&1)"
    if grep -q "mode=shielded" <<<"$out"; then
      sig="$(sed -n 's/.*signature=\([A-Za-z0-9]*\).*/\1/p' <<<"$out")"
      if grep -q "indexing pending" <<<"$out"; then
        log "  ok $from->$to  $(xurl "$sig")  (indexing pending)"
      else
        log "  ok $from->$to  $(xurl "$sig")"
      fi
      return 0
    fi
    log "  retry $from->$to  $i/$MAX_RETRIES: $(tail -n1 <<<"$out")"
    sleep "$RETRY_DELAY"
  done
  log "  FAIL $from->$to after $MAX_RETRIES: $(tail -n1 <<<"$out")"
  return 1
}

batch(){ # fire WIDTH concurrent transfers <to> <from>; echo success count
  local to="$1" from="$2" k ok=0; local -a pids=()
  refuel "$from"
  ensure_balance "$from" "$to" || true   # pull value from the other side if drained
  ensure_width "$from" || true           # reshape sender to >= WIDTH distinct notes
  for ((k=1;k<=WIDTH;k++)); do one "$to" "$from" & pids+=($!); done
  for p in "${pids[@]}"; do wait "$p" && ok=$((ok+1)); done
  echo "$ok"
}

for w in "$ALICE" "$BOB"; do [ -f "$HOME/.config/rings/wallets/$w.json" ] || { log "missing wallet $w"; exit 1; }; done
log "parallel ping-pong: width=$WIDTH rounds=$ROUNDS amount=$AMOUNT SOL"
log "start: $ALICE=$(sol "$ALICE") $BOB=$(sol "$BOB")"
start=$(date +%s); tot=0
for ((r=1;r<=ROUNDS;r++)); do
  a=$(batch "$BOB" "$ALICE")          # alice -> bob  (WIDTH concurrent)
  b=$(batch "$ALICE" "$BOB")          # bob -> alice  (WIDTH concurrent)
  tot=$((tot + a + b)); el=$(( $(date +%s) - start )); ((el==0)) && el=1
  rate=$(awk "BEGIN{printf \"%.2f\", $tot/$el}")
  log "round $r/$ROUNDS: A->B $a/$WIDTH  B->A $b/$WIDTH  | $tot tx | $rate tx/s"
done
log "done: $tot transfers in $(( $(date +%s) - start ))s  | $ALICE=$(sol "$ALICE") $BOB=$(sol "$BOB")"
