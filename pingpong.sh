#!/usr/bin/env bash
#
# Ping-pong shielded transfers between two local rings wallets, with
# auto-refuel of the funding (public) keys and per-hop tx logging.
# One "round" = alice -> bob, then bob -> alice.
#
# Usage:  ./pingpong.sh [rounds] [amount_sol]
#   rounds      round trips to run     (default 1000000)
#   amount_sol  SOL bounced each hop    (default 0.001)
#
# Env overrides:
#   RINGS_BIN ALICE_WALLET BOB_WALLET
#   FUNDER (keypair that tops up funding keys, default ~/.config/solana/id.json)
#   RPC (default: rpc_url from ~/.config/rings/config.json)
#   MIN_FUNDING (SOL; refuel when a funding key drops below this, default 0.01)
#   REFUND (SOL added per refuel, default 0.05)
#   MAX_RETRIES RETRY_DELAY HOP_DELAY PROGRESS_EVERY
#
# Each transfer burns ~5000 lamports of the SENDER's funding (public) SOL as a
# network fee; auto-refuel tops that up from FUNDER so the soak keeps running
# until FUNDER itself runs dry (then it aborts with a clear error).

set -uo pipefail

BIN="${RINGS_BIN:-$(cd "$(dirname "$0")" && pwd)/target/release/rings}"
ALICE="${ALICE_WALLET:-alice}"
BOB="${BOB_WALLET:-bob}"
ROUNDS="${1:-1000000}"
AMOUNT="${2:-0.001}"
FUNDER="${FUNDER:-$HOME/.config/solana/id.json}"
RPC="${RPC:-$(python3 -c "import json;print(json.load(open('$HOME/.config/rings/config.json')).get('rpc_url') or '')" 2>/dev/null)}"
MIN_FUNDING="${MIN_FUNDING:-0.01}"
REFUND="${REFUND:-0.05}"
MAX_RETRIES="${MAX_RETRIES:-5}"
RETRY_DELAY="${RETRY_DELAY:-2}"
HOP_DELAY="${HOP_DELAY:-0}"
PROGRESS_EVERY="${PROGRESS_EVERY:-25}"

log() { printf '%s  %s\n' "$(date +%H:%M:%S)" "$*"; }
sol() { "$BIN" wallet balance -w "$1" 2>/dev/null | sed -n 's/.*sol=\([0-9.]*\).*/\1/p'; }
CLUSTER="${CLUSTER:-devnet}"          # Solana Explorer cluster for tx links
xurl() { printf 'https://explorer.solana.com/tx/%s?cluster=%s' "$1" "$CLUSTER"; }

# Top up a wallet's funding key from FUNDER when it dips below MIN_FUNDING.
# args: <wallet-name> <funding-addr>
ensure_funded() {
  local name="$1" addr="$2" bal out sig
  bal="$(solana balance "$addr" --url "$RPC" 2>/dev/null | awk '{print $1}')"
  [[ -z "$bal" ]] && { log "warn  could not read $name funding balance; skipping refuel"; return 0; }
  awk "BEGIN{exit !($bal < $MIN_FUNDING)}" || return 0   # balance ok, nothing to do
  log "refuel $name funding=$bal SOL < $MIN_FUNDING -> +$REFUND SOL"
  if out="$(solana transfer "$addr" "$REFUND" --keypair "$FUNDER" --url "$RPC" \
              --allow-unfunded-recipient --commitment confirmed 2>&1)"; then
    sig="$(sed -n 's/.*Signature: *\([A-Za-z0-9]*\).*/\1/p' <<<"$out")"
    log "refuel $name ok  sig=$sig"
    return 0
  fi
  log "ERROR refuel $name failed (FUNDER dry / rpc error): $(tail -n1 <<<"$out")"
  return 1
}

# One shielded transfer with retries; logs the signature on success.
# args: <amount> <to-wallet> <from-wallet>  -> 0 ok / 1 failed / 2 not shielded
#
# A `mode=shielded` line means the transfer LANDED on-chain and is success, even
# when the CLI appends ` (indexing pending)` (confirmed on-chain but the indexer
# has not caught up). The CLI only exits non-zero / omits `mode=shielded` on a
# genuine on-chain failure or a still-unconfirmed signature, so retries fire only
# on real failures — a landed transfer is never resent, which is what stops the
# indexer-lag retry-flood.
transfer() {
  local amount="$1" to="$2" from="$3" attempt out sig
  for ((attempt = 1; attempt <= MAX_RETRIES; attempt++)); do
    out="$("$BIN" wallet transfer "$amount" "$to" -w "$from" 2>&1)"
    if grep -q "mode=shielded" <<<"$out"; then
      sig="$(sed -n 's/.*signature=\([A-Za-z0-9]*\).*/\1/p' <<<"$out")"
      if grep -q "indexing pending" <<<"$out"; then
        log "ok    $from -> $to  $amount SOL  $(xurl "$sig")  (indexing pending)"
      else
        log "ok    $from -> $to  $amount SOL  $(xurl "$sig")"
      fi
      return 0
    fi
    if grep -q "mode=withdrawal" <<<"$out"; then
      log "FAIL  $from -> $to  degraded to PUBLIC withdrawal: $(tail -n1 <<<"$out")"; return 2
    fi
    log "retry $from -> $to  $attempt/$MAX_RETRIES: $(tail -n1 <<<"$out")"
    sleep "$RETRY_DELAY"
  done
  log "FAIL  $from -> $to  after $MAX_RETRIES attempts: $(tail -n1 <<<"$out")"; return 1
}

# --- preflight ---------------------------------------------------------------
[[ -x "$BIN" ]] || { log "binary not found/executable: $BIN"; exit 1; }
command -v solana >/dev/null || { log "solana CLI not found (needed for refuel)"; exit 1; }
[[ -n "$RPC" ]] || { log "no RPC url (set RPC=... or 'rings config set --rpc-url ...')"; exit 1; }
[[ -f "$FUNDER" ]] || { log "FUNDER keypair not found: $FUNDER"; exit 1; }
ALICE_ADDR="$("$BIN" wallet address -w "$ALICE" 2>/dev/null)" || { log "wallet '$ALICE' not found"; exit 1; }
BOB_ADDR="$("$BIN" wallet address -w "$BOB" 2>/dev/null)"     || { log "wallet '$BOB' not found"; exit 1; }
log "ping-pong: $ALICE($ALICE_ADDR) <-> $BOB($BOB_ADDR)"
log "amount=$AMOUNT SOL | rounds=$ROUNDS | refuel<$MIN_FUNDING -> +$REFUND from $(basename "$FUNDER")"
log "start shielded balances: $ALICE=$(sol "$ALICE") $BOB=$(sol "$BOB")"

# --- loop --------------------------------------------------------------------
start=$(date +%s); done_rounds=0
trap 'log "interrupted after $done_rounds rounds ($((2*done_rounds)) transfers)"; exit 130' INT

for ((i = 1; i <= ROUNDS; i++)); do
  ensure_funded "$ALICE" "$ALICE_ADDR" || { log "aborting at round $i (refuel $ALICE)"; exit 1; }
  transfer "$AMOUNT" "$BOB" "$ALICE"    || { log "aborting at round $i (hop $ALICE->$BOB)"; exit 1; }
  [[ "$HOP_DELAY" != 0 ]] && sleep "$HOP_DELAY"
  ensure_funded "$BOB" "$BOB_ADDR"      || { log "aborting at round $i (refuel $BOB)"; exit 1; }
  transfer "$AMOUNT" "$ALICE" "$BOB"    || { log "aborting at round $i (hop $BOB->$ALICE)"; exit 1; }
  done_rounds=$i

  if ((i % PROGRESS_EVERY == 0)); then
    el=$(( $(date +%s) - start )); ((el == 0)) && el=1
    log "--- round $i/$ROUNDS | ${el}s | $(awk "BEGIN{printf \"%.2f\", (2*$i)/$el}") tx/s | $ALICE=$(sol "$ALICE") $BOB=$(sol "$BOB")"
  fi
done

log "done: $done_rounds rounds ($((2*done_rounds)) transfers) in $(( $(date +%s) - start ))s"
log "end shielded balances: $ALICE=$(sol "$ALICE") $BOB=$(sol "$BOB")"
