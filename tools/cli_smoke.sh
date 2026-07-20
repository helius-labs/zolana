#!/usr/bin/env bash
#
# One-pass coverage smoke test for the `zolana` CLI against an already-deployed
# Zolana environment (localnet or devnet): the shielded-pool program, pool tree,
# prover, and Photon indexer must all be reachable. Runs every CLI operation once,
# in dependency order, asserting each step, and exercises both the SOL and SPL
# asset rails plus the ed25519 and P256 wallet rails. Replaces the older
# pingpong.sh / pingpong_parallel.sh soak scripts, which targeted a superseded
# wallet-name/SOL-float CLI surface.
#
# Every zolana output is a machine-parseable `ok <verb> key=value ...` line; the
# assertions below match on the leading `ok <verb>` and extract signature=/mode=/
# hash=/count=/amount= as needed.
#
# Usage:  ./tools/cli_smoke.sh
#
# Required env (deployment endpoints; no universal default exists):
#   ZOLANA_INDEXER_URL   Photon indexer URL for this devnet deployment
#   ZOLANA_PROVER_URL    prover server URL for this devnet deployment
#
# Optional env:
#   ZOLANA_TREE  pool tree account pubkey; omit to use the CLI's compiled-in
#                DEFAULT_TREE_ADDRESS (the canonical deployed tree)
#   ZOLANA_BIN   path to the zolana binary (default: ./target/release/zolana)
#   RPC          Solana RPC URL           (default: https://api.devnet.solana.com)
#   FUNDER       Solana keypair that tops up wallet funding keys and receives the
#                withdrawal (default: ~/.config/solana/id.json)
#   WORKDIR      isolated config+wallet dir (default: ./.cli-smoke; reused across runs)
#   FUND_SOL     SOL sent to each wallet funding key   (default: 1.0)
#   DEPOSIT      lamports deposited per wallet          (default: 200000000 = 0.2 SOL)
#   TRANSFER     lamports per shielded transfer         (default: 20000000  = 0.02 SOL)
#   WITHDRAW     lamports per withdrawal                (default: 10000000  = 0.01 SOL)
#   SPLIT_PARTS  parts for `split`                      (default: 4)
#   SPL_UNITS    raw token units minted/moved for SPL   (default: 1000000)
#   MAX_RETRIES RETRY_DELAY  shielded-op retry policy   (default: 6 / 3)
#   CLUSTER      explorer cluster for tx links          (default: devnet)
#
# The SPL section is best-effort: `dev pool test-mint` requires the funding key to
# satisfy the deployment's SPL-creation policy (protocol authority, or a
# permissionless policy). If it is not permitted, the SPL steps are SKIPPED with a
# warning rather than failing the run; the SOL rail always executes.

set -uo pipefail

# --- configuration -----------------------------------------------------------
ROOT="$(cd "$(dirname "$0")/.." && pwd)"   # repo root (this script lives in tools/)
BIN="${ZOLANA_BIN:-$ROOT/target/release/zolana}"
RPC="${RPC:-https://api.devnet.solana.com}"
FUNDER="${FUNDER:-$HOME/.config/solana/id.json}"
WORKDIR="${WORKDIR:-$ROOT/.cli-smoke}"
FUND_SOL="${FUND_SOL:-1.0}"
DEPOSIT="${DEPOSIT:-200000000}"
TRANSFER="${TRANSFER:-20000000}"
WITHDRAW="${WITHDRAW:-10000000}"
SPLIT_PARTS="${SPLIT_PARTS:-4}"
SPL_UNITS="${SPL_UNITS:-1000000}"
MAX_RETRIES="${MAX_RETRIES:-6}"
RETRY_DELAY="${RETRY_DELAY:-3}"
CLUSTER="${CLUSTER:-devnet}"

INDEXER="${ZOLANA_INDEXER_URL:-}"
PROVER="${ZOLANA_PROVER_URL:-}"
TREE="${ZOLANA_TREE:-}"

# Fully isolate config.json, the default keypair, and any wallet files under
# WORKDIR so the run never touches the operator's ~/.config/zolana.
export ZOLANA_CONFIG_DIR="$WORKDIR"

ALICE="$WORKDIR/alice.json"   # ed25519 rail, primary actor
BOB="$WORKDIR/bob.json"       # ed25519 rail, transfer recipient
CAROL="$WORKDIR/carol.json"   # P256 rail, cross-rail transfer recipient

PASS=0 FAIL=0 SKIP=0
LAST_OUT=""

# --- output helpers ----------------------------------------------------------
ts() { date +%H:%M:%S; }
log()  { printf '%s  %s\n'      "$(ts)" "$*"; }
info() { printf '%s  ..   %s\n' "$(ts)" "$*"; }
xurl() { printf 'https://explorer.solana.com/tx/%s?cluster=%s' "$1" "$CLUSTER"; }

# kv <key> — extract the value of key=<value> from LAST_OUT (first match).
kv() { sed -n "s/.*[[:space:]]$1=\([^[:space:]]*\).*/\1/p" <<<"$LAST_OUT" | head -n1; }

# Run a zolana subcommand, capturing combined output into LAST_OUT.
# Returns the command's exit status.
z() { LAST_OUT="$("$BIN" "$@" 2>&1)"; }

# ok_line <verb> — true if LAST_OUT satisfies the assertion for <verb>:
#   "-"  => any exit-0 output is fine (commands that print bare text, no `ok` line)
#   else => require a line starting with `ok <verb>`.
ok_line() { [[ "$1" == "-" ]] || grep -q "^ok $1" <<<"$LAST_OUT"; }

# step "<desc>" <verb|-> <cmd...>  — run, require exit 0 AND the verb assertion.
# Aborts the whole run on failure (fail-fast for the core SOL rail).
step() {
  local desc="$1" verb="$2"; shift 2
  if z "$@" && ok_line "$verb"; then
    PASS=$((PASS + 1)); log "PASS $desc"; return 0
  fi
  FAIL=$((FAIL + 1)); log "FAIL $desc"
  sed 's/^/       | /' <<<"$LAST_OUT"
  summary; exit 1
}

# soft "<desc>" <verb|-> <cmd...> — like step but on failure WARNS + returns 1
# instead of aborting. Used for the optional (best-effort) SPL rail.
soft() {
  local desc="$1" verb="$2"; shift 2
  if z "$@" && ok_line "$verb"; then
    PASS=$((PASS + 1)); log "PASS $desc"; return 0
  fi
  SKIP=$((SKIP + 1)); log "SKIP $desc"
  sed 's/^/       | /' <<<"$LAST_OUT"
  return 1
}

# new_wallet "<desc>" <path> [extra wallet-new args] — create the wallet only if
# its file is absent; otherwise reuse it. `wallet new` is an exclusive 0600 create
# that would error on an existing file, so reuse keeps funded wallets across runs.
new_wallet() {
  local desc="$1" path="$2"; shift 2
  if [[ -f "$path" ]]; then
    PASS=$((PASS + 1)); log "PASS $desc (reused existing)"; return 0
  fi
  step "$desc" wallet wallet new --outfile "$path" "$@"
}

# A shielded transfer lands as soon as the CLI prints `mode=<expected>`, even when
# it appends `(indexing pending)` (confirmed on-chain, indexer catching up). Retry
# only on a genuine failure so a landed transfer is never resent under indexer lag.
# transfer_step "<desc>" <expected-mode> <cmd...>
transfer_step() {
  local desc="$1" want="$2"; shift 2
  local i sig mode
  for ((i = 1; i <= MAX_RETRIES; i++)); do
    if z "$@" && grep -q "^ok transfer" <<<"$LAST_OUT"; then
      mode="$(kv mode)"
      if [[ "$mode" == "$want" ]]; then
        sig="$(kv signature)"
        PASS=$((PASS + 1)); log "PASS $desc  mode=$mode  $(xurl "$sig")"; return 0
      fi
      FAIL=$((FAIL + 1)); log "FAIL $desc  expected mode=$want got mode=$mode"
      sed 's/^/       | /' <<<"$LAST_OUT"; summary; exit 1
    fi
    info "retry $desc $i/$MAX_RETRIES: $(tail -n1 <<<"$LAST_OUT")"
    sleep "$RETRY_DELAY"
  done
  FAIL=$((FAIL + 1)); log "FAIL $desc after $MAX_RETRIES attempts"
  sed 's/^/       | /' <<<"$LAST_OUT"; summary; exit 1
}

# transfer_soft "<desc>" <expected-mode> <cmd...> — retrying transfer that SKIPs
# (warns, returns 1) instead of aborting. Used for the best-effort SPL rail.
transfer_soft() {
  local desc="$1" want="$2"; shift 2
  local i sig mode
  for ((i = 1; i <= MAX_RETRIES; i++)); do
    if z "$@" && grep -q "^ok transfer" <<<"$LAST_OUT"; then
      mode="$(kv mode)"
      if [[ "$mode" == "$want" ]]; then
        sig="$(kv signature)"
        PASS=$((PASS + 1)); log "PASS $desc  mode=$mode  $(xurl "$sig")"; return 0
      fi
      SKIP=$((SKIP + 1)); log "SKIP $desc  expected mode=$want got mode=$mode"; return 1
    fi
    info "retry $desc $i/$MAX_RETRIES: $(tail -n1 <<<"$LAST_OUT")"
    sleep "$RETRY_DELAY"
  done
  SKIP=$((SKIP + 1)); log "SKIP $desc after $MAX_RETRIES attempts"
  sed 's/^/       | /' <<<"$LAST_OUT"; return 1
}

summary() {
  log "----------------------------------------------------------------"
  log "summary: $PASS passed, $FAIL failed, $SKIP skipped"
}

# --- funding (FUNDER keypair, devnet-airdrop fallback) -----------------------
funding_pubkey() { z wallet address --funding --keypair "$1"; printf '%s\n' "$LAST_OUT"; }

# Fund a public key to at least FUND_SOL via FUNDER; fall back to a devnet airdrop.
fund_pubkey() {
  local addr="$1" bal
  bal="$(solana balance "$addr" --url "$RPC" 2>/dev/null | awk '{print $1}')"
  if [[ -n "$bal" ]] && awk "BEGIN{exit !($bal >= $FUND_SOL)}"; then
    info "funded already $addr ($bal SOL)"; return 0
  fi
  if solana transfer "$addr" "$FUND_SOL" --keypair "$FUNDER" --url "$RPC" \
       --allow-unfunded-recipient --commitment confirmed >/dev/null 2>&1; then
    info "funded $addr +$FUND_SOL SOL (FUNDER)"; return 0
  fi
  info "FUNDER transfer failed for $addr; trying devnet airdrop"
  if solana airdrop "$FUND_SOL" "$addr" --url "$RPC" >/dev/null 2>&1; then
    info "funded $addr +$FUND_SOL SOL (airdrop)"; return 0
  fi
  log "FAIL could not fund $addr (FUNDER dry and airdrop refused)"
  summary; exit 1
}

# largest_utxo_hash <keypair> <mint> — echo the hash of the largest plain utxo.
largest_utxo_hash() {
  z utxos --keypair "$1" --mint "$2"
  awk '
    /^ok utxo / {
      h=""; a=0
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^hash=/)   { h = substr($i, 6) }
        if ($i ~ /^amount=/) { a = substr($i, 8) + 0 }
      }
      if (h != "" && a > best) { best = a; besth = h }
    }
    END { print besth }
  ' <<<"$LAST_OUT"
}

# --- preflight ---------------------------------------------------------------
[[ -x "$BIN" ]]              || { log "binary not found/executable: $BIN (build with: cargo build --release -p zolana-cli)"; exit 1; }
command -v solana >/dev/null || { log "solana CLI not found (needed for funding + withdrawal target)"; exit 1; }
[[ -f "$FUNDER" ]]           || { log "FUNDER keypair not found: $FUNDER"; exit 1; }
[[ -n "$INDEXER" ]]          || { log "set ZOLANA_INDEXER_URL to this devnet's Photon indexer"; exit 1; }
[[ -n "$PROVER"  ]]          || { log "set ZOLANA_PROVER_URL to this devnet's prover server"; exit 1; }

mkdir -p "$WORKDIR"   # never wipe: funded wallet files here are reused across runs
FUNDER_PUBKEY="$(solana address --keypair "$FUNDER" 2>/dev/null)"
log "zolana CLI smoke test"
log "  bin=$BIN"
log "  rpc=$RPC  indexer=$INDEXER  prover=$PROVER"
log "  tree=${TREE:-(CLI default)}"
log "  workdir=$WORKDIR  funder=$FUNDER_PUBKEY"
log "================================================================"

# --- 1. config ---------------------------------------------------------------
CONFIG_SET_ARGS=(config set --rpc-url "$RPC" --indexer-url "$INDEXER" --prover-url "$PROVER")
[[ -n "$TREE" ]] && CONFIG_SET_ARGS+=(--tree "$TREE")
step "config set (endpoints${TREE:+ + tree})" config "${CONFIG_SET_ARGS[@]}"
step "config get"        - config get
step "config asset path" - config asset path
step "config asset list" - config asset list

# --- 2. wallets (ed25519 x2, P256 x1) ----------------------------------------
new_wallet "wallet new alice (ed25519)" "$ALICE"
new_wallet "wallet new bob (ed25519)"   "$BOB"
new_wallet "wallet new carol (P256)"    "$CAROL" --p256

step "wallet address alice (owner hash)"  - wallet address --keypair "$ALICE"
ALICE_FUND="$(funding_pubkey "$ALICE")"
BOB_FUND="$(funding_pubkey "$BOB")"
CAROL_FUND="$(funding_pubkey "$CAROL")"
log "  alice funding=$ALICE_FUND"
log "  bob   funding=$BOB_FUND"
log "  carol funding=$CAROL_FUND"

# --- 3. fund funding keys, then register on-chain ----------------------------
for a in "$ALICE_FUND" "$BOB_FUND" "$CAROL_FUND"; do fund_pubkey "$a"; done

step "register alice" register wallet register --keypair "$ALICE"
step "register bob"   register wallet register --keypair "$BOB"
step "register carol" register wallet register --keypair "$CAROL"

# --- 4. SOL rail: deposit -> transfer -> withdraw -> split -> merge -----------
step "deposit SOL (alice, self)"      deposit deposit --keypair "$ALICE" --amount "$DEPOSIT"
step "deposit SOL (bob, self)"        deposit deposit --keypair "$BOB"   --amount "$DEPOSIT"
step "sync alice"                     sync    sync    --keypair "$ALICE"
step "balance SOL alice"              balance balance --keypair "$ALICE" --mint SOL
step "utxos SOL alice"                utxos   utxos   --keypair "$ALICE" --mint SOL

# registered recipient (ed25519) -> shielded
transfer_step "transfer SOL alice -> bob (shielded)"   shielded \
  transfer --keypair "$ALICE" --to "$BOB_FUND"   --amount "$TRANSFER" --mint SOL
# registered recipient (P256) -> shielded, cross-rail
transfer_step "transfer SOL alice -> carol (shielded, P256)" shielded \
  transfer --keypair "$ALICE" --to "$CAROL_FUND" --amount "$TRANSFER" --mint SOL
# unregistered recipient -> automatic public withdrawal fallback (CLI: mode=withdraw)
transfer_step "transfer SOL alice -> FUNDER (withdrawal fallback)" withdraw \
  transfer --keypair "$ALICE" --to "$FUNDER_PUBKEY" --amount "$WITHDRAW" --mint SOL

step "withdraw SOL alice -> FUNDER"   withdraw \
  withdraw --keypair "$ALICE" --to "$FUNDER_PUBKEY" --amount "$WITHDRAW" --mint SOL

step "split SOL alice into $SPLIT_PARTS" split \
  split --keypair "$ALICE" --mint SOL --parts "$SPLIT_PARTS"

step "set-merging enable alice"  set_merging set-merging --keypair "$ALICE" --enable
step "merge SOL alice (auto-sweep)" merge   merge       --keypair "$ALICE" --mint SOL
step "set-merging disable alice" set_merging set-merging --keypair "$ALICE" --disable

# split by explicit --input (exercises the input-selection flag)
step "deposit SOL (alice, for explicit-input split)" deposit \
  deposit --keypair "$ALICE" --amount "$DEPOSIT"
step "sync alice" sync sync --keypair "$ALICE"
SPLIT_INPUT="$(largest_utxo_hash "$ALICE" SOL)"
[[ -n "$SPLIT_INPUT" ]] || { log "FAIL no SOL utxo to split by --input"; summary; exit 1; }
step "split SOL alice --input $SPLIT_INPUT" split \
  split --keypair "$ALICE" --mint SOL --parts 2 --input "$SPLIT_INPUT"

# --- 5. SPL rail (best-effort: needs SPL-creation policy for test-mint) -------
log "----------------------------------------------------------------"
if soft "dev pool test-mint (SPL bootstrap)" test_mint \
      dev pool test-mint --keypair "$ALICE" --authority-path "$ALICE" --amount "$SPL_UNITS"; then
  MINT="$(kv mint)"; ASSET_ID="$(kv asset_id)"; TOKEN_ACCT="$(kv token_account)"
  log "  spl mint=$MINT asset_id=$ASSET_ID token_account=$TOKEN_ACCT"

  # Best-effort from here: every SPL step SKIPs (warns) rather than aborting, so an
  # SPL-only edge (e.g. an SPL withdrawal needing a pre-existing destination ATA)
  # never fails the run after the SOL rail has passed.
  soft "config asset list (shows SPL)" - config asset list
  soft "config asset add (idempotent re-add)" asset_registry \
    config asset add --mint "$MINT" --asset-id "$ASSET_ID" --token-account "$TOKEN_ACCT"

  soft "deposit SPL (alice)"  deposit deposit  --keypair "$ALICE" --mint "$MINT" --amount "$SPL_UNITS"
  soft "sync alice (SPL)"     sync    sync     --keypair "$ALICE"
  soft "balance SPL alice"    balance balance  --keypair "$ALICE" --mint "$MINT"
  soft "utxos SPL alice"      utxos   utxos    --keypair "$ALICE" --mint "$MINT"

  SPL_XFER=$((SPL_UNITS / 10))
  transfer_soft "transfer SPL alice -> bob (shielded)" shielded \
    transfer --keypair "$ALICE" --to "$BOB_FUND" --amount "$SPL_XFER" --mint "$MINT"
  soft "withdraw SPL alice -> FUNDER" withdraw \
    withdraw --keypair "$ALICE" --to "$FUNDER_PUBKEY" --amount "$SPL_XFER" --mint "$MINT"
  soft "split SPL alice into 2" split \
    split --keypair "$ALICE" --mint "$MINT" --parts 2
  soft "set-merging enable alice (SPL)"  set_merging set-merging --keypair "$ALICE" --enable
  soft "merge SPL alice (auto-sweep)"    merge       merge       --keypair "$ALICE" --mint "$MINT"
  soft "set-merging disable alice (SPL)" set_merging set-merging --keypair "$ALICE" --disable
else
  log "SPL rail skipped: alice does not satisfy this deployment's SPL-creation"
  log "policy (protocol authority / permissionless). Set FUNDER/authority to the"
  log "protocol authority, or run against a permissionless-SPL deployment."
fi

# --- 6. final state ----------------------------------------------------------
log "----------------------------------------------------------------"
step "final sync alice"    sync    sync    --keypair "$ALICE"
step "final balance alice" balance balance --keypair "$ALICE"
step "final balance bob"   balance balance --keypair "$BOB"
step "final balance carol" balance balance --keypair "$CAROL"

summary
[[ "$FAIL" -eq 0 ]] || exit 1
log "all covered CLI operations passed"
