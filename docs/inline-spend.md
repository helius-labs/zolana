# Inline spend: 100 notes in one transaction

Branch `experiment/merge/wide-merge`, forked from `experiment/merge/10x-admission`.

## Why

Merging 100 notes takes three sequential 36-input merges on PR #320 and a
buffer upload plus a commit on 10x-admission. One transaction needs three
things at once:

1. No per-note account. Transaction v1 allows 64 addresses; the admission
   filter and compact pending table of 10x-admission already replace the
   nullifier PDAs.
2. The statement in instruction data. 100 nullifiers are 3,200 bytes; the
   rest of the statement, the proof and the BSB22 commitment have to fit in
   the remaining ~900 bytes of a 4,096-byte transaction.
3. One proof the owner can produce. The admitted payment circuit proves
   membership, ownership and balance; spentness is checked on chain.

## What was added

- Circuit shape `direct-payment-gkr` 100 inputs × 1 output: membership,
  ownership, balance and non-inclusion at one nullifier root, Poseidon
  through the GKR compressor. 1,432,787 constraints (144×2 admitted is
  1,232,023; the same shape without non-inclusion was 1,091,546). Key
  `direct-payment-gkr_100_1.key`, 455 MB; verifying key module
  `direct_payment_gkr_100_1`.
- Instruction `inline_spend` (tag 28). Data `InlineSpend`: nullifiers,
  state root index, value commitment, expiry slot, max forester fee, one
  output (`OutputUtxo`), tx viewing key, salt, proof, commitment. The input
  tree, output tree, state root value and the non-inclusion root come from
  the accounts; every output is paid to the owner. 3,627 bytes at 100 inputs.
- Accounts: owner (signer, pays), input tree, output tree, pending
  nullifiers, nullifier filter, system program, this program. Seven
  addresses.
- The program expands `InlineSpend` into the same `Payment` the buffer path
  uses (`InlineSpend::payment`), with `INLINE_BINDING` (zero) in place of the
  buffer address in the intent and the certificate id, then runs the shared
  note verification and settlement (`direct_spend/commit.rs`: `NotesProof`,
  `Spend::settle`, `emit_events`). Admission is filter-negative, like an
  admitted payment, but the proof also covers non-inclusion at the filter's
  checkpoint root (below).
- SDK: `direct::inline_spend(payment, owner, proof)` builds the data;
  `payment(..).with_gkr()` accepts `(inputs, outputs)` from
  `GKR_PAYMENT_SHAPES`; `balance` takes one or two outputs.

## Checkpointed filter

10x-admission's filter was append-only: it had to cover the whole spend
history of the tree, so it filled up and the tree had to be rotated. The
filter now carries a checkpoint and can be cleared while the tree stays.

Header (`ZNFBLOM3`, 128 bytes): tree, hashes, next covered queue sequence,
`checkpoint_root`, `checkpoint_index`, `rebuild_cursor`,
`rebuild_close_before`. On enable the checkpoint is the empty nullifier tree
(`NULLIFIER_TREE_INIT_ROOT_40`, index 1).

Rule for a spend that relies on a filter negative: every nullifier is

1. absent from the nullifier tree at `checkpoint_root` — proven in the proof
   (`inline_spend`: freshness at the checkpoint root instead of a root in
   history; the root is stable for the whole epoch, so witnesses do not go
   stale);
2. negative in the filter, which covers the spends since the checkpoint;
3. absent from the pending table (exact).

History before the checkpoint is the tree's job, after it the filter's, the
window until the forester inserts is the pending table's — the same three
guards as before with the boundary moved.

`checkpoint_nullifier_filter` (tag 29), permissionless, accounts: tree,
pending nullifiers, filter. The first call moves the checkpoint to the tree's
current nullifier root and `next_index` and zeroes the bits; each call then
scans `CHECKPOINT_SCAN_SLOTS` (32,768) slots of the pending table and
re-records the nullifiers queued at or after `next_index` — the tree does not
hold them yet, and the pending table will forget them once they are inserted.
The default table has 131,072 slots, so a checkpoint is four calls. While the
rebuild is in progress filter-negative spends fail with
`NullifierFilterRebuilding`; legacy proof-based spends are unaffected. If the
tree's `close_before_index` moved during the rebuild, an entry the scan had
not reached may have been dropped, so the rebuild restarts. The backlog per
chunk is capped at `MAX_CHECKPOINT_BACKLOG` (1,024); a larger one fails with
`NullifierFilterBacklog` and waits for the forester.

Admitted payments without non-inclusion in the proof (`AdmittedPayment`,
`DagPayment`) remain sound only while the filter covers the whole history, so
they are refused after the first checkpoint (`NullifierFilterCheckpointed`).

## Measured

LiteSVM proof test, M5 Pro, 2026-09-17, 100 real notes merged into one output
(admitted shape, before the checkpoint change):

| | |
|---|---|
| transaction | 3,981 of 4,096 bytes, 7 of 64 addresses |
| compute units | 464,141 |
| proof (cold key, first request) | 5.97 s |
| transactions | 1 |

The checkpointed shape has the same transaction size (the proof is the same
size) and about 30% more constraints; its numbers come from
`inline_spend_settles_100_notes_in_one_transaction` and
`inline_spend_survives_a_filter_checkpoint`, which also prints the compute
units of each checkpoint step.

For comparison on the same machine: PR #320 needs three sequential 36-input
merges (about 240k CU each, three proofs of 781k constraints); the
10x-admission buffer path needs the buffer allocation, the chunk uploads and
the commit.

## Soundness

Same statement and checks as the buffer-based GKR payment: certificate over
the state root, non-inclusion at a root the program trusts, balance, intent
binding, exact pending duplicate check, filter negative. Two things differ.
The non-inclusion root is the filter's checkpoint root rather than one of the
last hundred roots in history; the checkpoint section above says why the
filter covers the gap. And replay protection no longer comes from a buffer's
`mark_spent`: an inline replay fails on the pending table
(`NullifierAlreadySpent`) exactly like a second commit of the same notes.

## Tests

```
cd prover/server && go test ./circuits/direct_spend -run TestInlineGKRPayment -v

cargo test -p zolana-tree --lib
cargo test -p zolana-interface --all-features direct_spend
cargo test -p zolana-client --lib direct_spend
ZOLANA_PROVER_URL=http://127.0.0.1:3001 cargo test -p shielded-pool-tests --features proofs \
  --test direct_spend_proofs inline_spend -- --ignored --nocapture
```

The proof tests need a prover serving `direct-payment-gkr_100_1.key` and
print proof time, transaction bytes and addresses, and compute units.

Key generation:

```
cd prover/server && go build -o light-prover . && ./light-prover setup-direct-spend \
  --circuit direct-payment-gkr --n-inputs 100 --n-outputs 1 \
  --output proving-keys/direct-payment-gkr_100_1.key \
  --output-vkey proving-keys/direct-payment-gkr_100_1.vkbin
cargo run -p xtask -- bsb22-vk prover/server/proving-keys/direct-payment-gkr_100_1.vkbin \
  program-libs/interface/src/verifying_keys direct_payment_gkr_100_1.rs
```

The committed module matches the key generated in the cloud on 2026-09-17;
a regenerated key needs a regenerated module.

## Open

- Resident-key proof time for the checkpointed shape.
- Shapes: 100×1 only. 8 and 36 inline shapes would cost one key each.
- Notes to a different recipient (a payment rather than a merge) need the
  recipient in the data; +32 bytes per output, still fits.
- Who runs the checkpoint and how often (a forester duty fits; four
  transactions per checkpoint on the default table).
- The indexer has to serve non-inclusion witnesses at the checkpoint root,
  which means keeping the indexed tree as of `checkpoint_index` per epoch.
- The two-filter rotation that keeps filter-negative spends available during
  the rebuild window was left out; legacy spends work throughout.
- The pending table and fee model are those of 10x-admission and carry its
  open items.
