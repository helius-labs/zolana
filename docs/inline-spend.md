# Inline spend: 100 notes in one transaction

Branch `experiment/merge/wide-merge`, forked from `experiment/merge/10x-admission`.

## Why

Merging 100 notes takes three sequential 36-input merges on PR #320 and a
buffer upload plus a commit on 10x-admission. One transaction needs three
things at once:

1. No per-note account. Transaction v1 allows 64 addresses; the compact
   pending-nullifier table of 10x-admission already replaces the nullifier
   PDAs.
2. The statement in instruction data. 100 nullifiers are 3,200 bytes; the
   rest of the statement, the proof and the BSB22 commitment have to fit in
   the remaining ~900 bytes of a 4,096-byte transaction.
3. One proof the owner can produce, covering membership, ownership, balance
   and non-inclusion.

## What was added

- Two shapes of the existing GKR payment circuit (membership, ownership,
  balance, non-inclusion at a nullifier root), `INLINE_SHAPES`:
  100 inputs × 1 output for merging (1,432,787 constraints, key 455 MB) and
  64 × 2 for paying (1,301,843 constraints, key 429 MB), so a wallet pays
  straight from 64 small notes with a recipient output and change, each
  output carrying an encrypted note. Verifying key modules
  `direct_payment_gkr_100_1` and `direct_payment_gkr_64_2`.
- Instruction `inline_spend` (tag 28). Data `InlineSpend`: shape capacity,
  nullifiers, state root index, nullifier root index, value commitment,
  expiry slot, max forester fee, outputs (recipient + `OutputUtxo`), tx
  viewing key, salt, proof, commitment. The input tree, output tree and both
  root values come from the accounts. 3,667 bytes at 100×1 with an empty
  output; 64×2 with two 500-byte ciphertexts is about 3,600.
- Accounts: owner (signer, pays), input tree, output tree, pending
  nullifiers, [nullifier filter if the tree has one], system program, this
  program. Six or seven addresses. The tree must be in compact
  pending-nullifier mode.
- The program expands `InlineSpend` into the same `Payment` the buffer path
  verifies (`InlineSpend::payment`), with `INLINE_BINDING` (zero) in place of
  the buffer address in the intent and the certificate id, then runs the
  shared note verification and settlement (`direct_spend/commit.rs`:
  `NotesProof`, `Spend::settle`, `emit_events`). Admission is
  `ExactProof`: the proof covers history at a root in the last hundred, the
  pending table covers the window since. A historical filter, if present,
  is recorded into but never relied on. The padded nullifier chain is hashed
  once on chain and shared by the certificate and freshness fields.
- SDK: `direct::inline_spend(payment, capacity, proof)` builds the data;
  `payment(..).with_gkr()` accepts `(inputs, outputs)` from
  `GKR_PAYMENT_SHAPES`; `balance` takes one or two outputs.

## Why not the admission filter

An earlier iteration of this branch used the `direct-payment-admitted` shape
(no non-inclusion in the proof, 1,091,546 constraints) with the historical
Bloom filter as the spentness guard, then added a checkpoint so the filter
could be cleared instead of forcing a tree rotation. Clearing required
non-inclusion back inside the proof, at which point the filter's only job
was "spends since the checkpoint", which the pending table already answers
exactly. The filter added a false-positive rate, a 4 MiB account (~29 SOL),
a permissionless rebuild instruction and an epoch cadence, and no soundness.
It was reverted; the pending table plus proof non-inclusion is the whole
design. What the checkpoint bought — a non-inclusion root that stays valid
for a long time so witnesses do not go stale — is available more cheaply as
anchor roots the forester pins in root history, if it turns out to matter.

## Measured

LiteSVM proof tests, M5 Pro, 2026-09-17, 100 real notes spent into one
output in one transaction:

| | admitted shape (earlier) | this shape |
|---|---|---|
| transaction | 3,981 B, 7 addresses | ~4,020 B, 6 addresses (7 with a filter) |
| compute units | 464,141 | see test output |
| constraints | 1,091,546 | 1,432,787 |
| proof, cold key | 5.97 s | 8.64 s |
| proof, resident key, 20 inputs | — | 2.2–3.8 s |

For comparison on the same machine: PR #320 needs three sequential 36-input
merges (about 240k CU each, three proofs of 781k constraints); the
10x-admission buffer path needs the buffer allocation, the chunk uploads and
the commit.

## Soundness

Identical to the buffer-based GKR payment: certificate over the state root,
non-inclusion at a nullifier root in history, balance, intent binding, exact
pending duplicate check. The inline variant only changes where the bytes
come from. Replay protection no longer comes from a buffer's `mark_spent`:
an inline replay fails on the pending table (`NullifierAlreadySpent`)
exactly like a second commit of the same notes.

## Tests

```
cd prover/server && go test ./circuits/direct_spend -run TestInlineGKRPayment -v

cargo test -p zolana-interface --all-features direct_spend
cargo test -p zolana-client --lib direct_spend
ZOLANA_PROVER_URL=http://127.0.0.1:3001 cargo test -p shielded-pool-tests --features proofs \
  --test direct_spend_proofs inline_spend -- --ignored --nocapture
```

The proof tests need a prover serving `direct-payment-gkr_100_1.key` and
print proof time, transaction bytes and addresses, and compute units: the
100×1 merge without and with a historical filter on the tree, and the 64×2
payment with two 500-byte encrypted outputs.

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

- Compute units and resident-key proof time at 100 inputs for this shape.
- Smaller inline shapes (8, 36) cost one key each; the GKR fixed cost makes
  them no faster to prove than 64.
- Poseidon2 for the tree hashes (circuit-only, roughly halves the membership
  and non-inclusion constraints) and sibling sharing for scattered notes are
  the next prover-side steps; both need fresh trees or a circuit change only.
- Pending-table capacity ties spend liveness to forester progress; anchor
  roots plus a larger table are the mitigation if it matters.
- The pending table and fee model are those of 10x-admission and carry its
  open items.
