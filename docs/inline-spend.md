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

- Circuit shape `direct-payment-admitted` 100 inputs × 1 output:
  1,091,546 constraints (144×2 is 1,232,023). Key
  `direct-payment-admitted_100_1.key`, 389 MB; verifying key module
  `direct_payment_admitted_100_1`.
- Instruction `inline_spend` (tag 28). Data `InlineSpend`: nullifiers,
  state root index, value commitment, expiry slot, max forester fee, one
  output (`OutputUtxo`), tx viewing key, salt, proof, commitment. The input
  tree, output tree and state root value come from the accounts; every
  output is paid to the owner. 3,627 bytes at 100 inputs.
- Accounts: owner (signer, pays), input tree, output tree, pending
  nullifiers, nullifier filter, system program, this program. Seven
  addresses.
- The program expands `InlineSpend` into the same `Payment` the buffer path
  uses (`InlineSpend::payment`), with `INLINE_BINDING` (zero) in place of the
  buffer address in the intent and the certificate id, then runs the shared
  note verification and settlement (`direct_spend/commit.rs`: `NotesProof`,
  `Spend::settle`, `emit_events`). Nothing else in the admission path changes.
- SDK: `direct::inline_spend(payment, owner, proof)` builds the data;
  `admitted_payment` accepts `(inputs, outputs)` from
  `ADMITTED_PAYMENT_SHAPES`; `balance` takes one or two outputs.

## Size

`InlineSpend` for 100 inputs is 3,627 bytes. The v1 envelope (one signature,
seven addresses, two compute-budget instructions) adds about 360, so the
transaction is about 3,990 of 4,096 bytes. `transaction_size` in the SDK
measures it; the proof test asserts it fits.

## Soundness

Same statement and checks as the buffer-based admitted payment: certificate
over the state root, admitted freshness (filter negative for every
nullifier, exact pending duplicate check), balance, intent binding. The
inline variant only changes where the bytes come from. The buffer used to
give replay protection through `mark_spent`; inline replay fails on the
pending table (`NullifierAlreadySpent`) exactly like a second commit of the
same notes would.

## Tests

```
cd prover/server && go test ./circuits/direct_spend -run TestAdmittedInlinePayment -v
ADMITTED_PAYMENT_COUNTS=1 go test ./circuits/direct_spend -run 'TestAdmittedPaymentConstraints/100x1' -v

cargo test -p zolana-interface --all-features direct_spend
cargo test -p zolana-client --lib direct_spend
ZOLANA_PROVER_URL=http://127.0.0.1:3001 cargo test -p shielded-pool-tests --test direct_spend_proofs \
  inline_spend_settles_100_notes_in_one_transaction -- --ignored --nocapture
```

The proof test needs a prover serving `direct-payment-admitted_100_1.key`
and prints proof time, transaction bytes and addresses, and compute units.

Key generation:

```
cd prover/server && go build -o light-prover . && ./light-prover setup-direct-spend \
  --circuit direct-payment-admitted --n-inputs 100 --n-outputs 1 \
  --output proving-keys/direct-payment-admitted_100_1.key \
  --output-vkey proving-keys/direct-payment-admitted_100_1.vkbin
cargo run -p xtask -- bsb22-vk prover/server/proving-keys/direct-payment-admitted_100_1.vkbin \
  program-libs/interface/src/verifying_keys direct_payment_admitted_100_1.rs
```

The committed module matches the key generated in the cloud on 2026-09-17;
a regenerated key needs a regenerated module.

## Open

- Measured proof time and CU: see the test output.
- Shapes: 100×1 only. 8 and 36 inline shapes would cost one key each.
- Notes to a different recipient (a payment rather than a merge) need the
  recipient in the data; +32 bytes per output, still fits.
- The filter, pending table and fee model are those of 10x-admission and
  carry its open items.
