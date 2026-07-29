# BN254 proof batching

When to fold multiple Groth16 proofs into one on-chain RLC, and when not to.
All numbers come from measured runs on 2026-07-27 to 2026-07-29.

## Policy

| Rule | Meaning |
| --- | --- |
| No no-gain code | Do not ship batch paths that measure flat or worse. Record them here instead. |
| 10% gate | Recommend a batch path only when the full-path CU saving is 10% or more against the best legacy alternative. |
| Measured only | Every CU cell comes from a LiteSVM or mollusk run. No estimates. |

Raw tables:

- [`program-libs/groth16-batch/CU_MATRIX.md`](../../program-libs/groth16-batch/CU_MATRIX.md): sizes and the main table
- [`program-libs/groth16-batch/BATCH_CU_RESULTS.md`](../../program-libs/groth16-batch/BATCH_CU_RESULTS.md): full-path duals
- [`program-libs/groth16-batch/FOLD_CU.md`](../../program-libs/groth16-batch/FOLD_CU.md): fold-only syscall CU

Snapshot and interpretation: [measured.md](./measured.md).

## When batching wins

Same verifying key, two or more proofs in one instruction.

- SPP: [`BatchTransact`](./same-vk-batch.md) applies N pure-shielded transfers with one RLC.
- Forester: [`BatchUpdateNullifierTreeMany`](./same-vk-batch.md) applies N address-append proofs.

The measured full-path duals clear the 10% gate. BatchTransact N=2 saves 13.6%
and NullifierTreeMany N=2 saves 22.5% (`just bench-batch-dual`). Both paths are
recommended for same-vk N of two or more.

Operators with volume go further: the [two-phase queue](./two-phase.md)
(enqueue, verify once, apply in slices) removes the packet bound and saves a
measured 27.6% at N=8 and 30.3% at N=16 end to end, 39% to 42% on the
contended tree accounts.

## When batching does not help

Mixed-key k=2 (one app policy proof plus one SPP transfer) measures worse than a
solo verify plus a CPI. Do not build `MAKE_BATCH` or `TAKE_BATCH` style twins
for CU. Numbers: [no-boost.md](./no-boost.md).

BSB22 and committed proofs stay off the batch rail. The batch fold accepts
standard Groth16 only.

## SDK surface

- `zolana_client::plan_batch_transact` validates the entries and decides batched
  against solo by the measured transaction size. Callers never do worse than solo.
- `ZolanaClient::send_batch_transact_sync` plans and submits in one call.
- `zolana_wallet::create_batch_transfer_sync` and
  `build_batch_private_transaction_sync` give wallets batch transfers.
- `sdk-tests/batch-payout/` shows the dapp pattern: an app policy check, then a
  `BatchTransact` CPI with no app proof in the fold.

## Examples

Runnable patterns and the size rules: [examples.md](./examples.md).
