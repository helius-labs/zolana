# No-boost cases

These patterns look like natural batching targets but do not save compute. The
numbers come from full-path duals under LiteSVM with the agave BN254 batch
syscalls, measured on 2026-07-27.

## Mixed-key k=2: app proof plus SPP transfer

One foreign (app) verifying key and one SPP transfer key in a single RLC.

| Use case | Legacy CU | Batch CU | Delta |
| --- | ---: | ---: | ---: |
| Swap take | 269481 | 270878 | -1397 (about 0.5% worse) |
| Swap cancel | 260690 | 262078 | -1388 (about 0.5% worse) |
| Swap make | n/a | n/a | The SPP transfer circuit rejects a PDA-owned `data_hash` output without an owner signature. |

### Why it loses

The RLC cost scales with n+3k pairings, where k is the number of distinct
verifying keys. For k=2 the multi-key structure does not beat two solo
verifies, because the app proof is cheap next to SPP. The decompress and
transcript setup does not amortize on the cheap leg.

### Product record

| Path | Status |
| --- | --- |
| Legacy make, take, and cancel (solo app verify plus SPP CPI) | The correct product path. |
| Swap, dynamic-swap, and escrow `*_BATCH` twins | Removed. No CU gain. |
| SPP `ComposeTransact` | Removed. It read an unvalidated foreign key account, nothing called it, and the mixed-key shape loses CU. Tag 54 is free. |

Do not add app batch twins again without a new full-path dual that clears the
10% gate.

## BSB22 and take_ve

The batch fold accepts standard Groth16 only. Verifiable-encryption take
(`take_ve`) stays on the solo BSB22 rail.

## What to do instead

- One app proof plus one SPP proof in a user transaction: keep the solo verify
  plus a CPI.
- Many same-shape SPP transfers: [`BatchTransact`](./same-vk-batch.md).
- Many same-vk forester proofs: [`BatchUpdateNullifierTreeMany`](./same-vk-batch.md).
- App policy in front of a batch: CPI `BatchTransact` from the app program with
  no app proof in the fold. Example: `sdk-tests/batch-payout/`.
