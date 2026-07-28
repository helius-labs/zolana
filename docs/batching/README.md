# BN254 proof batching

When to fold multiple Groth16 proofs into one on-chain RLC, and when not to.

## Policy

| Rule | Meaning |
| --- | --- |
| **No no-gain code** | Do not ship product batch twins that measure flat or worse. Document them here. |
| **≥10% CU only** | Recommend a batch path only when full-path CU saves **≥10%** vs the best legacy alternative (same semantics). |
| **Measured only** | Every CU cell comes from a LiteSVM/mollusk run. No estimates. |

Raw tables live in:

- [`program-libs/groth16-batch/CU_MATRIX.md`](../../program-libs/groth16-batch/CU_MATRIX.md) — sizes + main table
- [`program-libs/groth16-batch/BATCH_CU_RESULTS.md`](../../program-libs/groth16-batch/BATCH_CU_RESULTS.md) — dual full-path + summary
- [`program-libs/groth16-batch/FOLD_CU.md`](../../program-libs/groth16-batch/FOLD_CU.md) — fold-only syscall CU

Snapshot and interpretation: [measured.md](./measured.md).

## When batching wins

**Same verifying key, N ≥ 2 proofs in one instruction.**

- SPP: [`BatchTransact`](./same-vk-batch.md) — N pure-shielded transfers, one RLC
- Forester: [`BatchUpdateNullifierTreeMany`](./same-vk-batch.md) — N address-append proofs

Fold amortization (syscall layout, Independent same-vk) already shows large savings at N=2+; full-path promotion still requires a measured ≥10% dual run (see same-vk guide).

## When batching does not help

**Mixed-key k=2 (app policy proof + SPP transfer)** — measured slightly *worse* than solo verify + CPI. Do not build `MAKE_BATCH` / `TAKE_BATCH`-style twins for CU.

Details and numbers: [no-boost.md](./no-boost.md).

**BSB22 / committed proofs** — not on the batch rail (standard Groth16 only).

## Examples

Copy-paste oriented patterns: [examples.md](./examples.md).

## Related design notes

Longer product/operator framing (Model A vs Model B, two-phase queues):  
[`docs/alt-designs/proof-batching-programming-models.md`](../alt-designs/proof-batching-programming-models.md). That doc’s Model B is **future** operator design; it is not an excuse to re-add mixed-key app twins.
