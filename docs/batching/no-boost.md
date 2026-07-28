# No-boost cases (do not implement for CU)

These patterns look like natural batching targets but **do not save compute**. They were measured under LiteSVM with agave BN254 batch syscalls (`just bench-batch-cu` on the experimental twins, since removed).

## Mixed-key k=2: app proof + SPP transfer

One foreign (app) verifying key and one SPP transfer VK in a single RLC (the removed `ComposeTransact` hub or an app `*_BATCH` twin that CPI’d it).

| Use case | Legacy CU | Batch CU | Δ |
| --- | ---: | ---: | ---: |
| Swap take | 269 481 | 270 878 | **−1 397** (~0.5% worse) |
| Swap cancel | 260 690 | 262 078 | **−1 388** (~0.5% worse) |
| Swap make | n/a | n/a | PDA `data_hash` / owner-sign rejected by SPP circuit on the experimental path |

### Why it loses

- RLC cost scales roughly as **n + 3k** pairings (`k` = number of distinct VKs).
- For **k=2**, the fixed multi-VK structure does not beat two solo verifies when one proof (the app circuit) is cheap next to SPP.
- You still pay decompress / transcript / fold setup; the cheap leg does not amortize.

### Product implication

| Path | Keep? |
| --- | --- |
| Legacy make / take / cancel (solo app verify + SPP CPI) | **Yes** — correct product path |
| `MAKE_BATCH` / `TAKE_BATCH` / `CANCEL_BATCH` | **No** — removed; no CU win |
| dynamic-swap `CREATE_ESCROW_BATCH` / `SETTLE_BATCH` | **No** — same mixed-key shape |
| timelock-escrow `ESCROW_BATCH` / `WITHDRAW_BATCH` | **No** — same mixed-key shape |
| SPP `ComposeTransact` | **No** — removed (tag 54 freed): unvalidated foreign-vk account surface, zero callers after the twin prune, and no CU win. Single-tx atomicity across proof systems needs its own design if ever wanted. |

Do not re-add app batch twins “for future CU” without a **new** full-path dual that clears the **≥10%** bar.

## Make experimental path (blocked)

The make twin also hit a **circuit constraint**: PDA-owned outputs with non-zero `data_hash` are rejected by the current SPP transfer circuit (owner must sign). That is independent of fold math; fixing it is a circuit/product change, not a batching win.

## BSB22 / take_ve

Batch fold on this branch is **standard Groth16 only** (no Pedersen / proof commitment). Verifiable-encryption take (`take_ve`) stays on the solo BSB22 rail. There is no batch twin and none planned on this rail.

## What to do instead

- **User txs with one app + one SPP proof:** keep solo verify + CPI (legacy).
- **Many same-shape SPP transfers:** [`BatchTransact`](./same-vk-batch.md).
- **Many same-vk forester proofs:** [`BatchUpdateNullifierTreeMany`](./same-vk-batch.md).
- **Operator N ≫ 4 same-vk:** design note in [proof-batching-programming-models.md](../alt-designs/proof-batching-programming-models.md) (two-phase enqueue/execute) — not implemented as app `*_BATCH` tags.
