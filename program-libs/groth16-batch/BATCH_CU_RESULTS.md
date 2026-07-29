# Batch dual CU (LiteSVM + agave batch syscalls)

Policy: ship / recommend only if full-path savings ≥ **10%**. See `docs/batching/`.

Fold-only syscall numbers: [`FOLD_CU.md`](./FOLD_CU.md) (`just bench-batch-fold-cu`).

## Same-vk multi, full path (measured)

One transaction per leg: N solo instructions vs one batch instruction, CU
read from the VM. Wallet-shaped entries use the (2,3) circuit with
synthetic ciphertexts sized to the measured 773-byte wallet entry.
Nullifier updates use zkp batch 10 (`batch_address-append_40_10.key`).

Batch CU moves a few units between runs because proof bytes are
random. Treat deltas under 100 CU as the same measurement.

Rows whose batch transaction exceeds 1232 bytes are a 4096 size
simulation: the CU is measured, the packet does not exist yet.

| Use case | Legacy CU | Batch CU | Delta | Saved | Batch tx bytes | Packet | Gate |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| BatchTransact N=2 vs 2x Transact, (1,1) compact | 307602 | 265827 | 41775 | 13.6% | 947 | 1232 | **recommend** (≥10%) |
| BatchTransact N=2 vs 2x Transact, (2,3) wallet shaped | 336537 | 295004 | 41533 | 12.3% | 1837 | 4096 size simulation | **recommend** (≥10%) |
| BatchTransact N=4 vs 4x Transact, (2,3) wallet shaped | 674651 | 528452 | 146199 | 21.7% | 3393 | 4096 size simulation | **recommend** (≥10%) |
| NullifierTreeMany N=2 vs 2x single, zkp batch 10 | 198126 | 153499 | 44627 | 22.5% | n/a | 1232 | **recommend** (≥10%) |
| Two-phase N=8 vs 8x Transact, total with enqueues | 1233588 | 892955 | 340633 | 27.6% | n/a | 1232 | **recommend** (≥10%) |
| Two-phase N=8, hot path (execute plus applies) | 1233588 | 750369 | 483219 | 39.2% | n/a | 1232 | **recommend** (≥10%) |
| Two-phase N=16 vs 16x Transact, total with enqueues | 2468036 | 1720717 | 747319 | 30.3% | n/a | 1232 | **recommend** (≥10%) |
| Two-phase N=16, hot path (execute plus applies) | 2468036 | 1436520 | 1031516 | 41.8% | n/a | 1232 | **recommend** (≥10%) |

Regenerate: `just bench-batch-dual`.

## Mixed-key k=2 app plus SPP, no boost (twins removed)

Measured under the experimental `*_BATCH` twins (since deleted). Kept so nobody
re-implements the same shape for CU.

| Use case | Legacy CU | Batch CU | Delta |
| --- | ---: | ---: | ---: |
| Swap take | 269481 | 270878 | -1397 |
| Swap cancel | 260690 | 262078 | -1388 |
| Swap make | n/a | n/a | PDA-owned `data_hash` output rejected by SPP circuit |

Batch mixed-key k=2 is slightly higher than legacy: solo app verify is cheap
relative to SPP, and the RLC still pays n+3k pairing structure.
