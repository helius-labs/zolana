# Batch dual CU (LiteSVM + agave batch syscalls)

Policy: ship / recommend only if full-path savings ≥ **10%**. See `docs/batching/`.

Fold-only syscall numbers: [`FOLD_CU.md`](./FOLD_CU.md) (`just bench-batch-fold-cu`).

## Same-vk multi — full path (measured)

One transaction per leg: N solo instructions vs one batch instruction, CU
read from the VM. Transact entries use the (1,1) confidential eddsa shape
(N=2 with complete bodies fits 1232; (2,3) does not). Nullifier updates use
zkp batch 10 (`batch_address-append_40_10.key`).

| Use case | Legacy CU | Batch CU | Delta | Saved | Gate |
| --- | ---: | ---: | ---: | ---: | --- |
| BatchTransact N=2 vs 2x Transact (1,1) | 307296 | 265553 | 41743 | 13.6% | **recommend** (≥10%) |
| NullifierTreeMany N=2 vs 2x single (zkp=10) | 198110 | 153484 | 44626 | 22.5% | **recommend** (≥10%) |

Regenerate: `just bench-batch-dual`.

## Mixed-key k=2 app + SPP — no boost (twins removed)

Measured under the experimental `*_BATCH` twins (since deleted). Kept so nobody
re-implements the same shape for CU.

| Use case | Legacy CU | Batch CU | Delta |
| --- | ---: | ---: | ---: |
| Swap take | 269481 | 270878 | -1397 |
| Swap cancel | 260690 | 262078 | -1388 |
| Swap make | n/a | n/a | PDA-owned `data_hash` output rejected by SPP circuit |

Batch mixed-key k=2 is slightly higher than legacy: solo app verify is cheap
relative to SPP, and the RLC still pays n+3k pairing structure.
