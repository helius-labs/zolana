# Batch dual CU (LiteSVM + agave batch syscalls)

Policy: ship / recommend only if full-path savings ≥ **10%**. See `docs/batching/`.

Fold-only syscall numbers: [`FOLD_CU.md`](./FOLD_CU.md) (`just bench-batch-fold-cu`).

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

## Same-vk multi — full path

| Use case | Legacy CU | Batch CU | Delta | Gate |
| --- | ---: | ---: | ---: | --- |
| BatchTransact N=2 vs 2× Transact | | | | ≥10% to recommend |
| NullifierTreeMany N=2 vs 2× single | | | | ≥10% to recommend |

Fill via a same-vk dual harness (not the removed swap twin bench).

## Fold-only highlight (same-vk Independent)

From `just bench-batch-fold-cu`:

| N | Fold syscall CU | vs N×(N=1) |
| ---: | ---: | ---: |
| 1 | 72603 | — |
| 2 | 92395 | ~36% lower than 2×1 |
| 4 | 131784 | ~55% |

Solo×2 rough IC+pairing ≈ 124674; batch N=2 = 92395; **delta ≈ 32279** (~26% on verify-only). Full-path % is lower because apply still scales with N — measure before claiming ≥10% end-to-end.
