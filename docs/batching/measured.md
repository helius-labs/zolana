# Measured batch CU snapshot

Source of truth for regeneration:

- `program-libs/groth16-batch/CU_MATRIX.md` — sizes + table
- `program-libs/groth16-batch/BATCH_CU_RESULTS.md` — dual full-path + summary
- `program-libs/groth16-batch/FOLD_CU.md` — fold-only syscall CU

Commands: `just bench-batch-matrix`, `just bench-batch-fold-cu`.

## Policy gate

Recommend a path only if **full-path** savings ≥ **10%** vs legacy (same semantics). Fold-only numbers are strong evidence on the verify leg; they are not a full-path claim by themselves.

## Full-path duals

### Mixed-key k=2 (app + SPP) — **no boost** (twins removed)

| Use case | Legacy CU | Batch CU | Δ | Status |
| --- | ---: | ---: | ---: | --- |
| Swap take | 269 481 | 270 878 | −1 397 | **no boost** — do not implement |
| Swap cancel | 260 690 | 262 078 | −1 388 | **no boost** — do not implement |
| Swap make | — | — | — | blocked (circuit); would be same shape |

### Same-vk multi — full path (measured, `just bench-batch-dual`)

One transaction per leg: N solo instructions vs one batch instruction, CU read
from the VM on the SBF program with proofs.

| Use case | Legacy CU | Batch CU | Δ | Saved | Status |
| --- | ---: | ---: | ---: | ---: | --- |
| BatchTransact N=2 vs 2× Transact (1,1) | 307 296 | 265 553 | 41 743 | **13.6%** | **recommended** |
| NullifierTreeMany N=2 vs 2× single (zkp=10) | 198 110 | 153 484 | 44 626 | **22.5%** | **recommended** |

Both clear the ≥10% gate. Shape notes: transact entries use (1,1) — with
bodies a (2,3) N=2 batch already exceeds the 1232-byte packet; nullifier
updates use zkp batch 10 (`batch_address-append_40_10.key`). Larger N saves
more on the verify leg (see fold-only) but needs larger packets for size.

## Fold-only (syscall layout × agave prices)

Independent same-vk, 1 public input (`just bench-batch-fold-cu`):

| N | Fold CU | vs N×(N=1) |
| ---: | ---: | ---: |
| 1 | 72 603 | — |
| 2 | 92 395 | ~36% lower than 2×1 |
| 4 | 131 784 | ~55% |
| 8 | 207 730 | ~64% |
| 16 | 358 107 | ~69% |

Solo×2 rough IC+pairing ≈ 124 674; batch N=2 = 92 395; **delta ≈ 32 279** (~26% on verify-only). Apply still scales with N, so full-path % is lower than fold-only.

## Packet sizes (builders)

See `CU_MATRIX.md` for full table. Highlights:

| Builder | Legacy tx | v0+ALT | Limit |
| --- | ---: | ---: | --- |
| BatchTransact N=2 | 741 | 715 | 1232 |
| BatchTransact N=4 | 1201 | 1175 | 1232 |
| NullifierTreeMany N=4 | 1060 | 1034 | 1232 |
| NullifierTreeMany N=8 | 1836 | 1810 | 4096-sim |
