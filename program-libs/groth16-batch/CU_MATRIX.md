# BN254 batch verify, measured CU only

Every CU and byte cell comes from a measured run (mollusk `BENCHMARK.md` or this
test's builder serialization). **No invented CU.**

Policy: recommend batch paths only if full-path CU savings ≥ **10%**.
See `docs/batching/`. Mixed-key app `*_BATCH` twins removed (no boost).

Packet limits: **1232** (today) and **4096** (SIMD-0296 size sim).

## Syscall pin

Agave pin `7090028bb` (branch helius/bn254-b1-zolana-pin). The MSM and pairing costs come from `program-runtime/src/execution_budget.rs`.

## How cells were filled

| Column | Source |
| --- | --- |
| CU (legacy app / RFQ) | Existing `just bench-*` mollusk tables |
| Bytes (forester / BatchTransact) | This test: full builder serialize |
| CU (same-vk full path) | `BATCH_CU_RESULTS.md` (`just bench-batch-dual`) |
| App mixed-key batch | removed, see `docs/batching/no-boost.md` |

## Table

| Use case | Incarnation | N | CU | Bytes legacy | Bytes v0+ALT | Limit |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| RFQ | legacy | 1 | 155148 | 959 | 964 | 1232 |
| Forester | legacy ×1 | 1 | | 474 | 448 | 1232 |
| Forester | batch many | 2 | | 672 | 646 | 1232 |
| Forester | batch many | 4 | | 1060 | 1034 | 1232 |
| Forester | batch many | 8 | | 1836 | 1810 | 4096-sim |
| Forester | batch many | 16 | | 3388 | 3362 | 4096-sim |
| Transact | legacy | 1 | 155148 | 959 | 964 | 1232 |
| BatchTransact | batch | 2 | | 741 | 715 | 1232 |
| BatchTransact | batch | 4 | | 1201 | 1175 | 1232 |
| Swap make | legacy | 2 | 258987 | 1124 | 1098 | 1232 |
| Swap take | legacy | 2 | 261268 | 1056 | 999 | 1232 |
| Swap cancel | legacy | 2 | 252641 | 871 | 814 | 1232 |
| Swap take_ve | legacy | 2 | 395782 | | | 1232 |
| Create escrow | legacy | 2 | 271556 | 1294 | 1175 | 1232 |
| Settle | legacy | 2 | 269638 | 1221 | 1071 | 1232 |
| Escrow | legacy | 2 | 257763 | 1026 | 1000 | 1232 |
| Withdraw | legacy | 2 | 252567 | 871 | 814 | 1232 |

### Builder size detail (empty pure-shielded body; relative deltas hold)

| Builder | Ix data | Accounts | Legacy tx | v0+ALT |
| --- | ---: | ---: | ---: | ---: |
| Transact | 229 | 5 | 508 | 482 |
| BatchTransact N=2 | 462 | 5 | 741 | 715 |
| BatchTransact N=4 | 922 | 5 | 1201 | 1175 |
| NullifierTree ×1 | 195 | 5 | 474 | 448 |
| NullifierTreeMany N=2 | 393 | 5 | 672 | 646 |
| NullifierTreeMany N=4 | 781 | 5 | 1060 | 1034 |
| NullifierTreeMany N=8 | 1557 | 5 | 1836 | 1810 |
| NullifierTreeMany N=16 | 3109 | 5 | 3388 | 3362 |

### Mixed-key k=2 full-path CU (twins removed; historical)

| Use case | Legacy CU | Batch CU | Delta |
| --- | ---: | ---: | ---: |
| Swap take | 269481 | 270878 | -1397 |
| Swap cancel | 260690 | 262078 | -1388 |

Regenerate: `cargo test -p zolana-groth16-batch --test matrix_measure -- --nocapture`

Docs: `docs/batching/`
