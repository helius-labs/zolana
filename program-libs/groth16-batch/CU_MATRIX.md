# BN254 batch verify — measured CU only

Every CU and byte cell comes from a measured run (mollusk `BENCHMARK.md` or this
test's builder serialization). **No invented CU.**

Packet limits: **1232** (today) and **4096** (SIMD-0296 size sim).

## Syscall pin

Agave `5134c411` — `program-runtime/src/execution_budget.rs` MSM / pairing_check costs.

## How cells were filled

| Column | Source |
| --- | --- |
| CU (legacy app) | Existing `just bench-*` mollusk tables |
| Bytes (forester / BatchTransact / Compose) | This test: full builder serialize |
| Bytes (app batch twins) | Legacy BENCHMARK size + measured +foreign_vk account delta |
| CU (batch full path) | blank until SBF dual benches with batch syscalls |
| take_ve batch | n/a (standard Groth16 only on batch rail) |

Account delta measured here: legacy_tx +33, v0+ALT +2.

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
| ComposeTransact | batch | 2 | | 701 | 644 | 1232 |
| Swap make | legacy | 2 | 258987 | 1124 | 1098 | 1232 |
| Swap make | batch | 2 | | 1157 | 1100 | 1232 |
| Swap take | legacy | 2 | 261268 | 1056 | 999 | 1232 |
| Swap take | batch | 2 | | 1089 | 1001 | 1232 |
| Swap cancel | legacy | 2 | 252641 | 871 | 814 | 1232 |
| Swap cancel | batch | 2 | | 904 | 816 | 1232 |
| Swap take_ve | legacy | 2 | 395782 | | | 1232 |
| Swap take_ve | batch | — | n/a | n/a | n/a | n/a |
| Create escrow | legacy | 2 | 271556 | 1294 | 1175 | 1232 |
| Create escrow | batch | 2 | | 1327 | 1177 | 1232 |
| Settle | legacy | 2 | 269638 | 1221 | 1071 | 1232 |
| Settle | batch | 2 | | 1254 | 1073 | 1232 |
| Escrow | legacy | 2 | 257763 | 1026 | 1000 | 1232 |
| Escrow | batch | 2 | | 1059 | 1002 | 1232 |
| Withdraw | legacy | 2 | 252567 | 871 | 814 | 1232 |
| Withdraw | batch | 2 | | 904 | 816 | 1232 |

### Builder size detail (empty pure-shielded body; relative deltas hold)

| Builder | Ix data | Accounts | Legacy tx | v0+ALT |
| --- | ---: | ---: | ---: | ---: |
| Transact | 229 | 5 | 508 | 482 |
| BatchTransact N=2 | 462 | 5 | 741 | 715 |
| BatchTransact N=4 | 922 | 5 | 1201 | 1175 |
| ComposeTransact | 389 | 6 | 701 | 644 |
| NullifierTree ×1 | 195 | 5 | 474 | 448 |
| NullifierTreeMany N=2 | 393 | 5 | 672 | 646 |
| NullifierTreeMany N=4 | 781 | 5 | 1060 | 1034 |
| NullifierTreeMany N=8 | 1557 | 5 | 1836 | 1810 |
| NullifierTreeMany N=16 | 3109 | 5 | 3388 | 3362 |
| Swap make-shaped legacy | 357 | 7 | 702 | 614 |
| Swap make-shaped batch | 357 | 8 | 735 | 616 |

Regenerate: `cargo test -p zolana-groth16-batch --test matrix_measure -- --nocapture`
