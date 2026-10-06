# Shielded Pool -- CU Benchmark

Compute unit profiling for feasible shielded-pool instruction families, replayed under mollusk from litesvm-built account state: protocol creation, tree pause, proof-free SOL/SPL shields, Groth16-proven EdDSA transact shapes covering the narrowest and widest shape of every output count (up to the 1x16 split shape and the 49x2 widest input shape), the 49x2 shape on both `ring_transact` rails (EdDSA, and P256 whose BSB22 commitment adds a Pedersen proof-of-knowledge pairing to verification), every supported `merge_transact` shape, compact padding on the 2x4 and 49x2 transact shapes and every merge shape, and SOL/SPL withdrawals. This target is a pure benchmark: no CI workflow runs the profiling build, so no CU ceilings are enforced here -- a ceiling that never runs would be unfalsifiable. Regression ceilings live in the fast cross_cutting_cu_budget suite, which pins every proofless instruction family per operation.

Regenerate with `just bench-shielded-pool`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Create protocol config](#create-protocol-config)
2. [Deposit sol](#deposit-sol)
3. [Deposit sol batch 3](#deposit-sol-batch-3)
4. [Deposit spl](#deposit-spl)
5. [Merge 24x1](#merge-24x1)
6. [Merge 24x1 compact 9 sent](#merge-24x1-compact-9-sent)
7. [Merge 54x1](#merge-54x1)
8. [Merge 54x1 compact 25 sent](#merge-54x1-compact-25-sent)
9. [Merge 8x1](#merge-8x1)
10. [Merge 8x1 compact 1 sent](#merge-8x1-compact-1-sent)
11. [Pause tree](#pause-tree)
12. [Transfer eddsa 16x8](#transfer-eddsa-16x8)
13. [Transfer eddsa 1x16](#transfer-eddsa-1x16)
14. [Transfer eddsa 1x2](#transfer-eddsa-1x2)
15. [Transfer eddsa 1x8](#transfer-eddsa-1x8)
16. [Transfer eddsa 24x4](#transfer-eddsa-24x4)
17. [Transfer eddsa 2x2](#transfer-eddsa-2x2)
18. [Transfer eddsa 2x4](#transfer-eddsa-2x4)
19. [Transfer eddsa 2x4 compact](#transfer-eddsa-2x4-compact)
20. [Transfer eddsa 49x2](#transfer-eddsa-49x2)
21. [Transfer eddsa 49x2 compact](#transfer-eddsa-49x2-compact)
22. [Transfer eddsa 4x4](#transfer-eddsa-4x4)
23. [Transfer eddsa 5x4](#transfer-eddsa-5x4)
24. [Transfer eddsa 8x16](#transfer-eddsa-8x16)
25. [Transfer eddsa cached 1 of 32x2](#transfer-eddsa-cached-1-of-32x2)
26. [Transfer eddsa cached 32x2](#transfer-eddsa-cached-32x2)
27. [Transfer eddsa cached 5x4](#transfer-eddsa-cached-5x4)
28. [Transfer ring eddsa 49x2](#transfer-ring-eddsa-49x2)
29. [Transfer ring p256 49x2](#transfer-ring-p256-49x2)
30. [Withdrawal sol](#withdrawal-sol)
31. [Withdrawal spl](#withdrawal-spl)

## 1. Create protocol config

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |      4,525 |      4,525 |

## 2. Deposit sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     37,849 |     36,647 |
| `process_instruction`         |     37,900 |          0 |

## 3. Deposit sol batch 3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     49,561 |     48,359 |
| `process_instruction`         |     49,612 |          0 |

## 4. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl_deposit`          |      1,303 |      1,303 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     39,683 |     38,348 |
| `process_instruction`         |     39,734 |          0 |

## 5. Merge 24x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     49,448 |     49,448 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    197,764 |     68,780 |

## 6. Merge 24x1 compact 9 sent

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     20,772 |     20,772 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    152,403 |     52,095 |

## 7. Merge 54x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |    111,108 |    111,108 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    296,879 |    106,235 |

## 8. Merge 54x1 compact 25 sent

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     48,284 |     48,284 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    200,535 |     72,715 |

## 9. Merge 8x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     16,474 |     16,474 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    146,044 |     50,034 |

## 10. Merge 8x1 compact 1 sent

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |      1,957 |      1,957 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    124,107 |     42,614 |

## 11. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        254 |        254 |

## 12. Transfer eddsa 16x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |        579 |        579 |
| `create_nullifier_pdas`       |     30,753 |     30,753 |
| `apply_input_trees`           |     43,111 |     12,358 |
| `apply_output_tree`           |     31,971 |     31,971 |
| `public_input_hash`           |     34,747 |     34,747 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    198,032 |          0 |
| `process_instruction`         |    198,084 |          0 |

## 13. Transfer eddsa 1x16

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |      1,123 |      1,123 |
| `create_nullifier_pdas`       |      1,975 |      1,975 |
| `apply_input_trees`           |      3,138 |      1,163 |
| `apply_output_tree`           |     38,361 |     38,361 |
| `public_input_hash`           |     33,198 |     33,198 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    163,543 |      5,276 |
| `process_instruction`         |    163,595 |          0 |

## 14. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |        171 |        171 |
| `create_nullifier_pdas`       |      1,975 |      1,975 |
| `apply_input_trees`           |      3,138 |      1,163 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     20,014 |     20,014 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    136,612 |      2,576 |
| `process_instruction`         |    136,664 |          0 |

## 15. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |        579 |        579 |
| `create_nullifier_pdas`       |      1,975 |      1,975 |
| `apply_input_trees`           |      3,138 |      1,163 |
| `apply_output_tree`           |     31,971 |     31,971 |
| `public_input_hash`           |     26,566 |     26,566 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    148,429 |      3,728 |
| `process_instruction`         |    148,481 |          0 |

## 16. Transfer eddsa 24x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |        307 |        307 |
| `create_nullifier_pdas`       |     47,856 |     47,856 |
| `apply_input_trees`           |     65,107 |     17,251 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     33,159 |     33,159 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    215,354 |          0 |
| `process_instruction`         |    215,406 |          0 |

## 17. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |        171 |        171 |
| `create_nullifier_pdas`       |      3,747 |      3,747 |
| `apply_input_trees`           |      5,117 |      1,370 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     21,616 |     21,616 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    140,295 |        906 |
| `process_instruction`         |    140,347 |          0 |

## 18. Transfer eddsa 2x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |        307 |        307 |
| `create_nullifier_pdas`       |      3,747 |      3,747 |
| `apply_input_trees`           |      5,117 |      1,370 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     21,696 |     21,696 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    141,841 |      1,291 |
| `process_instruction`         |    141,893 |          0 |

## 19. Transfer eddsa 2x4 compact

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |        103 |        103 |
| `create_nullifier_pdas`       |      1,975 |      1,975 |
| `apply_input_trees`           |      3,138 |      1,163 |
| `apply_output_tree`           |     28,230 |     28,230 |
| `public_input_hash`           |     21,810 |     21,810 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    138,125 |      2,397 |
| `process_instruction`         |    138,177 |          0 |

## 20. Transfer eddsa 49x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |        171 |        171 |
| `create_nullifier_pdas`       |     98,347 |     98,347 |
| `apply_input_trees`           |    135,334 |     36,987 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     46,180 |     46,180 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    299,382 |          0 |
| `process_instruction`         |    299,434 |          0 |

## 21. Transfer eddsa 49x2 compact

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |        103 |        103 |
| `create_nullifier_pdas`       |      1,975 |      1,975 |
| `apply_input_trees`           |      3,138 |      1,163 |
| `apply_output_tree`           |     28,230 |     28,230 |
| `public_input_hash`           |     22,566 |     22,566 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    138,956 |      2,472 |
| `process_instruction`         |    139,008 |          0 |

## 22. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |        307 |        307 |
| `create_nullifier_pdas`       |      7,661 |      7,661 |
| `apply_input_trees`           |     11,063 |      3,402 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     21,735 |     21,735 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    148,027 |          0 |
| `process_instruction`         |    148,079 |          0 |

## 23. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |        307 |        307 |
| `create_nullifier_pdas`       |      9,433 |      9,433 |
| `apply_input_trees`           |     13,042 |      3,609 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     23,331 |     23,331 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    151,708 |          0 |
| `process_instruction`         |    151,760 |          0 |

## 24. Transfer eddsa 8x16

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |      1,123 |      1,123 |
| `create_nullifier_pdas`       |     14,749 |     14,749 |
| `apply_input_trees`           |     20,597 |      5,848 |
| `apply_output_tree`           |     38,361 |     38,361 |
| `public_input_hash`           |     38,070 |     38,070 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    186,598 |          0 |
| `process_instruction`         |    186,650 |          0 |

## 25. Transfer eddsa cached 1 of 32x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |        171 |        171 |
| `create_nullifier_pdas`       |     66,025 |     66,025 |
| `apply_input_trees`           |     89,633 |     23,608 |
| `assign_cached_inputs`        |      2,937 |      2,937 |
| `bind_cached_inputs`          |      2,957 |         20 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     37,887 |     37,887 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    247,326 |          0 |
| `process_instruction`         |    247,378 |          0 |

## 26. Transfer eddsa cached 32x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |        171 |        171 |
| `create_nullifier_pdas`       |     65,340 |     65,340 |
| `apply_input_trees`           |     88,948 |     23,608 |
| `assign_cached_inputs`        |     19,023 |     19,023 |
| `bind_cached_inputs`          |     19,043 |         20 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     37,887 |     37,887 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    262,727 |          0 |
| `process_instruction`         |    262,779 |          0 |

## 27. Transfer eddsa cached 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |        307 |        307 |
| `create_nullifier_pdas`       |     10,891 |     10,891 |
| `apply_input_trees`           |     14,348 |      3,457 |
| `assign_cached_inputs`        |      4,038 |      4,038 |
| `bind_cached_inputs`          |      4,058 |         20 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     23,252 |     23,252 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    157,505 |          0 |
| `process_instruction`         |    157,557 |          0 |

## 28. Transfer ring eddsa 49x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |         47 |         47 |
| `create_nullifier_pdas`       |     98,717 |     98,717 |
| `apply_input_trees`           |    135,704 |     36,987 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     44,665 |     44,665 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    300,084 |          0 |
| `process_instruction`         |    300,136 |          0 |

## 29. Transfer ring p256 49x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |         47 |         47 |
| `create_nullifier_pdas`       |     98,347 |     98,347 |
| `apply_input_trees`           |    135,334 |     36,987 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     48,273 |     48,273 |
| `verify_groth16`              |    137,140 |    137,140 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    361,018 |          0 |
| `process_instruction`         |    361,070 |          0 |

## 30. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |        171 |        171 |
| `create_nullifier_pdas`       |      4,835 |      4,835 |
| `apply_input_trees`           |      6,205 |      1,370 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     22,876 |     22,876 |
| `verify_groth16`              |     79,504 |     79,504 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    145,121 |        238 |
| `process_instruction`         |    145,173 |          0 |

## 31. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        936 |        936 |
| `fill_output_owner_pk_hashes` |        171 |        171 |
| `create_nullifier_pdas`       |      4,117 |      4,117 |
| `apply_input_trees`           |      5,487 |      1,370 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     22,878 |     22,878 |
| `verify_groth16`              |     79,504 |     79,504 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    146,046 |      2,576 |
| `process_instruction`         |    146,098 |          0 |

