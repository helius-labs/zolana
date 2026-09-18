# Shielded Pool -- CU Benchmark

Compute unit profiling for feasible shielded-pool instruction families, replayed under mollusk from litesvm-built account state: protocol creation, tree pause, proof-free SOL/SPL shields, all eleven Groth16-proven EdDSA transact shapes (including the 1x8 split shape and the 36x2 consolidation shape), the 36x2 consolidation shape on both `ring_transact` rails (EdDSA, and P256 whose BSB22 commitment adds a Pedersen proof-of-knowledge pairing to verification), both supported `merge_transact` shapes, and SOL/SPL withdrawals. This target is a pure benchmark: no CI workflow runs the profiling build, so no CU ceilings are enforced here -- a ceiling that never runs would be unfalsifiable. Regression ceilings live in the fast cross_cutting_cu_budget suite, which pins every proofless instruction family per operation.

Regenerate with `just bench-shielded-pool`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Create protocol config](#create-protocol-config)
2. [Deposit sol](#deposit-sol)
3. [Deposit sol batch 3](#deposit-sol-batch-3)
4. [Deposit spl](#deposit-spl)
5. [Merge 36x1](#merge-36x1)
6. [Merge 8x1](#merge-8x1)
7. [Pause tree](#pause-tree)
8. [Transfer eddsa 1x1](#transfer-eddsa-1x1)
9. [Transfer eddsa 1x2](#transfer-eddsa-1x2)
10. [Transfer eddsa 1x8](#transfer-eddsa-1x8)
11. [Transfer eddsa 2x2](#transfer-eddsa-2x2)
12. [Transfer eddsa 2x3](#transfer-eddsa-2x3)
13. [Transfer eddsa 36x2](#transfer-eddsa-36x2)
14. [Transfer eddsa 3x3](#transfer-eddsa-3x3)
15. [Transfer eddsa 4x3](#transfer-eddsa-4x3)
16. [Transfer eddsa 4x4](#transfer-eddsa-4x4)
17. [Transfer eddsa 5x3](#transfer-eddsa-5x3)
18. [Transfer eddsa 5x4](#transfer-eddsa-5x4)
19. [Transfer eddsa cached 1 of 36x2](#transfer-eddsa-cached-1-of-36x2)
20. [Transfer eddsa cached 36x2](#transfer-eddsa-cached-36x2)
21. [Transfer eddsa cached 5x4](#transfer-eddsa-cached-5x4)
22. [Transfer ring eddsa 36x2](#transfer-ring-eddsa-36x2)
23. [Transfer ring p256 36x2](#transfer-ring-p256-36x2)
24. [Withdrawal sol](#withdrawal-sol)
25. [Withdrawal spl](#withdrawal-spl)

## 1. Create protocol config

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |      4,525 |      4,525 |

## 2. Deposit sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     37,868 |     36,666 |
| `process_instruction`         |     37,919 |          0 |

## 3. Deposit sol batch 3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     49,632 |     48,430 |
| `process_instruction`         |     49,683 |          0 |

## 4. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl_deposit`          |      1,303 |      1,303 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     39,702 |     38,367 |
| `process_instruction`         |     39,753 |          0 |

## 5. Merge 36x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     85,070 |     85,070 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    247,152 |     82,527 |

## 6. Merge 8x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     15,235 |     15,235 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    144,458 |     49,668 |

## 7. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        254 |        254 |

## 8. Transfer eddsa 1x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         92 |         92 |
| `create_nullifier_pdas`       |      1,935 |      1,935 |
| `apply_input_trees`           |      3,021 |      1,086 |
| `apply_output_tree`           |     28,230 |     28,230 |
| `public_input_hash`           |     16,512 |     16,512 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    132,507 |      2,227 |
| `process_instruction`         |    132,560 |          0 |

## 9. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |      1,935 |      1,935 |
| `apply_input_trees`           |      3,021 |      1,086 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     19,718 |     19,718 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    136,002 |      2,414 |
| `process_instruction`         |    136,055 |          0 |

## 10. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        554 |        554 |
| `create_nullifier_pdas`       |      1,935 |      1,935 |
| `apply_input_trees`           |      3,021 |      1,086 |
| `apply_output_tree`           |     31,971 |     31,971 |
| `public_input_hash`           |     26,108 |     26,108 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    147,610 |      3,531 |
| `process_instruction`         |    147,663 |          0 |

## 11. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |      3,678 |      3,678 |
| `apply_input_trees`           |      4,982 |      1,304 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     21,333 |     21,333 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    139,658 |        751 |
| `process_instruction`         |    139,711 |          0 |

## 12. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      3,678 |      3,678 |
| `apply_input_trees`           |      4,982 |      1,304 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     21,341 |     21,341 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    140,828 |        938 |
| `process_instruction`         |    140,881 |          0 |

## 13. Transfer eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |     70,611 |     70,611 |
| `apply_input_trees`           |     96,851 |     26,240 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     39,090 |     39,090 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    251,871 |          0 |
| `process_instruction`         |    251,924 |          0 |

## 14. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      5,421 |      5,421 |
| `apply_input_trees`           |      6,939 |      1,518 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     21,344 |     21,344 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    142,866 |          0 |
| `process_instruction`         |    142,919 |          0 |

## 15. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      7,534 |      7,534 |
| `apply_input_trees`           |     10,882 |      3,348 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     21,348 |     21,348 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    146,885 |          0 |
| `process_instruction`         |    146,938 |          0 |

## 16. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |      7,534 |      7,534 |
| `apply_input_trees`           |     10,882 |      3,348 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     21,348 |     21,348 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    147,174 |          0 |
| `process_instruction`         |    147,227 |          0 |

## 17. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      9,277 |      9,277 |
| `apply_input_trees`           |     12,838 |      3,561 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     22,955 |     22,955 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    150,526 |          0 |
| `process_instruction`         |    150,579 |          0 |

## 18. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |      9,277 |      9,277 |
| `apply_input_trees`           |     12,838 |      3,561 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     22,955 |     22,955 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    150,815 |          0 |
| `process_instruction`         |    150,868 |          0 |

## 19. Transfer eddsa cached 1 of 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |     73,157 |     73,157 |
| `apply_input_trees`           |     99,422 |     26,265 |
| `assign_cached_inputs`        |      3,967 |      3,967 |
| `apply_cached_inputs`         |      4,018 |         51 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     39,008 |     39,008 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    258,434 |          0 |
| `process_instruction`         |    258,487 |          0 |

## 20. Transfer eddsa cached 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |     76,802 |     76,802 |
| `apply_input_trees`           |    103,362 |     26,560 |
| `assign_cached_inputs`        |     21,800 |     21,800 |
| `apply_cached_inputs`         |     21,851 |         51 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     39,008 |     39,008 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    280,207 |          0 |
| `process_instruction`         |    280,260 |          0 |

## 21. Transfer eddsa cached 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |     13,259 |     13,259 |
| `apply_input_trees`           |     16,737 |      3,478 |
| `assign_cached_inputs`        |      3,726 |      3,726 |
| `apply_cached_inputs`         |      3,777 |         51 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     22,873 |     22,873 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    158,465 |          0 |
| `process_instruction`         |    158,518 |          0 |

## 22. Transfer ring eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `create_nullifier_pdas`       |     70,611 |     70,611 |
| `apply_input_trees`           |     96,851 |     26,240 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     39,090 |     39,090 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    253,751 |          0 |
| `process_instruction`         |    253,804 |          0 |

## 23. Transfer ring p256 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `create_nullifier_pdas`       |     70,611 |     70,611 |
| `apply_input_trees`           |     96,851 |     26,240 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     42,680 |     42,680 |
| `verify_groth16`              |    210,747 |    210,747 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    388,626 |          0 |
| `process_instruction`         |    388,679 |          0 |

## 24. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      3,678 |      3,678 |
| `apply_input_trees`           |      4,982 |      1,304 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     23,362 |     23,362 |
| `verify_groth16`              |     79,523 |     79,523 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    144,451 |      1,355 |
| `process_instruction`         |    144,504 |          0 |

## 25. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      3,678 |      3,678 |
| `apply_input_trees`           |      4,982 |      1,304 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     23,365 |     23,365 |
| `verify_groth16`              |     79,523 |     79,523 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    146,100 |      2,980 |
| `process_instruction`         |    146,153 |          0 |

