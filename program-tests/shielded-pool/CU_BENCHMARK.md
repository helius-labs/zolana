# Shielded Pool -- CU Benchmark

Compute unit profiling for feasible shielded-pool instruction families, replayed under mollusk from litesvm-built account state: protocol creation, tree pause, proof-free SOL/SPL shields, all eleven Groth16-proven EdDSA transact shapes (including the 1x8 split shape and the 36x2 consolidation shape), the 36x2 consolidation shape on both `ring_transact` rails (EdDSA, and P256 whose BSB22 commitment adds a Pedersen proof-of-knowledge pairing to verification), both supported `merge_transact` shapes, compact padding on the 2x3 and 36x2 transact shapes and both merge shapes, and SOL/SPL withdrawals. This target is a pure benchmark: no CI workflow runs the profiling build, so no CU ceilings are enforced here -- a ceiling that never runs would be unfalsifiable. Regression ceilings live in the fast cross_cutting_cu_budget suite, which pins every proofless instruction family per operation.

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
6. [Merge 36x1 compact 9 sent](#merge-36x1-compact-9-sent)
7. [Merge 8x1](#merge-8x1)
8. [Merge 8x1 compact 1 sent](#merge-8x1-compact-1-sent)
9. [Pause tree](#pause-tree)
10. [Transfer eddsa 1x1](#transfer-eddsa-1x1)
11. [Transfer eddsa 1x2](#transfer-eddsa-1x2)
12. [Transfer eddsa 1x8](#transfer-eddsa-1x8)
13. [Transfer eddsa 2x2](#transfer-eddsa-2x2)
14. [Transfer eddsa 2x3](#transfer-eddsa-2x3)
15. [Transfer eddsa 2x3 compact](#transfer-eddsa-2x3-compact)
16. [Transfer eddsa 36x2](#transfer-eddsa-36x2)
17. [Transfer eddsa 36x2 compact](#transfer-eddsa-36x2-compact)
18. [Transfer eddsa 3x3](#transfer-eddsa-3x3)
19. [Transfer eddsa 4x3](#transfer-eddsa-4x3)
20. [Transfer eddsa 4x4](#transfer-eddsa-4x4)
21. [Transfer eddsa 5x3](#transfer-eddsa-5x3)
22. [Transfer eddsa 5x4](#transfer-eddsa-5x4)
23. [Transfer eddsa cached 1 of 36x2](#transfer-eddsa-cached-1-of-36x2)
24. [Transfer eddsa cached 36x2](#transfer-eddsa-cached-36x2)
25. [Transfer eddsa cached 5x4](#transfer-eddsa-cached-5x4)
26. [Transfer ring eddsa 36x2](#transfer-ring-eddsa-36x2)
27. [Transfer ring p256 36x2](#transfer-ring-p256-36x2)
28. [Withdrawal sol](#withdrawal-sol)
29. [Withdrawal spl](#withdrawal-spl)

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

## 5. Merge 36x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     76,055 |     76,055 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    239,203 |     83,612 |

## 6. Merge 36x1 compact 9 sent

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     19,706 |     19,706 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    151,545 |     52,303 |

## 7. Merge 8x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     18,998 |     18,998 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    148,565 |     50,031 |

## 8. Merge 8x1 compact 1 sent

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |      3,404 |      3,404 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    125,551 |     42,611 |

## 9. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        254 |        254 |

## 10. Transfer eddsa 1x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         92 |         92 |
| `create_nullifier_pdas`       |      1,975 |      1,975 |
| `apply_input_trees`           |      3,088 |      1,113 |
| `apply_output_tree`           |     28,230 |     28,230 |
| `public_input_hash`           |     16,615 |     16,615 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    132,994 |      2,523 |
| `process_instruction`         |    133,047 |          0 |

## 11. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |      1,975 |      1,975 |
| `apply_input_trees`           |      3,088 |      1,113 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     19,823 |     19,823 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    136,497 |      2,716 |
| `process_instruction`         |    136,550 |          0 |

## 12. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        554 |        554 |
| `create_nullifier_pdas`       |      1,975 |      1,975 |
| `apply_input_trees`           |      3,088 |      1,113 |
| `apply_output_tree`           |     31,971 |     31,971 |
| `public_input_hash`           |     26,375 |     26,375 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    148,303 |      3,869 |
| `process_instruction`         |    148,356 |          0 |

## 13. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |      3,747 |      3,747 |
| `apply_input_trees`           |      5,069 |      1,322 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     21,425 |     21,425 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    140,169 |      1,033 |
| `process_instruction`         |    140,222 |          0 |

## 14. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      3,747 |      3,747 |
| `apply_input_trees`           |      5,069 |      1,322 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     21,463 |     21,463 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    141,375 |      1,226 |
| `process_instruction`         |    141,428 |          0 |

## 15. Transfer eddsa 2x3 compact

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         92 |         92 |
| `create_nullifier_pdas`       |      1,975 |      1,975 |
| `apply_input_trees`           |      3,088 |      1,113 |
| `apply_output_tree`           |     28,230 |     28,230 |
| `public_input_hash`           |     21,591 |     21,591 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    137,971 |      2,524 |
| `process_instruction`         |    138,024 |          0 |

## 16. Transfer eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |     71,666 |     71,666 |
| `apply_input_trees`           |     97,788 |     26,122 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     39,428 |     39,428 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    253,954 |          0 |
| `process_instruction`         |    254,007 |          0 |

## 17. Transfer eddsa 36x2 compact

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         92 |         92 |
| `create_nullifier_pdas`       |      1,975 |      1,975 |
| `apply_input_trees`           |      3,088 |      1,113 |
| `apply_output_tree`           |     28,230 |     28,230 |
| `public_input_hash`           |     22,156 |     22,156 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    138,538 |      2,526 |
| `process_instruction`         |    138,591 |          0 |

## 18. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      5,519 |      5,519 |
| `apply_input_trees`           |      7,051 |      1,532 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     21,481 |     21,481 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    143,467 |          0 |
| `process_instruction`         |    143,520 |          0 |

## 19. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      7,661 |      7,661 |
| `apply_input_trees`           |     11,019 |      3,358 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     21,502 |     21,502 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    147,542 |          0 |
| `process_instruction`         |    147,595 |          0 |

## 20. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |      7,661 |      7,661 |
| `apply_input_trees`           |     11,019 |      3,358 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     21,544 |     21,544 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    147,879 |          0 |
| `process_instruction`         |    147,932 |          0 |

## 21. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      9,433 |      9,433 |
| `apply_input_trees`           |     13,000 |      3,567 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     23,098 |     23,098 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    151,211 |          0 |
| `process_instruction`         |    151,264 |          0 |

## 22. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |      9,433 |      9,433 |
| `apply_input_trees`           |     13,000 |      3,567 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     23,140 |     23,140 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    151,548 |          0 |
| `process_instruction`         |    151,601 |          0 |

## 23. Transfer eddsa cached 1 of 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |     74,941 |     74,941 |
| `apply_input_trees`           |    100,911 |     25,970 |
| `assign_cached_inputs`        |      2,988 |      2,988 |
| `bind_cached_inputs`          |      3,008 |         20 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     39,349 |     39,349 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    260,375 |          0 |
| `process_instruction`         |    260,428 |          0 |

## 24. Transfer eddsa cached 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |     80,381 |     80,381 |
| `apply_input_trees`           |    106,351 |     25,970 |
| `assign_cached_inputs`        |     20,462 |     20,462 |
| `bind_cached_inputs`          |     20,482 |         20 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     39,349 |     39,349 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    283,289 |          0 |
| `process_instruction`         |    283,342 |          0 |

## 25. Transfer eddsa cached 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |     10,521 |     10,521 |
| `apply_input_trees`           |     13,936 |      3,415 |
| `assign_cached_inputs`        |      4,006 |      4,006 |
| `bind_cached_inputs`          |      4,026 |         20 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     23,061 |     23,061 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    156,800 |          0 |
| `process_instruction`         |    156,853 |          0 |

## 26. Transfer ring eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `create_nullifier_pdas`       |     72,754 |     72,754 |
| `apply_input_trees`           |     98,876 |     26,122 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     37,913 |     37,913 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    255,410 |          0 |
| `process_instruction`         |    255,463 |          0 |

## 27. Transfer ring p256 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `create_nullifier_pdas`       |     71,666 |     71,666 |
| `apply_input_trees`           |     97,788 |     26,122 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     41,521 |     41,521 |
| `verify_groth16`              |    137,142 |    137,142 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    315,629 |          0 |
| `process_instruction`         |    315,682 |          0 |

## 28. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      3,747 |      3,747 |
| `apply_input_trees`           |      5,069 |      1,322 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     22,723 |     22,723 |
| `verify_groth16`              |     79,504 |     79,504 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    144,234 |      1,640 |
| `process_instruction`         |    144,287 |          0 |

## 29. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      4,835 |      4,835 |
| `apply_input_trees`           |      6,157 |      1,322 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     22,725 |     22,725 |
| `verify_groth16`              |     79,504 |     79,504 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    146,974 |      2,181 |
| `process_instruction`         |    147,027 |          0 |

