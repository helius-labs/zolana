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
19. [Transfer eddsa cached 36x2](#transfer-eddsa-cached-36x2)
20. [Transfer eddsa cached 5x4](#transfer-eddsa-cached-5x4)
21. [Transfer ring eddsa 36x2](#transfer-ring-eddsa-36x2)
22. [Transfer ring p256 36x2](#transfer-ring-p256-36x2)
23. [Withdrawal sol](#withdrawal-sol)
24. [Withdrawal spl](#withdrawal-spl)

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
| `create_nullifier_pdas`       |     71,677 |     71,677 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    234,420 |     83,188 |

## 6. Merge 8x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     16,334 |     16,334 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    145,879 |     49,990 |

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
| `apply_input_trees`           |      3,005 |      1,070 |
| `apply_output_tree`           |     28,230 |     28,230 |
| `public_input_hash`           |     16,496 |     16,496 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    132,480 |      2,232 |
| `process_instruction`         |    132,533 |          0 |

## 9. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |      1,935 |      1,935 |
| `apply_input_trees`           |      3,005 |      1,070 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     19,702 |     19,702 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    135,975 |      2,419 |
| `process_instruction`         |    136,028 |          0 |

## 10. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        554 |        554 |
| `create_nullifier_pdas`       |      1,935 |      1,935 |
| `apply_input_trees`           |      3,005 |      1,070 |
| `apply_output_tree`           |     31,971 |     31,971 |
| `public_input_hash`           |     26,092 |     26,092 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    147,583 |      3,536 |
| `process_instruction`         |    147,636 |          0 |

## 11. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |      3,678 |      3,678 |
| `apply_input_trees`           |      4,966 |      1,288 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     22,919 |     22,919 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    141,233 |        756 |
| `process_instruction`         |    141,286 |          0 |

## 12. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      3,678 |      3,678 |
| `apply_input_trees`           |      4,966 |      1,288 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     22,927 |     22,927 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    142,403 |        943 |
| `process_instruction`         |    142,456 |          0 |

## 13. Transfer eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |     70,611 |     70,611 |
| `apply_input_trees`           |     96,835 |     26,224 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     58,333 |     58,333 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    271,103 |          0 |
| `process_instruction`         |    271,156 |          0 |

## 14. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      5,421 |      5,421 |
| `apply_input_trees`           |      6,923 |      1,502 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     22,932 |     22,932 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    144,443 |          0 |
| `process_instruction`         |    144,496 |          0 |

## 15. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      7,534 |      7,534 |
| `apply_input_trees`           |     10,866 |      3,332 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     22,937 |     22,937 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    148,463 |          0 |
| `process_instruction`         |    148,516 |          0 |

## 16. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |      7,534 |      7,534 |
| `apply_input_trees`           |     10,866 |      3,332 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     22,937 |     22,937 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    148,752 |          0 |
| `process_instruction`         |    148,805 |          0 |

## 17. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      9,277 |      9,277 |
| `apply_input_trees`           |     12,822 |      3,545 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     26,147 |     26,147 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    153,707 |          0 |
| `process_instruction`         |    153,760 |          0 |

## 18. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |      9,277 |      9,277 |
| `apply_input_trees`           |     12,822 |      3,545 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     26,147 |     26,147 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    153,996 |          0 |
| `process_instruction`         |    154,049 |          0 |

## 19. Transfer eddsa cached 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |     74,245 |     74,245 |
| `apply_input_trees`           |    100,789 |     26,544 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     39,008 |     39,008 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    278,051 |          0 |
| `process_instruction`         |    278,104 |          0 |

## 20. Transfer eddsa cached 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |     11,453 |     11,453 |
| `apply_input_trees`           |     14,915 |      3,462 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     22,873 |     22,873 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    156,664 |          0 |
| `process_instruction`         |    156,717 |          0 |

## 21. Transfer ring eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `create_nullifier_pdas`       |     71,340 |     71,340 |
| `apply_input_trees`           |     97,564 |     26,224 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     58,333 |     58,333 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    273,709 |          0 |
| `process_instruction`         |    273,762 |          0 |

## 22. Transfer ring p256 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `create_nullifier_pdas`       |     70,611 |     70,611 |
| `apply_input_trees`           |     96,835 |     26,224 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     61,923 |     61,923 |
| `verify_groth16`              |    210,786 |    210,786 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    407,894 |          0 |
| `process_instruction`         |    407,947 |          0 |

## 23. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      4,048 |      4,048 |
| `apply_input_trees`           |      5,336 |      1,288 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     24,948 |     24,948 |
| `verify_groth16`              |     79,523 |     79,523 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    146,396 |        990 |
| `process_instruction`         |    146,449 |          0 |

## 24. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      4,407 |      4,407 |
| `apply_input_trees`           |      5,695 |      1,288 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     24,951 |     24,951 |
| `verify_groth16`              |     79,523 |     79,523 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    148,404 |      2,256 |
| `process_instruction`         |    148,457 |          0 |

