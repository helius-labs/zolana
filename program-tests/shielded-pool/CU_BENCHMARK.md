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
19. [Transfer ring eddsa 36x2](#transfer-ring-eddsa-36x2)
20. [Transfer ring p256 36x2](#transfer-ring-p256-36x2)
21. [Withdrawal sol](#withdrawal-sol)
22. [Withdrawal spl](#withdrawal-spl)

## 1. Create protocol config

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |      3,879 |      3,879 |

## 2. Deposit sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     37,918 |     36,716 |
| `process_instruction`         |     37,969 |          0 |

## 3. Deposit sol batch 3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     49,760 |     48,558 |
| `process_instruction`         |     49,811 |          0 |

## 4. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl_deposit`          |      1,303 |      1,303 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     39,753 |     38,418 |
| `process_instruction`         |     39,804 |          0 |

## 5. Merge 36x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     74,303 |     74,303 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    236,698 |     82,840 |

## 6. Merge 8x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     19,036 |     19,036 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    148,023 |     49,432 |

## 7. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        255 |        255 |

## 8. Transfer eddsa 1x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |        987 |        987 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `create_nullifier_pdas`       |      1,907 |      1,907 |
| `apply_input_trees`           |      2,944 |      1,037 |
| `apply_output_tree`           |     28,230 |     28,230 |
| `public_input_hash`           |     14,784 |     14,784 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    130,787 |      2,266 |
| `process_instruction`         |    130,840 |          0 |

## 9. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,053 |      1,053 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `create_nullifier_pdas`       |      1,907 |      1,907 |
| `apply_input_trees`           |      2,944 |      1,037 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     17,990 |     17,990 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    134,282 |      2,453 |
| `process_instruction`         |    134,335 |          0 |

## 10. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,449 |      1,449 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `create_nullifier_pdas`       |      1,907 |      1,907 |
| `apply_input_trees`           |      2,944 |      1,037 |
| `apply_output_tree`           |     31,971 |     31,971 |
| `public_input_hash`           |     24,380 |     24,380 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    145,890 |      3,570 |
| `process_instruction`         |    145,943 |          0 |

## 11. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,053 |      1,053 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `create_nullifier_pdas`       |      3,999 |      3,999 |
| `apply_input_trees`           |      5,267 |      1,268 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     19,606 |     19,606 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    138,302 |        442 |
| `process_instruction`         |    138,355 |          0 |

## 12. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,119 |      1,119 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `create_nullifier_pdas`       |      3,999 |      3,999 |
| `apply_input_trees`           |      5,267 |      1,268 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     19,614 |     19,614 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    139,472 |        629 |
| `process_instruction`         |    139,525 |          0 |

## 13. Transfer eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,053 |      1,053 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `create_nullifier_pdas`       |     74,631 |     74,631 |
| `apply_input_trees`           |    101,397 |     26,766 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     37,363 |     37,363 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    254,775 |          0 |
| `process_instruction`         |    254,828 |          0 |

## 14. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,119 |      1,119 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `create_nullifier_pdas`       |      5,728 |      5,728 |
| `apply_input_trees`           |      7,222 |      1,494 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     19,617 |     19,617 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    141,507 |          0 |
| `process_instruction`         |    141,560 |          0 |

## 15. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,119 |      1,119 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `create_nullifier_pdas`       |      7,457 |      7,457 |
| `apply_input_trees`           |     10,806 |      3,349 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     19,620 |     19,620 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    145,167 |          0 |
| `process_instruction`         |    145,220 |          0 |

## 16. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,185 |      1,185 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `create_nullifier_pdas`       |      7,457 |      7,457 |
| `apply_input_trees`           |     10,806 |      3,349 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     19,620 |     19,620 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    145,456 |          0 |
| `process_instruction`         |    145,509 |          0 |

## 17. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,119 |      1,119 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `create_nullifier_pdas`       |      9,549 |      9,549 |
| `apply_input_trees`           |     13,124 |      3,575 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     21,228 |     21,228 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    149,171 |          0 |
| `process_instruction`         |    149,224 |          0 |

## 18. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,185 |      1,185 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `create_nullifier_pdas`       |      9,549 |      9,549 |
| `apply_input_trees`           |     13,124 |      3,575 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     21,228 |     21,228 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    149,460 |          0 |
| `process_instruction`         |    149,513 |          0 |

## 19. Transfer ring eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `fill_owner_signer_hashes`    |      1,013 |      1,013 |
| `create_nullifier_pdas`       |     74,987 |     74,987 |
| `apply_input_trees`           |    101,753 |     26,766 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     37,363 |     37,363 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    257,021 |          0 |
| `process_instruction`         |    257,074 |          0 |

## 20. Transfer ring p256 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `fill_owner_signer_hashes`    |      1,013 |      1,013 |
| `create_nullifier_pdas`       |     73,563 |     73,563 |
| `apply_input_trees`           |    100,329 |     26,766 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     40,965 |     40,965 |
| `verify_groth16`              |    210,874 |    210,874 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    390,607 |          0 |
| `process_instruction`         |    390,660 |          0 |

## 21. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,119 |      1,119 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `create_nullifier_pdas`       |      3,999 |      3,999 |
| `apply_input_trees`           |      5,267 |      1,268 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     21,635 |     21,635 |
| `verify_groth16`              |     79,523 |     79,523 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    143,091 |      1,042 |
| `process_instruction`         |    143,144 |          0 |

## 22. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,119 |      1,119 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `create_nullifier_pdas`       |      4,711 |      4,711 |
| `apply_input_trees`           |      5,979 |      1,268 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     21,638 |     21,638 |
| `verify_groth16`              |     79,523 |     79,523 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    145,442 |      1,945 |
| `process_instruction`         |    145,495 |          0 |

