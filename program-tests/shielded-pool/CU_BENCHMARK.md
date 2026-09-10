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
| `create_nullifier_pdas`       |     77,950 |     77,950 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    278,602 |    107,264 |

## 6. Merge 8x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     18,161 |     18,161 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    166,332 |     54,783 |

## 7. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        255 |        255 |

## 8. Transfer eddsa 1x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |        992 |        992 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |        673 |        673 |
| `create_nullifier_pdas`       |      1,887 |      1,887 |
| `apply_output_tree`           |     28,263 |     28,263 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    148,669 |     23,352 |
| `process_instruction`         |    148,722 |          0 |

## 9. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,059 |      1,059 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |        673 |        673 |
| `create_nullifier_pdas`       |      1,887 |      1,887 |
| `apply_output_tree`           |     28,299 |     28,299 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    150,654 |     25,234 |
| `process_instruction`         |    150,707 |          0 |

## 10. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,461 |      1,461 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |        673 |        673 |
| `create_nullifier_pdas`       |      1,887 |      1,887 |
| `apply_output_tree`           |     32,004 |     32,004 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    165,912 |     36,385 |
| `process_instruction`         |    165,965 |          0 |

## 11. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,059 |      1,059 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      1,657 |      1,657 |
| `create_nullifier_pdas`       |      3,965 |      3,965 |
| `apply_output_tree`           |     28,299 |     28,299 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    154,630 |     26,148 |
| `process_instruction`         |    154,683 |          0 |

## 12. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,126 |      1,126 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      1,657 |      1,657 |
| `create_nullifier_pdas`       |      3,965 |      3,965 |
| `apply_output_tree`           |     29,208 |     29,208 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    157,466 |     28,008 |
| `process_instruction`         |    157,519 |          0 |

## 13. Transfer eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,059 |      1,059 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |     35,113 |     35,113 |
| `create_nullifier_pdas`       |     73,985 |     73,985 |
| `apply_output_tree`           |     28,299 |     28,299 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    288,946 |     56,988 |
| `process_instruction`         |    288,999 |          0 |

## 14. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,126 |      1,126 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      2,641 |      2,641 |
| `create_nullifier_pdas`       |      5,676 |      5,676 |
| `apply_output_tree`           |     29,208 |     29,208 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    161,069 |     28,916 |
| `process_instruction`         |    161,122 |          0 |

## 15. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,126 |      1,126 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      3,625 |      3,625 |
| `create_nullifier_pdas`       |      7,387 |      7,387 |
| `apply_output_tree`           |     29,208 |     29,208 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    164,668 |     29,820 |
| `process_instruction`         |    164,721 |          0 |

## 16. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,193 |      1,193 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      3,625 |      3,625 |
| `create_nullifier_pdas`       |      7,387 |      7,387 |
| `apply_output_tree`           |     29,244 |     29,244 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    166,631 |     31,680 |
| `process_instruction`         |    166,684 |          0 |

## 17. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,126 |      1,126 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      4,609 |      4,609 |
| `create_nullifier_pdas`       |      9,461 |      9,461 |
| `apply_output_tree`           |     29,208 |     29,208 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    168,635 |     30,729 |
| `process_instruction`         |    168,688 |          0 |

## 18. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,193 |      1,193 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      4,609 |      4,609 |
| `create_nullifier_pdas`       |      9,461 |      9,461 |
| `apply_output_tree`           |     29,244 |     29,244 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    170,598 |     32,589 |
| `process_instruction`         |    170,651 |          0 |

## 19. Transfer ring eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |         43 |         43 |
| `fill_owner_signer_hashes`    |      1,013 |      1,013 |
| `apply_input_tree`            |     35,113 |     35,113 |
| `create_nullifier_pdas`       |     72,554 |     72,554 |
| `apply_output_tree`           |     29,170 |     29,170 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    289,340 |     58,059 |
| `process_instruction`         |    289,393 |          0 |

## 20. Transfer ring p256 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |         44 |         44 |
| `fill_owner_signer_hashes`    |      1,013 |      1,013 |
| `apply_input_tree`            |     35,113 |     35,113 |
| `create_nullifier_pdas`       |     72,917 |     72,917 |
| `apply_output_tree`           |     29,170 |     29,170 |
| `verify_groth16`              |    224,627 |    224,627 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    424,705 |     61,789 |
| `process_instruction`         |    424,758 |          0 |

## 21. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,126 |      1,126 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      1,657 |      1,657 |
| `create_nullifier_pdas`       |      3,602 |      3,602 |
| `apply_output_tree`           |     29,206 |     29,206 |
| `verify_groth16`              |     93,356 |     93,356 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    160,722 |     30,440 |
| `process_instruction`         |    160,775 |          0 |

## 22. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,126 |      1,126 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      1,657 |      1,657 |
| `create_nullifier_pdas`       |      3,602 |      3,602 |
| `apply_output_tree`           |     29,206 |     29,206 |
| `verify_groth16`              |     93,356 |     93,356 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    162,360 |     32,057 |
| `process_instruction`         |    162,413 |          0 |

