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
| `create_nullifier_pdas`       |     76,480 |     76,480 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    278,288 |    108,420 |

## 6. Merge 8x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     15,195 |     15,195 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    163,856 |     55,273 |

## 7. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        255 |        255 |

## 8. Transfer eddsa 1x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |        992 |        992 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |        763 |        763 |
| `create_nullifier_pdas`       |      1,922 |      1,922 |
| `apply_output_tree`           |     28,222 |     28,222 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    148,757 |     23,356 |
| `process_instruction`         |    148,810 |          0 |

## 9. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,059 |      1,059 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |        763 |        763 |
| `create_nullifier_pdas`       |      1,922 |      1,922 |
| `apply_output_tree`           |     28,258 |     28,258 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    150,742 |     25,238 |
| `process_instruction`         |    150,795 |          0 |

## 10. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,461 |      1,461 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |        763 |        763 |
| `create_nullifier_pdas`       |      1,922 |      1,922 |
| `apply_output_tree`           |     31,963 |     31,963 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    166,000 |     36,389 |
| `process_instruction`         |    166,053 |          0 |

## 11. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,059 |      1,059 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      1,788 |      1,788 |
| `create_nullifier_pdas`       |      4,029 |      4,029 |
| `apply_output_tree`           |     28,258 |     28,258 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    154,788 |     26,152 |
| `process_instruction`         |    154,841 |          0 |

## 12. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,126 |      1,126 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      1,788 |      1,788 |
| `create_nullifier_pdas`       |      4,029 |      4,029 |
| `apply_output_tree`           |     29,167 |     29,167 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    157,624 |     28,012 |
| `process_instruction`         |    157,677 |          0 |

## 13. Transfer eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,059 |      1,059 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |     36,638 |     36,638 |
| `create_nullifier_pdas`       |     75,035 |     75,035 |
| `apply_output_tree`           |     28,258 |     28,258 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    291,484 |     56,992 |
| `process_instruction`         |    291,537 |          0 |

## 14. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,126 |      1,126 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      2,813 |      2,813 |
| `create_nullifier_pdas`       |      5,769 |      5,769 |
| `apply_output_tree`           |     29,167 |     29,167 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    161,297 |     28,920 |
| `process_instruction`         |    161,350 |          0 |

## 15. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,126 |      1,126 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      3,838 |      3,838 |
| `create_nullifier_pdas`       |      7,509 |      7,509 |
| `apply_output_tree`           |     29,167 |     29,167 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    164,966 |     29,824 |
| `process_instruction`         |    165,019 |          0 |

## 16. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,193 |      1,193 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      3,838 |      3,838 |
| `create_nullifier_pdas`       |      7,509 |      7,509 |
| `apply_output_tree`           |     29,203 |     29,203 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    166,929 |     31,684 |
| `process_instruction`         |    166,982 |          0 |

## 17. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,126 |      1,126 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      4,863 |      4,863 |
| `create_nullifier_pdas`       |      9,612 |      9,612 |
| `apply_output_tree`           |     29,167 |     29,167 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    169,003 |     30,733 |
| `process_instruction`         |    169,056 |          0 |

## 18. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,193 |      1,193 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      4,863 |      4,863 |
| `create_nullifier_pdas`       |      9,612 |      9,612 |
| `apply_output_tree`           |     29,203 |     29,203 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    170,966 |     32,593 |
| `process_instruction`         |    171,019 |          0 |

## 19. Transfer ring eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |         43 |         43 |
| `fill_owner_signer_hashes`    |      1,013 |      1,013 |
| `apply_input_tree`            |     36,638 |     36,638 |
| `create_nullifier_pdas`       |     73,967 |     73,967 |
| `apply_output_tree`           |     29,129 |     29,129 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    292,241 |     58,063 |
| `process_instruction`         |    292,294 |          0 |

## 20. Transfer ring p256 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |         44 |         44 |
| `fill_owner_signer_hashes`    |      1,013 |      1,013 |
| `apply_input_tree`            |     36,638 |     36,638 |
| `create_nullifier_pdas`       |     73,967 |     73,967 |
| `apply_output_tree`           |     29,129 |     29,129 |
| `verify_groth16`              |    224,580 |    224,580 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    427,196 |     61,793 |
| `process_instruction`         |    427,249 |          0 |

## 21. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,126 |      1,126 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      1,788 |      1,788 |
| `create_nullifier_pdas`       |      3,666 |      3,666 |
| `apply_output_tree`           |     29,165 |     29,165 |
| `verify_groth16`              |     93,356 |     93,356 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    160,880 |     30,444 |
| `process_instruction`         |    160,933 |          0 |

## 22. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,126 |      1,126 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      1,788 |      1,788 |
| `create_nullifier_pdas`       |      4,385 |      4,385 |
| `apply_output_tree`           |     29,165 |     29,165 |
| `verify_groth16`              |     93,356 |     93,356 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    163,237 |     32,061 |
| `process_instruction`         |    163,290 |          0 |

