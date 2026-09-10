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
| `process_instruction`         |      5,068 |      5,068 |

## 2. Deposit sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     40,076 |     38,874 |
| `process_instruction`         |     40,127 |          0 |

## 3. Deposit sol batch 3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     54,314 |     53,112 |
| `process_instruction`         |     54,365 |          0 |

## 4. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl_deposit`          |      1,303 |      1,303 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     40,964 |     39,629 |
| `process_instruction`         |     41,015 |          0 |

## 5. Merge 36x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |    142,952 |    142,952 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    350,313 |    113,973 |

## 6. Merge 8x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     41,228 |     41,228 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    193,942 |     59,326 |

## 7. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        255 |        255 |

## 8. Transfer eddsa 1x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |        997 |        997 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |        763 |        763 |
| `create_nullifier_pdas`       |      3,047 |      3,047 |
| `apply_output_tree`           |     28,244 |     28,244 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    151,273 |     24,719 |
| `process_instruction`         |    151,326 |          0 |

## 9. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,063 |      1,063 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |        763 |        763 |
| `create_nullifier_pdas`       |      3,047 |      3,047 |
| `apply_output_tree`           |     28,280 |     28,280 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    153,257 |     26,601 |
| `process_instruction`         |    153,310 |          0 |

## 10. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,459 |      1,459 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |        763 |        763 |
| `create_nullifier_pdas`       |      3,047 |      3,047 |
| `apply_output_tree`           |     31,985 |     31,985 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    168,509 |     37,752 |
| `process_instruction`         |    168,562 |          0 |

## 11. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,063 |      1,063 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      1,788 |      1,788 |
| `create_nullifier_pdas`       |      7,430 |      7,430 |
| `apply_output_tree`           |     28,280 |     28,280 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    159,579 |     27,515 |
| `process_instruction`         |    159,632 |          0 |

## 12. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      1,788 |      1,788 |
| `create_nullifier_pdas`       |      7,430 |      7,430 |
| `apply_output_tree`           |     29,189 |     29,189 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    162,414 |     29,375 |
| `process_instruction`         |    162,467 |          0 |

## 13. Transfer eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,063 |      1,063 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |     36,638 |     36,638 |
| `create_nullifier_pdas`       |    154,952 |    154,952 |
| `apply_output_tree`           |     28,280 |     28,280 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    372,791 |     58,355 |
| `process_instruction`         |    372,844 |          0 |

## 14. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      2,813 |      2,813 |
| `create_nullifier_pdas`       |     10,313 |     10,313 |
| `apply_output_tree`           |     29,189 |     29,189 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    167,230 |     30,283 |
| `process_instruction`         |    167,283 |          0 |

## 15. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      3,838 |      3,838 |
| `create_nullifier_pdas`       |     13,196 |     13,196 |
| `apply_output_tree`           |     29,189 |     29,189 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    172,042 |     31,187 |
| `process_instruction`         |    172,095 |          0 |

## 16. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,195 |      1,195 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      3,838 |      3,838 |
| `create_nullifier_pdas`       |     13,196 |     13,196 |
| `apply_output_tree`           |     29,225 |     29,225 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    174,004 |     33,047 |
| `process_instruction`         |    174,057 |          0 |

## 17. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      4,863 |      4,863 |
| `create_nullifier_pdas`       |     17,579 |     17,579 |
| `apply_output_tree`           |     29,189 |     29,189 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    178,359 |     32,096 |
| `process_instruction`         |    178,412 |          0 |

## 18. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,195 |      1,195 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      4,863 |      4,863 |
| `create_nullifier_pdas`       |     17,579 |     17,579 |
| `apply_output_tree`           |     29,225 |     29,225 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    180,321 |     33,956 |
| `process_instruction`         |    180,374 |          0 |

## 19. Transfer ring eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |         44 |         44 |
| `fill_owner_signer_hashes`    |      1,014 |      1,014 |
| `apply_input_tree`            |     36,638 |     36,638 |
| `create_nullifier_pdas`       |    148,952 |    148,952 |
| `apply_output_tree`           |     29,151 |     29,151 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    368,613 |     59,426 |
| `process_instruction`         |    368,666 |          0 |

## 20. Transfer ring p256 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |         45 |         45 |
| `fill_owner_signer_hashes`    |      1,014 |      1,014 |
| `apply_input_tree`            |     36,638 |     36,638 |
| `create_nullifier_pdas`       |    150,452 |    150,452 |
| `apply_output_tree`           |     29,151 |     29,151 |
| `verify_groth16`              |    224,639 |    224,639 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    505,127 |     63,156 |
| `process_instruction`         |    505,180 |          0 |

## 21. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      1,788 |      1,788 |
| `create_nullifier_pdas`       |      7,430 |      7,430 |
| `apply_output_tree`           |     29,187 |     29,187 |
| `verify_groth16`              |     93,356 |     93,356 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    166,033 |     31,807 |
| `process_instruction`         |    166,086 |          0 |

## 22. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      1,788 |      1,788 |
| `create_nullifier_pdas`       |      5,930 |      5,930 |
| `apply_output_tree`           |     29,187 |     29,187 |
| `verify_groth16`              |     93,356 |     93,356 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    166,171 |     33,424 |
| `process_instruction`         |    166,224 |          0 |

