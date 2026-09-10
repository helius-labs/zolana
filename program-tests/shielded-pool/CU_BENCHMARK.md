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
| `process_instruction`         |      3,878 |      3,878 |

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
| `create_nullifier_pdas`       |     78,162 |     78,162 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    281,375 |    109,825 |

## 6. Merge 8x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     15,070 |     15,070 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    165,475 |     57,017 |

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
| `create_nullifier_pdas`       |      1,892 |      1,892 |
| `apply_output_tree`           |     28,244 |     28,244 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    150,118 |     24,719 |
| `process_instruction`         |    150,171 |          0 |

## 9. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,063 |      1,063 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |        763 |        763 |
| `create_nullifier_pdas`       |      1,892 |      1,892 |
| `apply_output_tree`           |     28,280 |     28,280 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    152,102 |     26,601 |
| `process_instruction`         |    152,155 |          0 |

## 10. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,459 |      1,459 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |        763 |        763 |
| `create_nullifier_pdas`       |      1,892 |      1,892 |
| `apply_output_tree`           |     31,985 |     31,985 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    167,354 |     37,752 |
| `process_instruction`         |    167,407 |          0 |

## 11. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,063 |      1,063 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      1,788 |      1,788 |
| `create_nullifier_pdas`       |      3,983 |      3,983 |
| `apply_output_tree`           |     28,280 |     28,280 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    156,132 |     27,515 |
| `process_instruction`         |    156,185 |          0 |

## 12. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      1,788 |      1,788 |
| `create_nullifier_pdas`       |      3,983 |      3,983 |
| `apply_output_tree`           |     29,189 |     29,189 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    158,967 |     29,375 |
| `process_instruction`         |    159,020 |          0 |

## 13. Transfer eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,063 |      1,063 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |     36,638 |     36,638 |
| `create_nullifier_pdas`       |     74,581 |     74,581 |
| `apply_output_tree`           |     28,280 |     28,280 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    292,420 |     58,355 |
| `process_instruction`         |    292,473 |          0 |

## 14. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      2,813 |      2,813 |
| `create_nullifier_pdas`       |      5,711 |      5,711 |
| `apply_output_tree`           |     29,189 |     29,189 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    162,628 |     30,283 |
| `process_instruction`         |    162,681 |          0 |

## 15. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      3,838 |      3,838 |
| `create_nullifier_pdas`       |      7,439 |      7,439 |
| `apply_output_tree`           |     29,189 |     29,189 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    166,285 |     31,187 |
| `process_instruction`         |    166,338 |          0 |

## 16. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,195 |      1,195 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      3,838 |      3,838 |
| `create_nullifier_pdas`       |      7,439 |      7,439 |
| `apply_output_tree`           |     29,225 |     29,225 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    168,247 |     33,047 |
| `process_instruction`         |    168,300 |          0 |

## 17. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      4,863 |      4,863 |
| `create_nullifier_pdas`       |      9,530 |      9,530 |
| `apply_output_tree`           |     29,189 |     29,189 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    170,310 |     32,096 |
| `process_instruction`         |    170,363 |          0 |

## 18. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,195 |      1,195 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      4,863 |      4,863 |
| `create_nullifier_pdas`       |      9,530 |      9,530 |
| `apply_output_tree`           |     29,225 |     29,225 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    172,272 |     33,956 |
| `process_instruction`         |    172,325 |          0 |

## 19. Transfer ring eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |         44 |         44 |
| `fill_owner_signer_hashes`    |      1,014 |      1,014 |
| `apply_input_tree`            |     36,638 |     36,638 |
| `create_nullifier_pdas`       |     73,150 |     73,150 |
| `apply_output_tree`           |     29,151 |     29,151 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    292,811 |     59,426 |
| `process_instruction`         |    292,864 |          0 |

## 20. Transfer ring p256 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |         45 |         45 |
| `fill_owner_signer_hashes`    |      1,014 |      1,014 |
| `apply_input_tree`            |     36,638 |     36,638 |
| `create_nullifier_pdas`       |     73,513 |     73,513 |
| `apply_output_tree`           |     29,151 |     29,151 |
| `verify_groth16`              |    224,569 |    224,569 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    428,118 |     63,156 |
| `process_instruction`         |    428,171 |          0 |

## 21. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      1,788 |      1,788 |
| `create_nullifier_pdas`       |      3,983 |      3,983 |
| `apply_output_tree`           |     29,187 |     29,187 |
| `verify_groth16`              |     93,356 |     93,356 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    162,586 |     31,807 |
| `process_instruction`         |    162,639 |          0 |

## 22. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      1,788 |      1,788 |
| `create_nullifier_pdas`       |      3,620 |      3,620 |
| `apply_output_tree`           |     29,187 |     29,187 |
| `verify_groth16`              |     93,356 |     93,356 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    163,861 |     33,424 |
| `process_instruction`         |    163,914 |          0 |

