# Shielded Pool -- CU Benchmark

Compute unit profiling for feasible shielded-pool instruction families, replayed under mollusk from litesvm-built account state: protocol creation, tree pause, proof-free SOL/SPL shields, all ten Groth16-proven EdDSA transact shapes (including the 1x8 split shape), and SOL/SPL withdrawals. This target is a pure benchmark: no CI workflow runs the profiling build, so no CU ceilings are enforced here -- a ceiling that never runs would be unfalsifiable. Regression ceilings live in the fast cross_cutting_cu_budget suite, which pins every proofless instruction family per operation.

Regenerate with `just bench-shielded-pool`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Create protocol config](#create-protocol-config)
2. [Deposit sol](#deposit-sol)
3. [Deposit sol batch 3](#deposit-sol-batch-3)
4. [Deposit spl](#deposit-spl)
5. [Pause tree](#pause-tree)
6. [Transfer eddsa 1x1](#transfer-eddsa-1x1)
7. [Transfer eddsa 1x2](#transfer-eddsa-1x2)
8. [Transfer eddsa 1x8](#transfer-eddsa-1x8)
9. [Transfer eddsa 2x2](#transfer-eddsa-2x2)
10. [Transfer eddsa 2x3](#transfer-eddsa-2x3)
11. [Transfer eddsa 3x3](#transfer-eddsa-3x3)
12. [Transfer eddsa 4x3](#transfer-eddsa-4x3)
13. [Transfer eddsa 4x4](#transfer-eddsa-4x4)
14. [Transfer eddsa 5x3](#transfer-eddsa-5x3)
15. [Transfer eddsa 5x4](#transfer-eddsa-5x4)
16. [Withdrawal sol](#withdrawal-sol)
17. [Withdrawal spl](#withdrawal-spl)

## 1. Create protocol config

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |      4,691 |      4,691 |

## 2. Deposit sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     38,696 |     37,494 |
| `process_instruction`         |     38,746 |          0 |

## 3. Deposit sol batch 3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     50,211 |     49,009 |
| `process_instruction`         |     50,261 |          0 |

## 4. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl_deposit`          |      1,303 |      1,303 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     39,588 |     38,253 |
| `process_instruction`         |     39,638 |          0 |

## 5. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        243 |        243 |

## 6. Transfer eddsa 1x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,077 |      1,077 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |        799 |        799 |
| `create_nullifier_pdas`       |      4,547 |      4,547 |
| `apply_output_tree`           |     28,075 |     28,075 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    152,279 |     24,279 |
| `process_instruction`         |    152,331 |          0 |

## 7. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,142 |      1,142 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |        799 |        799 |
| `create_nullifier_pdas`       |      4,547 |      4,547 |
| `apply_output_tree`           |     28,108 |     28,108 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    154,530 |     26,432 |
| `process_instruction`         |    154,582 |          0 |

## 8. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,532 |      1,532 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |        799 |        799 |
| `create_nullifier_pdas`       |      4,547 |      4,547 |
| `apply_output_tree`           |     31,815 |     31,815 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    170,992 |     38,797 |
| `process_instruction`         |    171,044 |          0 |

## 9. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,142 |      1,142 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      2,044 |      2,044 |
| `create_nullifier_pdas`       |     10,430 |     10,430 |
| `apply_output_tree`           |     28,108 |     28,108 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    164,287 |     29,061 |
| `process_instruction`         |    164,339 |          0 |

## 10. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,207 |      1,207 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      2,044 |      2,044 |
| `create_nullifier_pdas`       |     10,430 |     10,430 |
| `apply_output_tree`           |     29,020 |     29,020 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    167,279 |     31,076 |
| `process_instruction`         |    167,331 |          0 |

## 11. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,207 |      1,207 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      3,289 |      3,289 |
| `create_nullifier_pdas`       |     16,313 |     16,313 |
| `apply_output_tree`           |     29,020 |     29,020 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    177,005 |     33,674 |
| `process_instruction`         |    177,057 |          0 |

## 12. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,207 |      1,207 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      4,534 |      4,534 |
| `create_nullifier_pdas`       |     19,196 |     19,196 |
| `apply_output_tree`           |     29,020 |     29,020 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    183,737 |     36,278 |
| `process_instruction`         |    183,789 |          0 |

## 13. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,272 |      1,272 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      4,534 |      4,534 |
| `create_nullifier_pdas`       |     19,196 |     19,196 |
| `apply_output_tree`           |     29,053 |     29,053 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    186,144 |     38,587 |
| `process_instruction`         |    186,196 |          0 |

## 14. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,207 |      1,207 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      5,779 |      5,779 |
| `create_nullifier_pdas`       |     22,079 |     22,079 |
| `apply_output_tree`           |     29,020 |     29,020 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    190,583 |     38,996 |
| `process_instruction`         |    190,635 |          0 |

## 15. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,272 |      1,272 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      5,779 |      5,779 |
| `create_nullifier_pdas`       |     22,079 |     22,079 |
| `apply_output_tree`           |     29,053 |     29,053 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    192,875 |     41,190 |
| `process_instruction`         |    192,927 |          0 |

## 16. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,207 |      1,207 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      2,044 |      2,044 |
| `create_nullifier_pdas`       |      7,430 |      7,430 |
| `apply_output_tree`           |     29,021 |     29,021 |
| `verify_groth16`              |     93,356 |     93,356 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    168,321 |     33,928 |
| `process_instruction`         |    168,373 |          0 |

## 17. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,207 |      1,207 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      2,044 |      2,044 |
| `create_nullifier_pdas`       |      5,930 |      5,930 |
| `apply_output_tree`           |     29,021 |     29,021 |
| `verify_groth16`              |     93,356 |     93,356 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    168,544 |     35,630 |
| `process_instruction`         |    168,596 |          0 |

