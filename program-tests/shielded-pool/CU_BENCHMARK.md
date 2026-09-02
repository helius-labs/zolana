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
| `process_instruction`         |      4,489 |      4,489 |

## 2. Deposit sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     38,389 |     37,188 |
| `process_instruction`         |     38,440 |          0 |

## 3. Deposit sol batch 3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     49,777 |     48,576 |
| `process_instruction`         |     49,828 |          0 |

## 4. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl_deposit`          |      1,277 |      1,277 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     39,243 |     37,935 |
| `process_instruction`         |     39,294 |          0 |

## 5. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        240 |        240 |

## 6. Transfer eddsa 1x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,078 |      1,078 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |        737 |        737 |
| `create_nullifier_pdas`       |      4,540 |      4,540 |
| `apply_output_tree`           |     28,046 |     28,046 |
| `verify_groth16`              |     93,351 |     93,351 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    152,179 |     24,282 |
| `process_instruction`         |    152,232 |          0 |

## 7. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,144 |      1,144 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |        737 |        737 |
| `create_nullifier_pdas`       |      4,540 |      4,540 |
| `apply_output_tree`           |     28,089 |     28,089 |
| `verify_groth16`              |     93,351 |     93,351 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    154,420 |     26,414 |
| `process_instruction`         |    154,473 |          0 |

## 8. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,540 |      1,540 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |        737 |        737 |
| `create_nullifier_pdas`       |      4,540 |      4,540 |
| `apply_output_tree`           |     31,819 |     31,819 |
| `verify_groth16`              |     93,351 |     93,351 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    170,785 |     38,653 |
| `process_instruction`         |    170,838 |          0 |

## 9. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,144 |      1,144 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      1,990 |      1,990 |
| `create_nullifier_pdas`       |     10,425 |     10,425 |
| `apply_output_tree`           |     28,089 |     28,089 |
| `verify_groth16`              |     93,351 |     93,351 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    164,170 |     29,026 |
| `process_instruction`         |    164,223 |          0 |

## 10. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,210 |      1,210 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      1,990 |      1,990 |
| `create_nullifier_pdas`       |     10,425 |     10,425 |
| `apply_output_tree`           |     29,000 |     29,000 |
| `verify_groth16`              |     93,351 |     93,351 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    167,141 |     31,020 |
| `process_instruction`         |    167,194 |          0 |

## 11. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,210 |      1,210 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      3,243 |      3,243 |
| `create_nullifier_pdas`       |     16,310 |     16,310 |
| `apply_output_tree`           |     29,000 |     29,000 |
| `verify_groth16`              |     93,351 |     93,351 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    176,860 |     33,601 |
| `process_instruction`         |    176,913 |          0 |

## 12. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,210 |      1,210 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      4,496 |      4,496 |
| `create_nullifier_pdas`       |     19,195 |     19,195 |
| `apply_output_tree`           |     29,000 |     29,000 |
| `verify_groth16`              |     93,351 |     93,351 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    183,585 |     36,188 |
| `process_instruction`         |    183,638 |          0 |

## 13. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,276 |      1,276 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      4,496 |      4,496 |
| `create_nullifier_pdas`       |     19,195 |     19,195 |
| `apply_output_tree`           |     29,043 |     29,043 |
| `verify_groth16`              |     93,351 |     93,351 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    185,982 |     38,476 |
| `process_instruction`         |    186,035 |          0 |

## 14. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,210 |      1,210 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      5,749 |      5,749 |
| `create_nullifier_pdas`       |     22,080 |     22,080 |
| `apply_output_tree`           |     29,000 |     29,000 |
| `verify_groth16`              |     93,351 |     93,351 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    190,424 |     38,889 |
| `process_instruction`         |    190,477 |          0 |

## 15. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,276 |      1,276 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      5,749 |      5,749 |
| `create_nullifier_pdas`       |     22,080 |     22,080 |
| `apply_output_tree`           |     29,043 |     29,043 |
| `verify_groth16`              |     93,351 |     93,351 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    192,706 |     41,062 |
| `process_instruction`         |    192,759 |          0 |

## 16. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,210 |      1,210 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      1,990 |      1,990 |
| `create_nullifier_pdas`       |      5,925 |      5,925 |
| `apply_output_tree`           |     29,000 |     29,000 |
| `verify_groth16`              |     93,351 |     93,351 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    166,682 |     33,872 |
| `process_instruction`         |    166,735 |          0 |

## 17. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,210 |      1,210 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      1,990 |      1,990 |
| `create_nullifier_pdas`       |      7,425 |      7,425 |
| `apply_output_tree`           |     29,000 |     29,000 |
| `verify_groth16`              |     93,351 |     93,351 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    169,891 |     35,560 |
| `process_instruction`         |    169,944 |          0 |

