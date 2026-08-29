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
| `process_instruction`         |      4,465 |      4,465 |

## 2. Deposit sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     38,352 |     37,151 |
| `process_instruction`         |     38,403 |          0 |

## 3. Deposit sol batch 3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     49,740 |     48,539 |
| `process_instruction`         |     49,791 |          0 |

## 4. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl_deposit`          |      1,277 |      1,277 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     39,206 |     37,898 |
| `process_instruction`         |     39,257 |          0 |

## 5. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        191 |        191 |

## 6. Transfer eddsa 1x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,078 |      1,078 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      1,137 |      1,137 |
| `create_nullifier_pdas`       |      8,643 |      8,643 |
| `apply_output_tree`           |     28,010 |     28,010 |
| `verify_groth16`              |     93,351 |     93,351 |
| `fund_nullifier_pdas`         |         49 |         49 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    156,595 |     24,182 |
| `process_instruction`         |    156,648 |          0 |

## 7. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,144 |      1,144 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      1,137 |      1,137 |
| `create_nullifier_pdas`       |      8,643 |      8,643 |
| `apply_output_tree`           |     28,053 |     28,053 |
| `verify_groth16`              |     93,351 |     93,351 |
| `fund_nullifier_pdas`         |         49 |         49 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    158,804 |     26,282 |
| `process_instruction`         |    158,857 |          0 |

## 8. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,540 |      1,540 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      1,137 |      1,137 |
| `create_nullifier_pdas`       |      8,643 |      8,643 |
| `apply_output_tree`           |     31,783 |     31,783 |
| `verify_groth16`              |     93,351 |     93,351 |
| `fund_nullifier_pdas`         |         49 |         49 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    175,073 |     38,425 |
| `process_instruction`         |    175,126 |          0 |

## 9. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,144 |      1,144 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      2,721 |      2,721 |
| `create_nullifier_pdas`       |     12,622 |     12,622 |
| `apply_output_tree`           |     28,053 |     28,053 |
| `verify_groth16`              |     93,351 |     93,351 |
| `fund_nullifier_pdas`         |         89 |         89 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    166,971 |     28,846 |
| `process_instruction`         |    167,024 |          0 |

## 10. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,210 |      1,210 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      2,721 |      2,721 |
| `create_nullifier_pdas`       |     12,622 |     12,622 |
| `apply_output_tree`           |     28,964 |     28,964 |
| `verify_groth16`              |     93,351 |     93,351 |
| `fund_nullifier_pdas`         |         89 |         89 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    169,926 |     30,824 |
| `process_instruction`         |    169,979 |          0 |

## 11. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,210 |      1,210 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      4,305 |      4,305 |
| `create_nullifier_pdas`       |     16,601 |     16,601 |
| `apply_output_tree`           |     28,964 |     28,964 |
| `verify_groth16`              |     93,351 |     93,351 |
| `fund_nullifier_pdas`         |        129 |        129 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    178,086 |     33,381 |
| `process_instruction`         |    178,139 |          0 |

## 12. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,210 |      1,210 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      5,889 |      5,889 |
| `create_nullifier_pdas`       |     20,580 |     20,580 |
| `apply_output_tree`           |     28,964 |     28,964 |
| `verify_groth16`              |     93,351 |     93,351 |
| `fund_nullifier_pdas`         |        169 |        169 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    186,252 |     35,944 |
| `process_instruction`         |    186,305 |          0 |

## 13. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,276 |      1,276 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      5,889 |      5,889 |
| `create_nullifier_pdas`       |     20,580 |     20,580 |
| `apply_output_tree`           |     29,007 |     29,007 |
| `verify_groth16`              |     93,351 |     93,351 |
| `fund_nullifier_pdas`         |        169 |        169 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    188,633 |     38,216 |
| `process_instruction`         |    188,686 |          0 |

## 14. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,210 |      1,210 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      7,473 |      7,473 |
| `create_nullifier_pdas`       |     24,559 |     24,559 |
| `apply_output_tree`           |     28,964 |     28,964 |
| `verify_groth16`              |     93,351 |     93,351 |
| `fund_nullifier_pdas`         |        209 |        209 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    194,532 |     38,621 |
| `process_instruction`         |    194,585 |          0 |

## 15. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,276 |      1,276 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      7,473 |      7,473 |
| `create_nullifier_pdas`       |     24,559 |     24,559 |
| `apply_output_tree`           |     29,007 |     29,007 |
| `verify_groth16`              |     93,351 |     93,351 |
| `fund_nullifier_pdas`         |        209 |        209 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    196,798 |     40,778 |
| `process_instruction`         |    196,851 |          0 |

## 16. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,210 |      1,210 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      2,721 |      2,721 |
| `create_nullifier_pdas`       |      8,122 |      8,122 |
| `apply_output_tree`           |     28,964 |     28,964 |
| `verify_groth16`              |     93,351 |     93,351 |
| `settle_sol`                  |      1,189 |      1,189 |
| `fund_nullifier_pdas`         |         89 |         89 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    169,467 |     33,676 |
| `process_instruction`         |    169,520 |          0 |

## 17. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,210 |      1,210 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_tree`            |      2,721 |      2,721 |
| `create_nullifier_pdas`       |      8,122 |      8,122 |
| `apply_output_tree`           |     28,964 |     28,964 |
| `verify_groth16`              |     93,351 |     93,351 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `fund_nullifier_pdas`         |         89 |         89 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    171,168 |     35,356 |
| `process_instruction`         |    171,221 |          0 |

