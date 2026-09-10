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
| `process_instruction`         |      5,068 |      5,068 |

## 2. Deposit sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     39,838 |     38,636 |
| `process_instruction`         |     39,889 |          0 |

## 3. Deposit sol batch 3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     53,340 |     52,138 |
| `process_instruction`         |     53,391 |          0 |

## 4. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl_deposit`          |      1,303 |      1,303 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     40,726 |     39,391 |
| `process_instruction`         |     40,777 |          0 |

## 5. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        255 |        255 |

## 6. Transfer eddsa 1x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |        997 |        997 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |        763 |        763 |
| `create_nullifier_pdas`       |      3,047 |      3,047 |
| `apply_output_tree`           |     28,244 |     28,244 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    151,859 |     25,305 |
| `process_instruction`         |    151,912 |          0 |

## 7. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,063 |      1,063 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |        763 |        763 |
| `create_nullifier_pdas`       |      3,047 |      3,047 |
| `apply_output_tree`           |     28,280 |     28,280 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    154,086 |     27,430 |
| `process_instruction`         |    154,139 |          0 |

## 8. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,459 |      1,459 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |        763 |        763 |
| `create_nullifier_pdas`       |      3,047 |      3,047 |
| `apply_output_tree`           |     31,985 |     31,985 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    170,201 |     39,444 |
| `process_instruction`         |    170,254 |          0 |

## 9. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,063 |      1,063 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      1,788 |      1,788 |
| `create_nullifier_pdas`       |      7,430 |      7,430 |
| `apply_output_tree`           |     28,280 |     28,280 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    160,441 |     28,377 |
| `process_instruction`         |    160,494 |          0 |

## 10. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      1,788 |      1,788 |
| `create_nullifier_pdas`       |      7,430 |      7,430 |
| `apply_output_tree`           |     29,189 |     29,189 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    163,402 |     30,363 |
| `process_instruction`         |    163,455 |          0 |

## 11. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      2,813 |      2,813 |
| `create_nullifier_pdas`       |     10,313 |     10,313 |
| `apply_output_tree`           |     29,189 |     29,189 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    168,244 |     31,297 |
| `process_instruction`         |    168,297 |          0 |

## 12. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      3,838 |      3,838 |
| `create_nullifier_pdas`       |     13,196 |     13,196 |
| `apply_output_tree`           |     29,189 |     29,189 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    173,092 |     32,237 |
| `process_instruction`         |    173,145 |          0 |

## 13. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,195 |      1,195 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      3,838 |      3,838 |
| `create_nullifier_pdas`       |     13,196 |     13,196 |
| `apply_output_tree`           |     29,225 |     29,225 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    175,295 |     34,338 |
| `process_instruction`         |    175,348 |          0 |

## 14. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      4,863 |      4,863 |
| `create_nullifier_pdas`       |     17,579 |     17,579 |
| `apply_output_tree`           |     29,189 |     29,189 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    179,554 |     33,291 |
| `process_instruction`         |    179,607 |          0 |

## 15. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,195 |      1,195 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      4,863 |      4,863 |
| `create_nullifier_pdas`       |     17,579 |     17,579 |
| `apply_output_tree`           |     29,225 |     29,225 |
| `verify_groth16`              |     93,356 |     93,356 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    181,642 |     35,277 |
| `process_instruction`         |    181,695 |          0 |

## 16. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,129 |      1,129 |
| `fill_owner_signer_hashes`    |        115 |        115 |
| `apply_input_tree`            |      1,788 |      1,788 |
| `create_nullifier_pdas`       |      8,930 |      8,930 |
| `apply_output_tree`           |     29,187 |     29,187 |
| `verify_groth16`              |     93,356 |     93,356 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    168,610 |     32,884 |
| `process_instruction`         |    168,663 |          0 |

## 17. Withdrawal spl

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
| `process_transact_ix`         |    167,284 |     34,537 |
| `process_instruction`         |    167,337 |          0 |

