# Shielded Pool -- CU Benchmark

Compute unit profiling for feasible shielded-pool instruction families, replayed under mollusk from litesvm-built account state: protocol creation, tree pause, proof-free SOL/SPL shields, all ten Groth16-proven EdDSA transact shapes (including the 1x8 split shape), and SOL/SPL withdrawals. Each proof-bearing replay has an enforced ceiling; the fast cu_budget_contract separately pins every proofless administration variant.

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
| `process_instruction`         |      5,448 |      5,448 |

## 2. Deposit sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     38,307 |     37,106 |
| `process_instruction`         |     38,357 |          0 |

## 3. Deposit sol batch 3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     49,807 |     48,606 |
| `process_instruction`         |     49,857 |          0 |

## 4. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl_deposit`          |      1,277 |      1,277 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     39,290 |     37,982 |
| `process_instruction`         |     39,340 |          0 |

## 5. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        190 |        190 |

## 6. Transfer eddsa 1x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |        988 |        988 |
| `fill_output_owner_pk_hashes` |        970 |        970 |
| `apply_input_tree`            |      1,363 |      1,363 |
| `apply_output_tree`           |     27,913 |     27,913 |
| `verify_groth16`              |     93,292 |     93,292 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    153,111 |     28,554 |
| `process_instruction`         |    153,162 |          0 |

## 7. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |        988 |        988 |
| `fill_output_owner_pk_hashes` |      1,926 |      1,926 |
| `apply_input_tree`            |      1,363 |      1,363 |
| `apply_output_tree`           |     27,958 |     27,958 |
| `verify_groth16`              |     93,292 |     93,292 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    156,209 |     30,651 |
| `process_instruction`         |    156,260 |          0 |

## 8. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |        988 |        988 |
| `fill_output_owner_pk_hashes` |      7,664 |      7,664 |
| `apply_input_tree`            |      1,363 |      1,363 |
| `apply_output_tree`           |     31,696 |     31,696 |
| `verify_groth16`              |     93,292 |     93,292 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    177,810 |     42,776 |
| `process_instruction`         |    177,861 |          0 |

## 9. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      1,961 |      1,961 |
| `fill_output_owner_pk_hashes` |      1,926 |      1,926 |
| `apply_input_tree`            |      3,387 |      3,387 |
| `apply_output_tree`           |     27,958 |     27,958 |
| `verify_groth16`              |     93,292 |     93,292 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    162,577 |     34,022 |
| `process_instruction`         |    162,628 |          0 |

## 10. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      1,961 |      1,961 |
| `fill_output_owner_pk_hashes` |      2,882 |      2,882 |
| `apply_input_tree`            |      3,387 |      3,387 |
| `apply_output_tree`           |     28,870 |     28,870 |
| `verify_groth16`              |     93,292 |     93,292 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    166,420 |     35,997 |
| `process_instruction`         |    166,471 |          0 |

## 11. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      2,934 |      2,934 |
| `fill_output_owner_pk_hashes` |      2,882 |      2,882 |
| `apply_input_tree`            |      5,411 |      5,411 |
| `apply_output_tree`           |     28,870 |     28,870 |
| `verify_groth16`              |     93,292 |     93,292 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    172,784 |     39,364 |
| `process_instruction`         |    172,835 |          0 |

## 12. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      3,907 |      3,907 |
| `fill_output_owner_pk_hashes` |      2,882 |      2,882 |
| `apply_input_tree`            |      7,435 |      7,435 |
| `apply_output_tree`           |     28,870 |     28,870 |
| `verify_groth16`              |     93,292 |     93,292 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    179,150 |     42,733 |
| `process_instruction`         |    179,201 |          0 |

## 13. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      3,907 |      3,907 |
| `fill_output_owner_pk_hashes` |      3,838 |      3,838 |
| `apply_input_tree`            |      7,435 |      7,435 |
| `apply_output_tree`           |     28,915 |     28,915 |
| `verify_groth16`              |     93,292 |     93,292 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    182,420 |     45,002 |
| `process_instruction`         |    182,471 |          0 |

## 14. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      4,880 |      4,880 |
| `fill_output_owner_pk_hashes` |      2,882 |      2,882 |
| `apply_input_tree`            |      9,459 |      9,459 |
| `apply_output_tree`           |     28,870 |     28,870 |
| `verify_groth16`              |     93,292 |     93,292 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    185,633 |     46,219 |
| `process_instruction`         |    185,684 |          0 |

## 15. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      4,880 |      4,880 |
| `fill_output_owner_pk_hashes` |      3,838 |      3,838 |
| `apply_input_tree`            |      9,459 |      9,459 |
| `apply_output_tree`           |     28,915 |     28,915 |
| `verify_groth16`              |     93,292 |     93,292 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    188,788 |     48,373 |
| `process_instruction`         |    188,839 |          0 |

## 16. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      1,961 |      1,961 |
| `fill_output_owner_pk_hashes` |      2,882 |      2,882 |
| `apply_input_tree`            |      3,387 |      3,387 |
| `apply_output_tree`           |     28,870 |     28,870 |
| `verify_groth16`              |     93,292 |     93,292 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    169,733 |     38,121 |
| `process_instruction`         |    169,784 |          0 |

## 17. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      1,961 |      1,961 |
| `fill_output_owner_pk_hashes` |      2,882 |      2,882 |
| `apply_input_tree`            |      3,387 |      3,387 |
| `apply_output_tree`           |     28,870 |     28,870 |
| `verify_groth16`              |     93,292 |     93,292 |
| `settle_spl_withdrawal`       |      1,209 |      1,209 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    171,435 |     39,803 |
| `process_instruction`         |    171,486 |          0 |

