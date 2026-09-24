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
| `process_instruction`         |      4,525 |      4,525 |

## 2. Deposit sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     37,867 |     36,666 |
| `process_instruction`         |     37,919 |          0 |

## 3. Deposit sol batch 3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     49,631 |     48,430 |
| `process_instruction`         |     49,683 |          0 |

## 4. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl_deposit`          |      1,303 |      1,303 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     39,701 |     38,367 |
| `process_instruction`         |     39,753 |          0 |

## 5. Merge 36x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     72,904 |     72,904 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         31 |         31 |
| `process_instruction`         |    235,929 |     83,490 |

## 6. Merge 8x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     16,842 |     16,842 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         31 |         31 |
| `process_instruction`         |    146,103 |     49,726 |

## 7. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        255 |        255 |

## 8. Transfer eddsa 1x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         92 |         92 |
| `create_nullifier_pdas`       |      1,912 |      1,912 |
| `apply_input_trees`           |      2,963 |      1,051 |
| `apply_output_tree`           |     28,230 |     28,230 |
| `public_input_hash`           |     14,688 |     14,688 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    130,612 |      2,257 |
| `process_instruction`         |    130,665 |          0 |

## 9. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |      1,912 |      1,912 |
| `apply_input_trees`           |      2,963 |      1,051 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     17,894 |     17,894 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    134,107 |      2,444 |
| `process_instruction`         |    134,160 |          0 |

## 10. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        554 |        554 |
| `create_nullifier_pdas`       |      1,912 |      1,912 |
| `apply_input_trees`           |      2,963 |      1,051 |
| `apply_output_tree`           |     31,971 |     31,971 |
| `public_input_hash`           |     24,284 |     24,284 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    145,715 |      3,561 |
| `process_instruction`         |    145,768 |          0 |

## 11. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |      3,632 |      3,632 |
| `apply_input_trees`           |      4,901 |      1,269 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     19,510 |     19,510 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    137,742 |        805 |
| `process_instruction`         |    137,795 |          0 |

## 12. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      3,632 |      3,632 |
| `apply_input_trees`           |      4,901 |      1,269 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     19,518 |     19,518 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    138,912 |        992 |
| `process_instruction`         |    138,965 |          0 |

## 13. Transfer eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |     69,672 |     69,672 |
| `apply_input_trees`           |     95,877 |     26,205 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     37,267 |     37,267 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    249,061 |          0 |
| `process_instruction`         |    249,114 |          0 |

## 14. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      5,352 |      5,352 |
| `apply_input_trees`           |      6,835 |      1,483 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     19,521 |     19,521 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    140,926 |          0 |
| `process_instruction`         |    140,979 |          0 |

## 15. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      7,435 |      7,435 |
| `apply_input_trees`           |     10,748 |      3,313 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     19,524 |     19,524 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    144,915 |          0 |
| `process_instruction`         |    144,968 |          0 |

## 16. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |      7,435 |      7,435 |
| `apply_input_trees`           |     10,748 |      3,313 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     19,524 |     19,524 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    145,204 |          0 |
| `process_instruction`         |    145,257 |          0 |

## 17. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      9,155 |      9,155 |
| `apply_input_trees`           |     12,681 |      3,526 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     21,132 |     21,132 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    148,534 |          0 |
| `process_instruction`         |    148,587 |          0 |

## 18. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |      9,155 |      9,155 |
| `apply_input_trees`           |     12,681 |      3,526 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     21,132 |     21,132 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    148,823 |          0 |
| `process_instruction`         |    148,876 |          0 |

## 19. Transfer ring eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `create_nullifier_pdas`       |     69,672 |     69,672 |
| `apply_input_trees`           |     95,877 |     26,205 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     37,267 |     37,267 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    250,946 |          0 |
| `process_instruction`         |    250,999 |          0 |

## 20. Transfer ring p256 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `create_nullifier_pdas`       |     69,672 |     69,672 |
| `apply_input_trees`           |     95,877 |     26,205 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     40,869 |     40,869 |
| `verify_groth16`              |    137,144 |    137,144 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    312,245 |          0 |
| `process_instruction`         |    312,298 |          0 |

## 21. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      4,351 |      4,351 |
| `apply_input_trees`           |      5,620 |      1,269 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     20,781 |     20,781 |
| `verify_groth16`              |     79,504 |     79,504 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    142,492 |        686 |
| `process_instruction`         |    142,545 |          0 |

## 22. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      3,632 |      3,632 |
| `apply_input_trees`           |      4,901 |      1,269 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     20,783 |     20,783 |
| `verify_groth16`              |     79,504 |     79,504 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    143,411 |      3,020 |
| `process_instruction`         |    143,464 |          0 |

