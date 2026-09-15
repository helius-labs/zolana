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
4. [Deposit sol batch 3 with data](#deposit-sol-batch-3-with-data)
5. [Deposit sol with data](#deposit-sol-with-data)
6. [Deposit spl](#deposit-spl)
7. [Deposit spl with data](#deposit-spl-with-data)
8. [Merge 36x1](#merge-36x1)
9. [Merge 8x1](#merge-8x1)
10. [Pause tree](#pause-tree)
11. [Transfer eddsa 1x1](#transfer-eddsa-1x1)
12. [Transfer eddsa 1x2](#transfer-eddsa-1x2)
13. [Transfer eddsa 1x8](#transfer-eddsa-1x8)
14. [Transfer eddsa 2x2](#transfer-eddsa-2x2)
15. [Transfer eddsa 2x3](#transfer-eddsa-2x3)
16. [Transfer eddsa 36x2](#transfer-eddsa-36x2)
17. [Transfer eddsa 3x3](#transfer-eddsa-3x3)
18. [Transfer eddsa 4x3](#transfer-eddsa-4x3)
19. [Transfer eddsa 4x4](#transfer-eddsa-4x4)
20. [Transfer eddsa 5x3](#transfer-eddsa-5x3)
21. [Transfer eddsa 5x4](#transfer-eddsa-5x4)
22. [Transfer ring eddsa 36x2](#transfer-ring-eddsa-36x2)
23. [Transfer ring p256 36x2](#transfer-ring-p256-36x2)
24. [Withdrawal sol](#withdrawal-sol)
25. [Withdrawal spl](#withdrawal-spl)

## 1. Create protocol config

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |      4,525 |      4,525 |

## 2. Deposit sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     37,873 |     36,672 |
| `process_instruction`         |     37,925 |          0 |

## 3. Deposit sol batch 3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     49,607 |     48,406 |
| `process_instruction`         |     49,659 |          0 |

## 4. Deposit sol batch 3 with data

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     51,945 |     50,744 |
| `process_instruction`         |     51,997 |          0 |

## 5. Deposit sol with data

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     39,800 |     38,599 |
| `process_instruction`         |     39,852 |          0 |

## 6. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl_deposit`          |      1,303 |      1,303 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     39,708 |     38,374 |
| `process_instruction`         |     39,760 |          0 |

## 7. Deposit spl with data

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl_deposit`          |      1,303 |      1,303 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     41,635 |     40,301 |
| `process_instruction`         |     41,687 |          0 |

## 8. Merge 36x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     71,843 |     71,843 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         31 |         31 |
| `process_instruction`         |    234,196 |     82,799 |

## 9. Merge 8x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     19,327 |     19,327 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         31 |         31 |
| `process_instruction`         |    148,594 |     49,713 |

## 10. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        255 |        255 |

## 11. Transfer eddsa 1x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         92 |         92 |
| `create_nullifier_pdas`       |      1,912 |      1,912 |
| `apply_input_trees`           |      2,944 |      1,032 |
| `apply_output_tree`           |     28,230 |     28,230 |
| `public_input_hash`           |     14,784 |     14,784 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    130,708 |      2,257 |
| `process_instruction`         |    130,761 |          0 |

## 12. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |      1,912 |      1,912 |
| `apply_input_trees`           |      2,944 |      1,032 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     17,990 |     17,990 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    134,203 |      2,444 |
| `process_instruction`         |    134,256 |          0 |

## 13. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        554 |        554 |
| `create_nullifier_pdas`       |      1,912 |      1,912 |
| `apply_input_trees`           |      2,944 |      1,032 |
| `apply_output_tree`           |     31,971 |     31,971 |
| `public_input_hash`           |     24,380 |     24,380 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    145,811 |      3,561 |
| `process_instruction`         |    145,864 |          0 |

## 14. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |      3,632 |      3,632 |
| `apply_input_trees`           |      4,882 |      1,250 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     19,606 |     19,606 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    137,838 |        805 |
| `process_instruction`         |    137,891 |          0 |

## 15. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      3,632 |      3,632 |
| `apply_input_trees`           |      4,882 |      1,250 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     19,614 |     19,614 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    139,008 |        992 |
| `process_instruction`         |    139,061 |          0 |

## 16. Transfer eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |     69,672 |     69,672 |
| `apply_input_trees`           |     95,858 |     26,186 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     37,363 |     37,363 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    249,157 |          0 |
| `process_instruction`         |    249,210 |          0 |

## 17. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      5,352 |      5,352 |
| `apply_input_trees`           |      6,816 |      1,464 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     19,617 |     19,617 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    141,022 |          0 |
| `process_instruction`         |    141,075 |          0 |

## 18. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      7,435 |      7,435 |
| `apply_input_trees`           |     10,729 |      3,294 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     19,620 |     19,620 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    145,011 |          0 |
| `process_instruction`         |    145,064 |          0 |

## 19. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |      7,435 |      7,435 |
| `apply_input_trees`           |     10,729 |      3,294 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     19,620 |     19,620 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    145,300 |          0 |
| `process_instruction`         |    145,353 |          0 |

## 20. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      9,155 |      9,155 |
| `apply_input_trees`           |     12,662 |      3,507 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     21,228 |     21,228 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    148,630 |          0 |
| `process_instruction`         |    148,683 |          0 |

## 21. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |      9,155 |      9,155 |
| `apply_input_trees`           |     12,662 |      3,507 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     21,228 |     21,228 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    148,919 |          0 |
| `process_instruction`         |    148,972 |          0 |

## 22. Transfer ring eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `create_nullifier_pdas`       |     69,672 |     69,672 |
| `apply_input_trees`           |     95,858 |     26,186 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     37,363 |     37,363 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    251,042 |          0 |
| `process_instruction`         |    251,095 |          0 |

## 23. Transfer ring p256 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `create_nullifier_pdas`       |     69,672 |     69,672 |
| `apply_input_trees`           |     95,858 |     26,186 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     40,965 |     40,965 |
| `verify_groth16`              |    210,790 |    210,790 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    385,968 |          0 |
| `process_instruction`         |    386,021 |          0 |

## 24. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      3,632 |      3,632 |
| `apply_input_trees`           |      4,882 |      1,250 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     21,635 |     21,635 |
| `verify_groth16`              |     79,523 |     79,523 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    142,627 |      1,405 |
| `process_instruction`         |    142,680 |          0 |

## 25. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      5,063 |      5,063 |
| `apply_input_trees`           |      6,313 |      1,250 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     21,638 |     21,638 |
| `verify_groth16`              |     79,523 |     79,523 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    145,697 |      1,589 |
| `process_instruction`         |    145,750 |          0 |

