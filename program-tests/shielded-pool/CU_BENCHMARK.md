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
| `process_deposit`             |     38,344 |     37,142 |
| `process_instruction`         |     38,395 |          0 |

## 3. Deposit sol batch 3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     50,257 |     49,055 |
| `process_instruction`         |     50,308 |          0 |

## 4. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl_deposit`          |      1,303 |      1,303 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     40,179 |     38,844 |
| `process_instruction`         |     40,230 |          0 |

## 5. Merge 36x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     79,716 |     79,716 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    242,057 |     82,786 |

## 6. Merge 8x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     17,100 |     17,100 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    146,372 |     49,717 |

## 7. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        256 |        256 |

## 8. Transfer eddsa 1x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |        987 |        987 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_trees`           |        919 |        919 |
| `create_nullifier_pdas`       |      1,887 |      1,887 |
| `apply_output_tree`           |     28,230 |     28,230 |
| `public_input_hash`           |     14,851 |     14,851 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    131,116 |      4,573 |
| `process_instruction`         |    131,169 |          0 |

## 9. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,053 |      1,053 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_trees`           |        919 |        919 |
| `create_nullifier_pdas`       |      1,887 |      1,887 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     18,042 |     18,042 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    134,596 |      4,760 |
| `process_instruction`         |    134,649 |          0 |

## 10. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,449 |      1,449 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_trees`           |        919 |        919 |
| `create_nullifier_pdas`       |      1,887 |      1,887 |
| `apply_output_tree`           |     31,971 |     31,971 |
| `public_input_hash`           |     24,419 |     24,419 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    146,191 |      5,877 |
| `process_instruction`         |    146,244 |          0 |

## 11. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,053 |      1,053 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_trees`           |      1,157 |      1,157 |
| `create_nullifier_pdas`       |      3,965 |      3,965 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     19,635 |     19,635 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    138,599 |      4,854 |
| `process_instruction`         |    138,652 |          0 |

## 12. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,119 |      1,119 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_trees`           |      1,157 |      1,157 |
| `create_nullifier_pdas`       |      3,965 |      3,965 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     19,653 |     19,653 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    139,779 |      5,041 |
| `process_instruction`         |    139,832 |          0 |

## 13. Transfer eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,053 |      1,053 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_trees`           |     26,825 |     26,825 |
| `create_nullifier_pdas`       |     73,985 |     73,985 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     37,314 |     37,314 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    254,790 |      7,678 |
| `process_instruction`         |    254,843 |          0 |

## 14. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,119 |      1,119 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_trees`           |      1,388 |      1,388 |
| `create_nullifier_pdas`       |      5,676 |      5,676 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     19,666 |     19,666 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    141,818 |      5,125 |
| `process_instruction`         |    141,871 |          0 |

## 15. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,119 |      1,119 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_trees`           |      3,248 |      3,248 |
| `create_nullifier_pdas`       |      7,387 |      7,387 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     19,676 |     19,676 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    145,479 |      5,205 |
| `process_instruction`         |    145,532 |          0 |

## 16. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,185 |      1,185 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_trees`           |      3,248 |      3,248 |
| `create_nullifier_pdas`       |      7,387 |      7,387 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     19,685 |     19,685 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    145,777 |      5,392 |
| `process_instruction`         |    145,830 |          0 |

## 17. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,119 |      1,119 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_trees`           |      3,479 |      3,479 |
| `create_nullifier_pdas`       |      9,461 |      9,461 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     21,259 |     21,259 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    149,452 |      5,290 |
| `process_instruction`         |    149,505 |          0 |

## 18. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,185 |      1,185 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_trees`           |      3,479 |      3,479 |
| `create_nullifier_pdas`       |      9,461 |      9,461 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     21,268 |     21,268 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    149,750 |      5,477 |
| `process_instruction`         |    149,803 |          0 |

## 19. Transfer ring eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `fill_owner_signer_hashes`    |      1,013 |      1,013 |
| `apply_input_trees`           |     26,825 |     26,825 |
| `create_nullifier_pdas`       |     72,554 |     72,554 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     37,314 |     37,314 |
| `verify_groth16`              |     79,523 |     79,523 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    255,179 |      8,745 |
| `process_instruction`         |    255,232 |          0 |

## 20. Transfer ring p256 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `fill_owner_signer_hashes`    |      1,013 |      1,013 |
| `apply_input_trees`           |     26,825 |     26,825 |
| `create_nullifier_pdas`       |     72,917 |     72,917 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     40,911 |     40,911 |
| `verify_groth16`              |    210,724 |    210,724 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    390,397 |      8,802 |
| `process_instruction`         |    390,450 |          0 |

## 21. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,119 |      1,119 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_trees`           |      1,157 |      1,157 |
| `create_nullifier_pdas`       |      3,602 |      3,602 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     21,674 |     21,674 |
| `verify_groth16`              |     79,523 |     79,523 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    143,035 |      5,454 |
| `process_instruction`         |    143,088 |          0 |

## 22. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      1,119 |      1,119 |
| `fill_owner_signer_hashes`    |        114 |        114 |
| `apply_input_trees`           |      1,157 |      1,157 |
| `create_nullifier_pdas`       |      4,677 |      4,677 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     21,677 |     21,677 |
| `verify_groth16`              |     79,523 |     79,523 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    145,749 |      7,069 |
| `process_instruction`         |    145,802 |          0 |

