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
19. [Transfer eddsa cached 1 of 36x2](#transfer-eddsa-cached-1-of-36x2)
20. [Transfer eddsa cached 36x2](#transfer-eddsa-cached-36x2)
21. [Transfer eddsa cached 5x4](#transfer-eddsa-cached-5x4)
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
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     37,849 |     36,647 |
| `process_instruction`         |     37,900 |          0 |

## 3. Deposit sol batch 3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     49,561 |     48,359 |
| `process_instruction`         |     49,612 |          0 |

## 4. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl_deposit`          |      1,303 |      1,303 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     39,683 |     38,348 |
| `process_instruction`         |     39,734 |          0 |

## 5. Merge 36x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     72,802 |     72,802 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    234,693 |     82,355 |

## 6. Merge 8x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     16,866 |     16,866 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    147,366 |     50,964 |

## 7. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        254 |        254 |

## 8. Transfer eddsa 1x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         92 |         92 |
| `create_nullifier_pdas`       |      1,975 |      1,975 |
| `apply_input_trees`           |      3,088 |      1,113 |
| `apply_output_tree`           |     28,230 |     28,230 |
| `public_input_hash`           |     16,419 |     16,419 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    132,760 |      2,485 |
| `process_instruction`         |    132,813 |          0 |

## 9. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |      1,975 |      1,975 |
| `apply_input_trees`           |      3,088 |      1,113 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     19,625 |     19,625 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    136,255 |      2,672 |
| `process_instruction`         |    136,308 |          0 |

## 10. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        554 |        554 |
| `create_nullifier_pdas`       |      1,975 |      1,975 |
| `apply_input_trees`           |      3,088 |      1,113 |
| `apply_output_tree`           |     31,971 |     31,971 |
| `public_input_hash`           |     26,015 |     26,015 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    147,863 |      3,789 |
| `process_instruction`         |    147,916 |          0 |

## 11. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |      3,747 |      3,747 |
| `apply_input_trees`           |      5,069 |      1,322 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     21,240 |     21,240 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    139,929 |        978 |
| `process_instruction`         |    139,982 |          0 |

## 12. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      3,747 |      3,747 |
| `apply_input_trees`           |      5,069 |      1,322 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     21,248 |     21,248 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    141,099 |      1,165 |
| `process_instruction`         |    141,152 |          0 |

## 13. Transfer eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |     71,666 |     71,666 |
| `apply_input_trees`           |     97,788 |     26,122 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     38,997 |     38,997 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    253,094 |          0 |
| `process_instruction`         |    253,147 |          0 |

## 14. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      5,519 |      5,519 |
| `apply_input_trees`           |      7,051 |      1,532 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     21,251 |     21,251 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    143,165 |          0 |
| `process_instruction`         |    143,218 |          0 |

## 15. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      7,661 |      7,661 |
| `apply_input_trees`           |     11,019 |      3,358 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     21,255 |     21,255 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    147,212 |          0 |
| `process_instruction`         |    147,265 |          0 |

## 16. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |      7,661 |      7,661 |
| `apply_input_trees`           |     11,019 |      3,358 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     21,255 |     21,255 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    147,501 |          0 |
| `process_instruction`         |    147,554 |          0 |

## 17. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      9,433 |      9,433 |
| `apply_input_trees`           |     13,000 |      3,567 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     22,862 |     22,862 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    150,881 |          0 |
| `process_instruction`         |    150,934 |          0 |

## 18. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |      9,433 |      9,433 |
| `apply_input_trees`           |     13,000 |      3,567 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     22,862 |     22,862 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    151,170 |          0 |
| `process_instruction`         |    151,223 |          0 |

## 19. Transfer eddsa cached 1 of 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |     74,582 |     74,582 |
| `apply_input_trees`           |    100,552 |     25,970 |
| `assign_cached_inputs`        |      2,983 |      2,983 |
| `bind_cached_inputs`          |      3,003 |         20 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     38,918 |     38,918 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    259,152 |          0 |
| `process_instruction`         |    259,205 |          0 |

## 20. Transfer eddsa cached 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |     77,443 |     77,443 |
| `apply_input_trees`           |    103,413 |     25,970 |
| `assign_cached_inputs`        |     20,459 |     20,459 |
| `bind_cached_inputs`          |     20,479 |         20 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     38,918 |     38,918 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    279,489 |          0 |
| `process_instruction`         |    279,542 |          0 |

## 21. Transfer eddsa cached 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |     12,708 |     12,708 |
| `apply_input_trees`           |     16,123 |      3,415 |
| `assign_cached_inputs`        |      4,003 |      4,003 |
| `bind_cached_inputs`          |      4,023 |         20 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     22,783 |     22,783 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    158,607 |          0 |
| `process_instruction`         |    158,660 |          0 |

## 22. Transfer ring eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `create_nullifier_pdas`       |     72,036 |     72,036 |
| `apply_input_trees`           |     98,158 |     26,122 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     38,997 |     38,997 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    255,345 |          0 |
| `process_instruction`         |    255,398 |          0 |

## 23. Transfer ring p256 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `create_nullifier_pdas`       |     71,666 |     71,666 |
| `apply_input_trees`           |     97,788 |     26,122 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     42,603 |     42,603 |
| `verify_groth16`              |    137,138 |    137,138 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    316,276 |          0 |
| `process_instruction`         |    316,329 |          0 |

## 24. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      3,747 |      3,747 |
| `apply_input_trees`           |      5,069 |      1,322 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     22,504 |     22,504 |
| `verify_groth16`              |     79,504 |     79,504 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    143,954 |      1,579 |
| `process_instruction`         |    144,007 |          0 |

## 25. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      3,747 |      3,747 |
| `apply_input_trees`           |      5,069 |      1,322 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     22,506 |     22,506 |
| `verify_groth16`              |     79,504 |     79,504 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    145,606 |      3,208 |
| `process_instruction`         |    145,659 |          0 |

