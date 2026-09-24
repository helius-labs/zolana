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
| `process_deposit`             |     37,868 |     36,666 |
| `process_instruction`         |     37,919 |          0 |

## 3. Deposit sol batch 3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,170 |      1,170 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     49,632 |     48,430 |
| `process_instruction`         |     49,683 |          0 |

## 4. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl_deposit`          |      1,303 |      1,303 |
| `process_instruction`         |         32 |         32 |
| `process_deposit`             |     39,702 |     38,367 |
| `process_instruction`         |     39,753 |          0 |

## 5. Merge 36x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     76,802 |     76,802 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    238,934 |     82,596 |

## 6. Merge 8x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     17,041 |     17,041 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    146,314 |     49,737 |

## 7. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        254 |        254 |

## 8. Transfer eddsa 1x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         92 |         92 |
| `create_nullifier_pdas`       |      1,935 |      1,935 |
| `apply_input_trees`           |      3,041 |      1,106 |
| `apply_output_tree`           |     28,230 |     28,230 |
| `public_input_hash`           |     16,419 |     16,419 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    132,666 |      2,478 |
| `process_instruction`         |    132,719 |          0 |

## 9. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |      1,935 |      1,935 |
| `apply_input_trees`           |      3,041 |      1,106 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     19,625 |     19,625 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    136,161 |      2,665 |
| `process_instruction`         |    136,214 |          0 |

## 10. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        554 |        554 |
| `create_nullifier_pdas`       |      1,935 |      1,935 |
| `apply_input_trees`           |      3,041 |      1,106 |
| `apply_output_tree`           |     31,971 |     31,971 |
| `public_input_hash`           |     26,015 |     26,015 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    147,769 |      3,782 |
| `process_instruction`         |    147,822 |          0 |

## 11. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |      3,678 |      3,678 |
| `apply_input_trees`           |      5,002 |      1,324 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     21,240 |     21,240 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    139,816 |      1,001 |
| `process_instruction`         |    139,869 |          0 |

## 12. Transfer eddsa 2x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      3,678 |      3,678 |
| `apply_input_trees`           |      5,002 |      1,324 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     21,248 |     21,248 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    140,986 |      1,188 |
| `process_instruction`         |    141,039 |          0 |

## 13. Transfer eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |     70,611 |     70,611 |
| `apply_input_trees`           |     96,871 |     26,260 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     38,997 |     38,997 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    251,995 |          0 |
| `process_instruction`         |    252,048 |          0 |

## 14. Transfer eddsa 3x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      5,421 |      5,421 |
| `apply_input_trees`           |      6,959 |      1,538 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     21,251 |     21,251 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    143,023 |          0 |
| `process_instruction`         |    143,076 |          0 |

## 15. Transfer eddsa 4x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      7,534 |      7,534 |
| `apply_input_trees`           |     10,902 |      3,368 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     21,255 |     21,255 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    147,041 |          0 |
| `process_instruction`         |    147,094 |          0 |

## 16. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |      7,534 |      7,534 |
| `apply_input_trees`           |     10,902 |      3,368 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     21,255 |     21,255 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    147,330 |          0 |
| `process_instruction`         |    147,383 |          0 |

## 17. Transfer eddsa 5x3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      9,277 |      9,277 |
| `apply_input_trees`           |     12,858 |      3,581 |
| `apply_output_tree`           |     29,175 |     29,175 |
| `public_input_hash`           |     22,862 |     22,862 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    150,681 |          0 |
| `process_instruction`         |    150,734 |          0 |

## 18. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |      9,277 |      9,277 |
| `apply_input_trees`           |     12,858 |      3,581 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     22,862 |     22,862 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    150,970 |          0 |
| `process_instruction`         |    151,023 |          0 |

## 19. Transfer eddsa cached 1 of 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |     73,527 |     73,527 |
| `apply_input_trees`           |     99,635 |     26,108 |
| `assign_cached_inputs`        |      2,983 |      2,983 |
| `bind_cached_inputs`          |      3,003 |         20 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     38,918 |     38,918 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    258,053 |          0 |
| `process_instruction`         |    258,106 |          0 |

## 20. Transfer eddsa cached 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        158 |        158 |
| `create_nullifier_pdas`       |     73,897 |     73,897 |
| `apply_input_trees`           |    100,005 |     26,108 |
| `assign_cached_inputs`        |     20,459 |     20,459 |
| `bind_cached_inputs`          |     20,479 |         20 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     38,918 |     38,918 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    275,899 |          0 |
| `process_instruction`         |    275,952 |          0 |

## 21. Transfer eddsa cached 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        290 |        290 |
| `create_nullifier_pdas`       |      9,277 |      9,277 |
| `apply_input_trees`           |     12,706 |      3,429 |
| `assign_cached_inputs`        |      4,003 |      4,003 |
| `bind_cached_inputs`          |      4,023 |         20 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     22,783 |     22,783 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    155,132 |          0 |
| `process_instruction`         |    155,185 |          0 |

## 22. Transfer ring eddsa 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `create_nullifier_pdas`       |     70,981 |     70,981 |
| `apply_input_trees`           |     97,241 |     26,260 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     38,997 |     38,997 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    254,246 |          0 |
| `process_instruction`         |    254,299 |          0 |

## 23. Transfer ring p256 36x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |         38 |         38 |
| `create_nullifier_pdas`       |     70,611 |     70,611 |
| `apply_input_trees`           |     96,871 |     26,260 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     42,581 |     42,581 |
| `verify_groth16`              |    137,141 |    137,141 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    315,158 |          0 |
| `process_instruction`         |    315,211 |          0 |

## 24. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      3,678 |      3,678 |
| `apply_input_trees`           |      5,002 |      1,324 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     22,502 |     22,502 |
| `verify_groth16`              |     79,504 |     79,504 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    143,839 |      1,602 |
| `process_instruction`         |    143,892 |          0 |

## 25. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        935 |        935 |
| `fill_output_owner_pk_hashes` |        224 |        224 |
| `create_nullifier_pdas`       |      4,048 |      4,048 |
| `apply_input_trees`           |      5,372 |      1,324 |
| `apply_output_tree`           |     29,171 |     29,171 |
| `public_input_hash`           |     22,504 |     22,504 |
| `verify_groth16`              |     79,504 |     79,504 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    145,861 |      2,861 |
| `process_instruction`         |    145,914 |          0 |

