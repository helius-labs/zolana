# Shielded Pool -- CU Benchmark

Compute unit profiling for feasible shielded-pool instruction families, replayed under mollusk from litesvm-built account state: protocol creation, tree pause, proof-free SOL/SPL shields, Groth16-proven EdDSA transact shapes covering the narrowest and widest shape of every output count (up to the 1x16 split shape and the 49x2 widest input shape), the 49x2 runtime-authorized `ring_transact` shape, every supported `merge_transact` shape, compact padding on the 2x4 and 49x2 transact shapes and every merge shape, and SOL/SPL withdrawals. This target is a pure benchmark: no CI workflow runs the profiling build, so no CU ceilings are enforced here -- a ceiling that never runs would be unfalsifiable. Regression ceilings live in the fast cross_cutting_cu_budget suite, which pins every proofless instruction family per operation.

Regenerate with `just bench-shielded-pool`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Create protocol config](#create-protocol-config)
2. [Deposit sol](#deposit-sol)
3. [Deposit sol batch 3](#deposit-sol-batch-3)
4. [Deposit spl](#deposit-spl)
5. [Merge 24x1](#merge-24x1)
6. [Merge 24x1 compact 9 sent](#merge-24x1-compact-9-sent)
7. [Merge 52x1](#merge-52x1)
8. [Merge 52x1 compact 25 sent](#merge-52x1-compact-25-sent)
9. [Merge 8x1](#merge-8x1)
10. [Merge 8x1 compact 1 sent](#merge-8x1-compact-1-sent)
11. [Pause tree](#pause-tree)
12. [Transfer eddsa 16x8](#transfer-eddsa-16x8)
13. [Transfer eddsa 1x16](#transfer-eddsa-1x16)
14. [Transfer eddsa 1x2](#transfer-eddsa-1x2)
15. [Transfer eddsa 1x8](#transfer-eddsa-1x8)
16. [Transfer eddsa 24x4](#transfer-eddsa-24x4)
17. [Transfer eddsa 2x2](#transfer-eddsa-2x2)
18. [Transfer eddsa 2x4](#transfer-eddsa-2x4)
19. [Transfer eddsa 2x4 compact](#transfer-eddsa-2x4-compact)
20. [Transfer eddsa 49x2](#transfer-eddsa-49x2)
21. [Transfer eddsa 49x2 compact](#transfer-eddsa-49x2-compact)
22. [Transfer eddsa 4x4](#transfer-eddsa-4x4)
23. [Transfer eddsa 5x4](#transfer-eddsa-5x4)
24. [Transfer eddsa 8x16](#transfer-eddsa-8x16)
25. [Transfer eddsa cached 1 of 32x2](#transfer-eddsa-cached-1-of-32x2)
26. [Transfer eddsa cached 32x2](#transfer-eddsa-cached-32x2)
27. [Transfer eddsa cached 5x4](#transfer-eddsa-cached-5x4)
28. [Transfer ring eddsa 49x2](#transfer-ring-eddsa-49x2)
29. [Transfer ring p256 49x2](#transfer-ring-p256-49x2)
30. [Withdrawal sol](#withdrawal-sol)
31. [Withdrawal spl](#withdrawal-spl)

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

## 5. Merge 24x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     50,930 |     50,930 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    201,648 |     71,182 |

## 6. Merge 24x1 compact 9 sent

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     18,638 |     18,638 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    151,993 |     53,819 |

## 7. Merge 52x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |    108,319 |    108,319 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    293,555 |    105,700 |

## 8. Merge 52x1 compact 25 sent

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     57,405 |     57,405 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    211,331 |     74,390 |

## 9. Merge 8x1

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |     18,321 |     18,321 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    150,293 |     52,436 |

## 10. Merge 8x1 compact 1 sent

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`       |      1,958 |      1,958 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_instruction`         |    125,832 |     44,338 |

## 11. Pause tree

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `process_instruction`         |        254 |        254 |

## 12. Transfer eddsa 16x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |        578 |        578 |
| `create_nullifier_pdas`       |     30,769 |     30,769 |
| `apply_input_trees`           |     43,144 |     12,375 |
| `apply_output_tree`           |     31,971 |     31,971 |
| `public_input_hash`           |     34,749 |     34,749 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    198,131 |          0 |
| `process_instruction`         |    198,183 |          0 |

## 13. Transfer eddsa 1x16

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |      1,122 |      1,122 |
| `create_nullifier_pdas`       |      1,976 |      1,976 |
| `apply_input_trees`           |      3,156 |      1,180 |
| `apply_output_tree`           |     38,361 |     38,361 |
| `public_input_hash`           |     33,200 |     33,200 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    163,627 |      5,290 |
| `process_instruction`         |    163,679 |          0 |

## 14. Transfer eddsa 1x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |        170 |        170 |
| `create_nullifier_pdas`       |      1,976 |      1,976 |
| `apply_input_trees`           |      3,156 |      1,180 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     20,016 |     20,016 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    136,696 |      2,590 |
| `process_instruction`         |    136,748 |          0 |

## 15. Transfer eddsa 1x8

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |        578 |        578 |
| `create_nullifier_pdas`       |      1,976 |      1,976 |
| `apply_input_trees`           |      3,156 |      1,180 |
| `apply_output_tree`           |     31,971 |     31,971 |
| `public_input_hash`           |     26,568 |     26,568 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    148,513 |      3,742 |
| `process_instruction`         |    148,565 |          0 |

## 16. Transfer eddsa 24x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |        306 |        306 |
| `create_nullifier_pdas`       |     47,880 |     47,880 |
| `apply_input_trees`           |     65,148 |     17,268 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     33,161 |     33,161 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    215,461 |          0 |
| `process_instruction`         |    215,513 |          0 |

## 17. Transfer eddsa 2x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |        170 |        170 |
| `create_nullifier_pdas`       |      3,749 |      3,749 |
| `apply_input_trees`           |      5,136 |      1,387 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     21,618 |     21,618 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    140,380 |        919 |
| `process_instruction`         |    140,432 |          0 |

## 18. Transfer eddsa 2x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |        306 |        306 |
| `create_nullifier_pdas`       |      3,749 |      3,749 |
| `apply_input_trees`           |      5,136 |      1,387 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     21,698 |     21,698 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    141,926 |      1,304 |
| `process_instruction`         |    141,978 |          0 |

## 19. Transfer eddsa 2x4 compact

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |        102 |        102 |
| `create_nullifier_pdas`       |      1,976 |      1,976 |
| `apply_input_trees`           |      3,156 |      1,180 |
| `apply_output_tree`           |     28,230 |     28,230 |
| `public_input_hash`           |     21,812 |     21,812 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    138,209 |      2,411 |
| `process_instruction`         |    138,261 |          0 |

## 20. Transfer eddsa 49x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |        170 |        170 |
| `create_nullifier_pdas`       |     98,396 |     98,396 |
| `apply_input_trees`           |    135,400 |     37,004 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     46,182 |     46,182 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    299,514 |          0 |
| `process_instruction`         |    299,566 |          0 |

## 21. Transfer eddsa 49x2 compact

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |        102 |        102 |
| `create_nullifier_pdas`       |      1,976 |      1,976 |
| `apply_input_trees`           |      3,156 |      1,180 |
| `apply_output_tree`           |     28,230 |     28,230 |
| `public_input_hash`           |     22,568 |     22,568 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    139,040 |      2,486 |
| `process_instruction`         |    139,092 |          0 |

## 22. Transfer eddsa 4x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |        306 |        306 |
| `create_nullifier_pdas`       |      7,665 |      7,665 |
| `apply_input_trees`           |     11,084 |      3,419 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     21,737 |     21,737 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    148,114 |          0 |
| `process_instruction`         |    148,166 |          0 |

## 23. Transfer eddsa 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |        306 |        306 |
| `create_nullifier_pdas`       |      9,438 |      9,438 |
| `apply_input_trees`           |     13,064 |      3,626 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     23,333 |     23,333 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    151,796 |          0 |
| `process_instruction`         |    151,848 |          0 |

## 24. Transfer eddsa 8x16

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |      1,122 |      1,122 |
| `create_nullifier_pdas`       |     14,757 |     14,757 |
| `apply_input_trees`           |     20,622 |      5,865 |
| `apply_output_tree`           |     38,361 |     38,361 |
| `public_input_hash`           |     38,072 |     38,072 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    186,689 |          0 |
| `process_instruction`         |    186,741 |          0 |

## 25. Transfer eddsa cached 1 of 32x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |        170 |        170 |
| `create_nullifier_pdas`       |     66,057 |     66,057 |
| `apply_input_trees`           |     89,682 |     23,625 |
| `assign_cached_inputs`        |      2,937 |      2,937 |
| `bind_cached_inputs`          |      2,957 |         20 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     37,889 |     37,889 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    247,436 |          0 |
| `process_instruction`         |    247,488 |          0 |

## 26. Transfer eddsa cached 32x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |        170 |        170 |
| `create_nullifier_pdas`       |     72,596 |     72,596 |
| `apply_input_trees`           |     96,221 |     23,625 |
| `assign_cached_inputs`        |     19,023 |     19,023 |
| `bind_cached_inputs`          |     19,043 |         20 |
| `apply_output_tree`           |     28,266 |     28,266 |
| `public_input_hash`           |     37,889 |     37,889 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    270,061 |          0 |
| `process_instruction`         |    270,113 |          0 |

## 27. Transfer eddsa cached 5x4

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |        306 |        306 |
| `create_nullifier_pdas`       |     15,574 |     15,574 |
| `apply_input_trees`           |     19,048 |      3,474 |
| `assign_cached_inputs`        |      4,038 |      4,038 |
| `bind_cached_inputs`          |      4,058 |         20 |
| `apply_output_tree`           |     29,211 |     29,211 |
| `public_input_hash`           |     23,254 |     23,254 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    162,266 |          0 |
| `process_instruction`         |    162,318 |          0 |

## 28. Transfer ring eddsa 49x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |         46 |         46 |
| `create_nullifier_pdas`       |     98,396 |     98,396 |
| `apply_input_trees`           |    135,400 |     37,004 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     44,667 |     44,667 |
| `verify_groth16`              |     79,504 |     79,504 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    299,846 |          0 |
| `process_instruction`         |    299,898 |          0 |

## 29. Transfer ring p256 49x2

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |         24 |         24 |
| `fill_output_owner_pk_hashes` |         46 |         46 |
| `create_nullifier_pdas`       |     98,396 |     98,396 |
| `apply_input_trees`           |    135,400 |     37,004 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     47,388 |     47,388 |
| `verify_groth16`              |    137,137 |    137,137 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    359,285 |          0 |
| `process_instruction`         |    359,337 |          0 |

## 30. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |        170 |        170 |
| `create_nullifier_pdas`       |      4,478 |      4,478 |
| `apply_input_trees`           |      5,865 |      1,387 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     22,878 |     22,878 |
| `verify_groth16`              |     79,504 |     79,504 |
| `settle_sol`                  |      1,189 |      1,189 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    144,843 |        606 |
| `process_instruction`         |    144,895 |          0 |

## 31. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_owner_signer_hashes`    |        986 |        986 |
| `fill_output_owner_pk_hashes` |        170 |        170 |
| `create_nullifier_pdas`       |      4,119 |      4,119 |
| `apply_input_trees`           |      5,506 |      1,387 |
| `apply_output_tree`           |     29,135 |     29,135 |
| `public_input_hash`           |     22,880 |     22,880 |
| `verify_groth16`              |     79,504 |     79,504 |
| `settle_spl_withdrawal`       |      1,210 |      1,210 |
| `process_instruction`         |         32 |         32 |
| `process_transact_ix`         |    146,127 |      2,585 |
| `process_instruction`         |    146,179 |          0 |

