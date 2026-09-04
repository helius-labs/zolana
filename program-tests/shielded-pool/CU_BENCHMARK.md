# Shielded Pool -- CU Benchmark

Compute unit profiling for feasible shielded-pool instruction families, replayed under mollusk from litesvm-built account state: protocol creation, tree pause, proof-free SOL/SPL shields, all eleven Groth16-proven EdDSA transact shapes (including the 1x8 split shape and the 36x2 consolidation shape, the widest that fits a transaction v1), that same 36x2 consolidation shape on both policy-ring `ring_transact` rails (EdDSA, and P256 -- whose BSB22 commitment adds a Pedersen proof-of-knowledge pairing to verification), both supported `merge_transact` shapes (8x1 and 36x1), and SOL/SPL withdrawals. This target is a pure benchmark: no CI workflow runs the profiling build, so no CU ceilings are enforced here -- a ceiling that never runs would be unfalsifiable. Regression ceilings live in the fast cross_cutting_cu_budget suite, which pins every proofless instruction family per operation.

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
19. [Transfer p256 ring 36x2](#transfer-p256-ring-36x2)
20. [Transfer ring 36x2](#transfer-ring-36x2)
21. [Withdrawal sol](#withdrawal-sol)
22. [Withdrawal spl](#withdrawal-spl)

## 1. Create protocol config

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `process_instruction`      |      4,694 |      4,694 |

## 2. Deposit sol

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `settle_sol`               |      1,170 |      1,170 |
| `process_instruction`      |         32 |         32 |
| `process_deposit`          |     38,588 |     37,386 |
| `process_instruction`      |     38,638 |          0 |

## 3. Deposit sol batch 3

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `settle_sol`               |      1,170 |      1,170 |
| `process_instruction`      |         32 |         32 |
| `process_deposit`          |     50,348 |     49,146 |
| `process_instruction`      |     50,398 |          0 |

## 4. Deposit spl

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `settle_spl_deposit`       |      1,277 |      1,277 |
| `process_instruction`      |         32 |         32 |
| `process_deposit`          |     39,448 |     38,139 |
| `process_instruction`      |     39,498 |          0 |

## 5. Merge 36x1

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`    |    146,081 |    146,081 |
| `verify_groth16`           |     93,351 |     93,351 |
| `process_instruction`      |         32 |         32 |
| `process_instruction`      |    423,577 |    184,113 |

## 6. Merge 8x1

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`    |     38,273 |     38,273 |
| `verify_groth16`           |     93,351 |     93,351 |
| `process_instruction`      |         32 |         32 |
| `process_instruction`      |    201,046 |     69,390 |

## 7. Pause tree

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `process_instruction`      |        240 |        240 |

## 8. Transfer eddsa 1x1

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      1,212 |      1,212 |
| `fill_owner_signer_hashes` |        113 |        113 |
| `apply_input_tree`         |        752 |        752 |
| `create_nullifier_pdas`    |      4,571 |      4,571 |
| `apply_output_tree`        |     28,157 |     28,157 |
| `verify_groth16`           |     93,351 |     93,351 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    149,882 |     21,694 |
| `process_instruction`      |    149,934 |          0 |

## 9. Transfer eddsa 1x2

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      2,200 |      2,200 |
| `fill_owner_signer_hashes` |        113 |        113 |
| `apply_input_tree`         |        752 |        752 |
| `create_nullifier_pdas`    |      4,571 |      4,571 |
| `apply_output_tree`        |     28,269 |     28,269 |
| `verify_groth16`           |     93,351 |     93,351 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    152,117 |     22,829 |
| `process_instruction`      |    152,169 |          0 |

## 10. Transfer eddsa 1x8

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      8,128 |      8,128 |
| `fill_owner_signer_hashes` |        113 |        113 |
| `apply_input_tree`         |        752 |        752 |
| `create_nullifier_pdas`    |      4,571 |      4,571 |
| `apply_output_tree`        |     32,444 |     32,444 |
| `verify_groth16`           |     93,351 |     93,351 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    169,025 |     29,634 |
| `process_instruction`      |    169,077 |          0 |

## 11. Transfer eddsa 2x2

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      2,200 |      2,200 |
| `fill_owner_signer_hashes` |        113 |        113 |
| `apply_input_tree`         |      3,671 |      3,671 |
| `create_nullifier_pdas`    |     10,457 |     10,457 |
| `apply_output_tree`        |     28,269 |     28,269 |
| `verify_groth16`           |     93,351 |     93,351 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    161,922 |     23,829 |
| `process_instruction`      |    161,974 |          0 |

## 12. Transfer eddsa 2x3

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      3,188 |      3,188 |
| `fill_owner_signer_hashes` |        113 |        113 |
| `apply_input_tree`         |      3,671 |      3,671 |
| `create_nullifier_pdas`    |     10,457 |     10,457 |
| `apply_output_tree`        |     29,258 |     29,258 |
| `verify_groth16`           |     93,351 |     93,351 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    165,034 |     24,964 |
| `process_instruction`      |    165,086 |          0 |

## 13. Transfer eddsa 36x2

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      2,200 |      2,200 |
| `fill_owner_signer_hashes` |        113 |        113 |
| `apply_input_tree`         |    102,917 |    102,917 |
| `create_nullifier_pdas`    |    159,581 |    159,581 |
| `apply_output_tree`        |     28,269 |     28,269 |
| `verify_groth16`           |     93,351 |     93,351 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    444,294 |     57,831 |
| `process_instruction`      |    444,346 |          0 |

## 14. Transfer eddsa 3x3

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      3,188 |      3,188 |
| `fill_owner_signer_hashes` |        113 |        113 |
| `apply_input_tree`         |      6,590 |      6,590 |
| `create_nullifier_pdas`    |     16,343 |     16,343 |
| `apply_output_tree`        |     29,258 |     29,258 |
| `verify_groth16`           |     93,351 |     93,351 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    174,840 |     25,965 |
| `process_instruction`      |    174,892 |          0 |

## 15. Transfer eddsa 4x3

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      3,188 |      3,188 |
| `fill_owner_signer_hashes` |        113 |        113 |
| `apply_input_tree`         |      9,509 |      9,509 |
| `create_nullifier_pdas`    |     19,229 |     19,229 |
| `apply_output_tree`        |     29,258 |     29,258 |
| `verify_groth16`           |     93,351 |     93,351 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    181,642 |     26,962 |
| `process_instruction`      |    181,694 |          0 |

## 16. Transfer eddsa 4x4

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      4,176 |      4,176 |
| `fill_owner_signer_hashes` |        113 |        113 |
| `apply_input_tree`         |      9,509 |      9,509 |
| `create_nullifier_pdas`    |     19,229 |     19,229 |
| `apply_output_tree`        |     29,370 |     29,370 |
| `verify_groth16`           |     93,351 |     93,351 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    183,877 |     28,097 |
| `process_instruction`      |    183,929 |          0 |

## 17. Transfer eddsa 5x3

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      3,188 |      3,188 |
| `fill_owner_signer_hashes` |        113 |        113 |
| `apply_input_tree`         |     12,428 |     12,428 |
| `create_nullifier_pdas`    |     22,115 |     22,115 |
| `apply_output_tree`        |     29,258 |     29,258 |
| `verify_groth16`           |     93,351 |     93,351 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    188,449 |     27,964 |
| `process_instruction`      |    188,501 |          0 |

## 18. Transfer eddsa 5x4

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      4,176 |      4,176 |
| `fill_owner_signer_hashes` |        113 |        113 |
| `apply_input_tree`         |     12,428 |     12,428 |
| `create_nullifier_pdas`    |     22,115 |     22,115 |
| `apply_output_tree`        |     29,370 |     29,370 |
| `verify_groth16`           |     93,351 |     93,351 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    190,684 |     29,099 |
| `process_instruction`      |    190,736 |          0 |

## 19. Transfer p256 ring 36x2

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      1,115 |      1,115 |
| `fill_owner_signer_hashes` |      1,092 |      1,092 |
| `apply_input_tree`         |    102,917 |    102,917 |
| `create_nullifier_pdas`    |    167,081 |    167,081 |
| `apply_output_tree`        |     29,147 |     29,147 |
| `verify_groth16`           |    224,586 |    224,586 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    588,770 |     62,800 |
| `process_instruction`      |    588,823 |          0 |

## 20. Transfer ring 36x2

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      1,115 |      1,115 |
| `fill_owner_signer_hashes` |      1,092 |      1,092 |
| `apply_input_tree`         |    102,989 |    102,989 |
| `create_nullifier_pdas`    |    159,581 |    159,581 |
| `apply_output_tree`        |     29,147 |     29,147 |
| `verify_groth16`           |     93,351 |     93,351 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    446,259 |     58,952 |
| `process_instruction`      |    446,312 |          0 |

## 21. Withdrawal sol

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      3,188 |      3,188 |
| `fill_owner_signer_hashes` |        113 |        113 |
| `apply_input_tree`         |      3,671 |      3,671 |
| `create_nullifier_pdas`    |      5,957 |      5,957 |
| `apply_output_tree`        |     29,259 |     29,259 |
| `verify_groth16`           |     93,351 |     93,351 |
| `settle_sol`               |      1,189 |      1,189 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    164,458 |     27,698 |
| `process_instruction`      |    164,510 |          0 |

## 22. Withdrawal spl

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      3,188 |      3,188 |
| `fill_owner_signer_hashes` |        113 |        113 |
| `apply_input_tree`         |      3,671 |      3,671 |
| `create_nullifier_pdas`    |      5,957 |      5,957 |
| `apply_output_tree`        |     29,259 |     29,259 |
| `verify_groth16`           |     93,351 |     93,351 |
| `settle_spl_withdrawal`    |      1,210 |      1,210 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    166,124 |     29,343 |
| `process_instruction`      |    166,176 |          0 |

