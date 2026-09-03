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
| `process_instruction`      |      4,691 |      4,691 |

## 2. Deposit sol

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `settle_sol`               |      1,170 |      1,170 |
| `process_instruction`      |         32 |         32 |
| `process_deposit`          |     38,687 |     37,485 |
| `process_instruction`      |     38,738 |          0 |

## 3. Deposit sol batch 3

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `settle_sol`               |      1,170 |      1,170 |
| `process_instruction`      |         32 |         32 |
| `process_deposit`          |     50,204 |     49,002 |
| `process_instruction`      |     50,255 |          0 |

## 4. Deposit spl

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `settle_spl_deposit`       |      1,303 |      1,303 |
| `process_instruction`      |         32 |         32 |
| `process_deposit`          |     39,578 |     38,243 |
| `process_instruction`      |     39,629 |          0 |

## 5. Merge 36x1

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`    |    178,657 |    178,657 |
| `verify_groth16`           |     93,356 |     93,356 |
| `process_instruction`      |         32 |         32 |
| `process_instruction`      |    445,044 |    172,999 |

## 6. Merge 8x1

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `create_nullifier_pdas`    |     34,009 |     34,009 |
| `verify_groth16`           |     93,356 |     93,356 |
| `process_instruction`      |         32 |         32 |
| `process_instruction`      |    199,669 |     72,272 |

## 7. Pause tree

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `process_instruction`      |        243 |        243 |

## 8. Transfer eddsa 1x1

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      1,160 |      1,160 |
| `fill_owner_signer_hashes` |        111 |        111 |
| `apply_input_tree`         |        718 |        718 |
| `create_nullifier_pdas`    |      4,597 |      4,597 |
| `apply_output_tree`        |     28,066 |     28,066 |
| `verify_groth16`           |     93,356 |     93,356 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    149,827 |     21,787 |
| `process_instruction`      |    149,879 |          0 |

## 9. Transfer eddsa 1x2

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      2,078 |      2,078 |
| `fill_owner_signer_hashes` |        111 |        111 |
| `apply_input_tree`         |        718 |        718 |
| `create_nullifier_pdas`    |      4,597 |      4,597 |
| `apply_output_tree`        |     28,099 |     28,099 |
| `verify_groth16`           |     93,356 |     93,356 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    151,819 |     22,828 |
| `process_instruction`      |    151,871 |          0 |

## 10. Transfer eddsa 1x8

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      7,586 |      7,586 |
| `fill_owner_signer_hashes` |        111 |        111 |
| `apply_input_tree`         |        718 |        718 |
| `create_nullifier_pdas`    |      4,597 |      4,597 |
| `apply_output_tree`        |     31,806 |     31,806 |
| `verify_groth16`           |     93,356 |     93,356 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    167,275 |     29,069 |
| `process_instruction`      |    167,327 |          0 |

## 11. Transfer eddsa 2x2

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      2,078 |      2,078 |
| `fill_owner_signer_hashes` |        111 |        111 |
| `apply_input_tree`         |      3,615 |      3,615 |
| `create_nullifier_pdas`    |     10,513 |     10,513 |
| `apply_output_tree`        |     28,099 |     28,099 |
| `verify_groth16`           |     93,356 |     93,356 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    161,534 |     23,730 |
| `process_instruction`      |    161,586 |          0 |

## 12. Transfer eddsa 2x3

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      2,996 |      2,996 |
| `fill_owner_signer_hashes` |        111 |        111 |
| `apply_input_tree`         |      3,615 |      3,615 |
| `create_nullifier_pdas`    |     10,513 |     10,513 |
| `apply_output_tree`        |     29,011 |     29,011 |
| `verify_groth16`           |     93,356 |     93,356 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    164,405 |     24,771 |
| `process_instruction`      |    164,457 |          0 |

## 13. Transfer eddsa 36x2

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      2,078 |      2,078 |
| `fill_owner_signer_hashes` |        111 |        111 |
| `apply_input_tree`         |    101,841 |    101,841 |
| `create_nullifier_pdas`    |    160,657 |    160,657 |
| `apply_output_tree`        |     28,099 |     28,099 |
| `verify_groth16`           |     93,356 |     93,356 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    440,574 |     54,400 |
| `process_instruction`      |    440,626 |          0 |

## 14. Transfer eddsa 3x3

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      2,996 |      2,996 |
| `fill_owner_signer_hashes` |        111 |        111 |
| `apply_input_tree`         |      6,504 |      6,504 |
| `create_nullifier_pdas`    |     16,429 |     16,429 |
| `apply_output_tree`        |     29,011 |     29,011 |
| `verify_groth16`           |     93,356 |     93,356 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    174,113 |     25,674 |
| `process_instruction`      |    174,165 |          0 |

## 15. Transfer eddsa 4x3

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      2,996 |      2,996 |
| `fill_owner_signer_hashes` |        111 |        111 |
| `apply_input_tree`         |      9,393 |      9,393 |
| `create_nullifier_pdas`    |     19,345 |     19,345 |
| `apply_output_tree`        |     29,011 |     29,011 |
| `verify_groth16`           |     93,356 |     93,356 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    180,817 |     26,573 |
| `process_instruction`      |    180,869 |          0 |

## 16. Transfer eddsa 4x4

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      3,914 |      3,914 |
| `fill_owner_signer_hashes` |        111 |        111 |
| `apply_input_tree`         |      9,393 |      9,393 |
| `create_nullifier_pdas`    |     19,345 |     19,345 |
| `apply_output_tree`        |     29,044 |     29,044 |
| `verify_groth16`           |     93,356 |     93,356 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    182,809 |     27,614 |
| `process_instruction`      |    182,861 |          0 |

## 17. Transfer eddsa 5x3

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      2,996 |      2,996 |
| `fill_owner_signer_hashes` |        111 |        111 |
| `apply_input_tree`         |     12,282 |     12,282 |
| `create_nullifier_pdas`    |     22,261 |     22,261 |
| `apply_output_tree`        |     29,011 |     29,011 |
| `verify_groth16`           |     93,356 |     93,356 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    187,526 |     27,477 |
| `process_instruction`      |    187,578 |          0 |

## 18. Transfer eddsa 5x4

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      3,914 |      3,914 |
| `fill_owner_signer_hashes` |        111 |        111 |
| `apply_input_tree`         |     12,282 |     12,282 |
| `create_nullifier_pdas`    |     22,261 |     22,261 |
| `apply_output_tree`        |     29,044 |     29,044 |
| `verify_groth16`           |     93,356 |     93,356 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    189,518 |     28,518 |
| `process_instruction`      |    189,570 |          0 |

## 19. Transfer p256 ring 36x2

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |        994 |        994 |
| `fill_owner_signer_hashes` |      1,090 |      1,090 |
| `apply_input_tree`         |    101,841 |    101,841 |
| `create_nullifier_pdas`    |    168,157 |    168,157 |
| `apply_output_tree`        |     28,979 |     28,979 |
| `verify_groth16`           |    224,595 |    224,595 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    584,962 |     59,274 |
| `process_instruction`      |    585,015 |          0 |

## 20. Transfer ring 36x2

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |        993 |        993 |
| `fill_owner_signer_hashes` |      1,090 |      1,090 |
| `apply_input_tree`         |    101,841 |    101,841 |
| `create_nullifier_pdas`    |    159,157 |    159,157 |
| `apply_output_tree`        |     28,979 |     28,979 |
| `verify_groth16`           |     93,356 |     93,356 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    440,917 |     55,469 |
| `process_instruction`      |    440,970 |          0 |

## 21. Withdrawal sol

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      2,996 |      2,996 |
| `fill_owner_signer_hashes` |        111 |        111 |
| `apply_input_tree`         |      3,615 |      3,615 |
| `create_nullifier_pdas`    |      6,013 |      6,013 |
| `apply_output_tree`        |     29,012 |     29,012 |
| `verify_groth16`           |     93,356 |     93,356 |
| `settle_sol`               |      1,189 |      1,189 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    163,645 |     27,321 |
| `process_instruction`      |    163,697 |          0 |

## 22. Withdrawal spl

| Function                   |   Total CU |     Net CU |
| -------------------------- | ---------- | ---------- |
| `fill_output_owner_chain`  |      2,996 |      2,996 |
| `fill_owner_signer_hashes` |        111 |        111 |
| `apply_input_tree`         |      3,615 |      3,615 |
| `create_nullifier_pdas`    |      6,013 |      6,013 |
| `apply_output_tree`        |     29,012 |     29,012 |
| `verify_groth16`           |     93,356 |     93,356 |
| `settle_spl_withdrawal`    |      1,210 |      1,210 |
| `process_instruction`      |         32 |         32 |
| `process_transact_ix`      |    165,490 |     29,145 |
| `process_instruction`      |    165,542 |          0 |

