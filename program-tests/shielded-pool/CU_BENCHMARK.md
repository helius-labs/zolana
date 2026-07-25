# Shielded Pool -- CU Benchmark

Compute unit profiling for the shielded-pool deposit and transact instructions, replayed under mollusk from litesvm-built account state: proof-free SOL and SPL shields, plus Groth16-proven (2,3) eddsa transact shapes -- a shielded transfer and SOL/SPL withdrawals.

Regenerate with `just bench-shielded-pool`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Deposit sol](#deposit-sol)
2. [Deposit sol batch 3](#deposit-sol-batch-3)
3. [Deposit spl](#deposit-spl)
4. [Transfer](#transfer)
5. [Withdrawal sol](#withdrawal-sol)
6. [Withdrawal spl](#withdrawal-spl)

## 1. Deposit sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,224 |      1,224 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     39,073 |     37,818 |
| `process_instruction`         |     39,123 |         50 |

## 2. Deposit sol batch 3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,224 |      1,224 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     48,987 |     47,732 |
| `process_instruction`         |     49,037 |         50 |

## 3. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl`                  |      1,195 |      1,195 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     38,831 |     37,605 |
| `process_instruction`         |     38,881 |         50 |

## 4. Transfer

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      1,875 |      1,875 |
| `fill_output_owner_pk_hashes` |      2,732 |      2,732 |
| `apply_tree`                  |     31,696 |     31,696 |
| `verify_groth16`              |     93,350 |     93,350 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    159,658 |     29,974 |
| `process_instruction`         |    159,708 |         50 |

## 5. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      1,875 |      1,875 |
| `fill_output_owner_pk_hashes` |      2,732 |      2,732 |
| `apply_tree`                  |     31,696 |     31,696 |
| `verify_groth16`              |     93,350 |     93,350 |
| `settle_sol`                  |      1,243 |      1,243 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    164,506 |     33,579 |
| `process_instruction`         |    164,556 |         50 |

## 6. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      1,875 |      1,875 |
| `fill_output_owner_pk_hashes` |      2,732 |      2,732 |
| `apply_tree`                  |     31,696 |     31,696 |
| `verify_groth16`              |     93,350 |     93,350 |
| `settle_spl`                  |      1,208 |      1,208 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    164,761 |     33,869 |
| `process_instruction`         |    164,811 |         50 |

