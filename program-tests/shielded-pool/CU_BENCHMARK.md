# Shielded Pool -- CU Benchmark

Compute unit profiling for the shielded-pool deposit and transact instructions, replayed under mollusk from litesvm-built account state: proof-free SOL and SPL shields, plus Groth16-proven (2,3) eddsa transact shapes -- a shielded transfer and SOL/SPL withdrawals.

Regenerate with `just bench-shielded-pool`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Deposit sol](#deposit-sol)
2. [Deposit spl](#deposit-spl)
3. [Transfer](#transfer)
4. [Withdrawal sol](#withdrawal-sol)
5. [Withdrawal spl](#withdrawal-spl)

## 1. Deposit sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,224 |      1,224 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     40,043 |     38,788 |
| `process_instruction`         |     40,093 |         50 |

## 2. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl`                  |      1,195 |      1,195 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     41,086 |     39,860 |
| `process_instruction`         |     41,136 |         50 |

## 3. Transfer

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      2,811 |      2,811 |
| `fill_output_owner_pk_hashes` |      4,160 |      4,160 |
| `apply_tree`                  |     31,602 |     31,602 |
| `verify_groth16`              |     93,350 |     93,350 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    161,102 |     29,148 |
| `process_instruction`         |    161,152 |         50 |

## 4. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      2,811 |      2,811 |
| `fill_output_owner_pk_hashes` |      4,160 |      4,160 |
| `apply_tree`                  |     31,602 |     31,602 |
| `verify_groth16`              |     93,350 |     93,350 |
| `settle_sol`                  |      1,243 |      1,243 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    165,885 |     32,688 |
| `process_instruction`         |    165,935 |         50 |

## 5. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      2,811 |      2,811 |
| `fill_output_owner_pk_hashes` |      4,160 |      4,160 |
| `apply_tree`                  |     31,602 |     31,602 |
| `verify_groth16`              |     93,350 |     93,350 |
| `settle_spl`                  |      1,208 |      1,208 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    167,297 |     34,135 |
| `process_instruction`         |    167,347 |         50 |

