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
| `process_deposit`             |     40,158 |     38,903 |
| `process_instruction`         |     40,208 |         50 |

## 2. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl`                  |      1,195 |      1,195 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     39,510 |     38,284 |
| `process_instruction`         |     39,560 |         50 |

## 3. Transfer

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      1,888 |      1,888 |
| `fill_output_owner_pk_hashes` |      2,797 |      2,797 |
| `apply_tree`                  |     31,620 |     31,620 |
| `verify_groth16`              |     93,346 |     93,346 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    160,795 |     31,113 |
| `process_instruction`         |    160,845 |         50 |

## 4. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      1,888 |      1,888 |
| `fill_output_owner_pk_hashes` |      2,797 |      2,797 |
| `apply_tree`                  |     31,620 |     31,620 |
| `verify_groth16`              |     93,346 |     93,346 |
| `settle_sol`                  |      1,243 |      1,243 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    164,807 |     33,882 |
| `process_instruction`         |    164,857 |         50 |

## 5. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      1,888 |      1,888 |
| `fill_output_owner_pk_hashes` |      2,797 |      2,797 |
| `apply_tree`                  |     31,620 |     31,620 |
| `verify_groth16`              |     93,346 |     93,346 |
| `settle_spl`                  |      1,208 |      1,208 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    165,414 |     34,524 |
| `process_instruction`         |    165,464 |         50 |

