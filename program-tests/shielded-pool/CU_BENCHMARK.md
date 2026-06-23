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

| Function              |   Total CU |     Net CU |
| --------------------- | ---------- | ---------- |
| `settle_sol`          |      1,224 |      1,224 |
| `process_instruction` |         36 |         36 |
| `process_deposit`     |     33,280 |     32,020 |
| `process_instruction` |     33,336 |         56 |

## 2. Deposit spl

| Function              |   Total CU |     Net CU |
| --------------------- | ---------- | ---------- |
| `settle_spl`          |      1,195 |      1,195 |
| `process_instruction` |         36 |         36 |
| `process_deposit`     |     33,957 |     32,726 |
| `process_instruction` |     34,013 |         56 |

## 3. Transfer

| Function              |   Total CU |     Net CU |
| --------------------- | ---------- | ---------- |
| `check_input_signers` |      1,845 |      1,845 |
| `apply_tree`          |     26,364 |     26,364 |
| `verify_groth16`      |     93,344 |     93,344 |
| `process_instruction` |         36 |         36 |
| `process_transact_ix` |    147,784 |     26,195 |
| `process_instruction` |    147,839 |         55 |

## 4. Withdrawal sol

| Function              |   Total CU |     Net CU |
| --------------------- | ---------- | ---------- |
| `check_input_signers` |      1,845 |      1,845 |
| `apply_tree`          |     26,364 |     26,364 |
| `verify_groth16`      |     93,344 |     93,344 |
| `settle_sol`          |      1,243 |      1,243 |
| `process_instruction` |         36 |         36 |
| `process_transact_ix` |    150,758 |     27,926 |
| `process_instruction` |    150,813 |         55 |

## 5. Withdrawal spl

| Function              |   Total CU |     Net CU |
| --------------------- | ---------- | ---------- |
| `check_input_signers` |      1,845 |      1,845 |
| `apply_tree`          |     26,364 |     26,364 |
| `verify_groth16`      |     93,344 |     93,344 |
| `settle_spl`          |      1,208 |      1,208 |
| `process_instruction` |         36 |         36 |
| `process_transact_ix` |    152,328 |     29,531 |
| `process_instruction` |    152,383 |         55 |

