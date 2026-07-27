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

## 1. Deposit sol

| Function              |   Total CU |     Net CU |
| --------------------- | ---------- | ---------- |
| `settle_sol`          |      1,224 |      1,224 |
| `process_instruction` |         31 |         31 |
| `process_deposit`     |     38,411 |     37,156 |
| `process_instruction` |     38,461 |         50 |

## 2. Deposit sol batch 3

| Function              |   Total CU |     Net CU |
| --------------------- | ---------- | ---------- |
| `settle_sol`          |      1,224 |      1,224 |
| `process_instruction` |         31 |         31 |
| `process_deposit`     |     49,915 |     48,660 |
| `process_instruction` |     49,965 |         50 |

## 3. Deposit spl

| Function              |   Total CU |     Net CU |
| --------------------- | ---------- | ---------- |
| `settle_spl_deposit`  |      1,249 |      1,249 |
| `process_instruction` |         31 |         31 |
| `process_deposit`     |     39,310 |     38,030 |
| `process_instruction` |     39,360 |         50 |

