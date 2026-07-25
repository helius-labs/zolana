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
| `process_deposit`     |     39,814 |     38,559 |
| `process_instruction` |     39,864 |         50 |

## 2. Deposit sol batch 3

| Function              |   Total CU |     Net CU |
| --------------------- | ---------- | ---------- |
| `settle_sol`          |      1,224 |      1,224 |
| `process_instruction` |         31 |         31 |
| `process_deposit`     |     49,822 |     48,567 |
| `process_instruction` |     49,872 |         50 |

## 3. Deposit spl

| Function              |   Total CU |     Net CU |
| --------------------- | ---------- | ---------- |
| `settle_spl`          |      1,195 |      1,195 |
| `process_instruction` |         31 |         31 |
| `process_deposit`     |     39,573 |     38,347 |
| `process_instruction` |     39,623 |         50 |

