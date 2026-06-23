# Shielded Pool -- CU Benchmark

Compute unit profiling for the shielded-pool deposit instructions, replayed under mollusk from litesvm-built account state: proof-free SOL and SPL shields.

Regenerate with `just bench-shielded-pool`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Deposit sol](#deposit-sol)
2. [Deposit spl](#deposit-spl)

## 1. Deposit sol

| Function          |   Total CU |     Net CU |
| ----------------- | ---------- | ---------- |
| `settle_sol`      |      1,224 |      1,224 |
| `process_deposit` |     32,147 |     30,923 |

## 2. Deposit spl

| Function          |   Total CU |     Net CU |
| ----------------- | ---------- | ---------- |
| `settle_spl`      |      1,195 |      1,195 |
| `process_deposit` |     35,187 |     33,992 |

