# Bloom Filter -- CU Benchmark

Compute unit profiling for light-bloom-filter insert and contains, using the state and address batched-merkle-tree defaults (num hashes and bloom filter capacity).

Regenerate with `just bench-bloom-filter`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Address 1 insertion](#address-1-insertion)
2. [Address 10 insertions](#address-10-insertions)

## 1. Address 1 insertion

| Function              |   Total CU |     Net CU |
| --------------------- | ---------- | ---------- |
| `bench_insert`        |        300 |        300 |
| `bench_contains_hit`  |        248 |        248 |
| `bench_contains_miss` |        140 |        140 |

## 2. Address 10 insertions

| Function              |   Total CU |     Net CU |
| --------------------- | ---------- | ---------- |
| `bench_insert`        |      2,874 |      2,874 |
| `bench_contains_hit`  |      2,381 |      2,381 |
| `bench_contains_miss` |      1,328 |      1,328 |

