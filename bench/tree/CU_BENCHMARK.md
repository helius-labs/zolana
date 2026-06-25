# Tree -- CU Benchmark

Compute unit profiling for zolana-tree: account init, zero-copy deserialization, UTXO sparse-merkle-tree append, and end-to-end nullifier insert (bloom + hash chain + non-inclusion).

Regenerate with `just bench-tree`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Deserialize](#deserialize)
2. [Nullifier insert x1](#nullifier-insert-x1)
3. [Nullifier insert x10](#nullifier-insert-x10)
4. [Tree init](#tree-init)
5. [Utxo append x1](#utxo-append-x1)
6. [Utxo append x10](#utxo-append-x10)
7. [Utxo append Batch x10](#utxo-append-batch-x10)

## 1. Deserialize

| Function                 |   Total CU |     Net CU |
| ------------------------ | ---------- | ---------- |
| `bench_deserialize`      |         49 |         49 |

## 2. Nullifier insert x1

| Function                 |   Total CU |     Net CU |
| ------------------------ | ---------- | ---------- |
| `bench_nullifier_insert` |        595 |        595 |

## 3. Nullifier insert x10

| Function                 |   Total CU |     Net CU |
| ------------------------ | ---------- | ---------- |
| `bench_nullifier_insert` |     13,402 |     13,402 |

## 4. Tree init

| Function                 |   Total CU |     Net CU |
| ------------------------ | ---------- | ---------- |
| `bench_init`             |        941 |        941 |

## 5. Utxo append x1

| Function                 |   Total CU |     Net CU |
| ------------------------ | ---------- | ---------- |
| `bench_append`           |     22,647 |     22,647 |

## 6. Utxo append x10

| Function                 |   Total CU |     Net CU |
| ------------------------ | ---------- | ---------- |
| `bench_append`           |    226,212 |    226,212 |

## 7. Utxo append Batch x10

| Function                 |   Total CU |     Net CU |
| ------------------------ | ---------- | ---------- |
| `bench_append_batch`     |     29,392 |     29,392 |
