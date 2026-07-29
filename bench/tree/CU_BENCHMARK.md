# Tree -- CU Benchmark

Compute unit profiling for zolana-tree: account init, zero-copy deserialization, UTXO sparse-merkle-tree append, end-to-end nullifier insert (bloom + hash chain + non-inclusion), and the worst-case address-tree batch update that finalizes 120 cached tree updates in one transaction.

See `CU_BENCHMARK_NOTES.md` for analysis notes (e.g. why nullifier insert x10 is not 10x x1, and the proof-verify vs cascade-apply split of the batch update).

Regenerate with `just bench-tree`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Address tree batch update x120](#address-tree-batch-update-x120)
2. [Deserialize](#deserialize)
3. [Nullifier insert x1](#nullifier-insert-x1)
4. [Nullifier insert x10](#nullifier-insert-x10)
5. [Tree init](#tree-init)
6. [Utxo append x1](#utxo-append-x1)
7. [Utxo append x10](#utxo-append-x10)
8. [Utxo append Batch x10](#utxo-append-batch-x10)

## 1. Address tree batch update x120

| Function                     |   Total CU |     Net CU |
| ---------------------------- | ---------- | ---------- |
| `apply_cached_tree_updates`  |     33,063 |     33,063 |
| `bench_batch_address_update` |    129,097 |     96,034 |

## 2. Deserialize

| Function                     |   Total CU |     Net CU |
| ---------------------------- | ---------- | ---------- |
| `bench_deserialize`          |         66 |         66 |

## 3. Nullifier insert x1

| Function                     |   Total CU |     Net CU |
| ---------------------------- | ---------- | ---------- |
| `bench_nullifier_insert`     |        877 |        877 |

## 4. Nullifier insert x10

| Function                     |   Total CU |     Net CU |
| ---------------------------- | ---------- | ---------- |
| `bench_nullifier_insert`     |     16,240 |     16,240 |

## 5. Tree init

| Function                     |   Total CU |     Net CU |
| ---------------------------- | ---------- | ---------- |
| `bench_init`                 |        244 |        244 |

## 6. Utxo append x1

| Function                     |   Total CU |     Net CU |
| ---------------------------- | ---------- | ---------- |
| `bench_append`               |     27,849 |     27,849 |

## 7. Utxo append x10

| Function                     |   Total CU |     Net CU |
| ---------------------------- | ---------- | ---------- |
| `bench_append`               |    278,241 |    278,241 |

## 8. Utxo append Batch x10

| Function                     |   Total CU |     Net CU |
| ---------------------------- | ---------- | ---------- |
| `bench_append_batch`         |     34,405 |     34,405 |

