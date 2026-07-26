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
| `bench_batch_address_update` |    126,664 |    126,664 |

## 2. Deserialize

| Function                     |   Total CU |     Net CU |
| ---------------------------- | ---------- | ---------- |
| `bench_deserialize`          |         48 |         48 |

## 3. Nullifier insert x1

| Function                     |   Total CU |     Net CU |
| ---------------------------- | ---------- | ---------- |
| `bench_nullifier_insert`     |        588 |        588 |

## 4. Nullifier insert x10

| Function                     |   Total CU |     Net CU |
| ---------------------------- | ---------- | ---------- |
| `bench_nullifier_insert`     |     13,341 |     13,341 |

## 5. Tree init

| Function                     |   Total CU |     Net CU |
| ---------------------------- | ---------- | ---------- |
| `bench_init`                 |        757 |        757 |

## 6. Utxo append x1

| Function                     |   Total CU |     Net CU |
| ---------------------------- | ---------- | ---------- |
| `bench_append`               |     27,881 |     27,881 |

## 7. Utxo append x10

| Function                     |   Total CU |     Net CU |
| ---------------------------- | ---------- | ---------- |
| `bench_append`               |    278,552 |    278,552 |

## 8. Utxo append Batch x10

| Function                     |   Total CU |     Net CU |
| ---------------------------- | ---------- | ---------- |
| `bench_append_batch`         |     34,646 |     34,646 |

