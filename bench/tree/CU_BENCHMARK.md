# Tree -- CU Benchmark

Compute unit profiling for zolana-tree: account init, zero-copy deserialization, UTXO sparse-merkle-tree append, and end-to-end nullifier insert (bloom + hash chain + non-inclusion).

See `CU_BENCHMARK_NOTES.md` for analysis notes (e.g. why nullifier insert x10 is not 10x x1).

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

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `apply_cached_changelog_updates` |     36,429 |     36,429 |
| `bench_batch_address_update`     |    132,722 |     96,293 |

## 2. Deserialize

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `bench_deserialize`              |         48 |         48 |

## 3. Nullifier insert x1

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `bench_nullifier_insert`         |        595 |        595 |

## 4. Nullifier insert x10

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `bench_nullifier_insert`         |     13,402 |     13,402 |

## 5. Tree init

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `bench_init`                     |        954 |        954 |

## 6. Utxo append x1

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `bench_append`                   |     22,647 |     22,647 |

## 7. Utxo append x10

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `bench_append`                   |    226,212 |    226,212 |

## 8. Utxo append Batch x10

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `bench_append_batch`             |     29,392 |     29,392 |

