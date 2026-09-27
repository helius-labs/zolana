# Confidential Swap -- CU Benchmark

Compute unit profiling for the confidential swap make/take/take_verifiable_encryption/cancel instructions, replayed under mollusk. The shielded-pool tree account is built directly (the program's `create_tree` init plus the input utxo hashes appended), and each instruction hashes its public input, verifies its own Groth16 proof, then CPIs SPP `transact` (the `cpi_spp_transact*` row). Only the swap program is profiled; the shielded-pool program is built plain, so the CU its CPI consumes is charged to the `cpi_spp_transact*` row as a black box and its internal functions do not appear here. Each instruction section also records its proving times (SPP transfer proof plus swap circuit proof) and the serialized size of the version 1 transaction, which states its compute ceilings in the message header.

Regenerate with `just bench-swap`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Cancel](#cancel)
2. [Make](#make)
3. [Take](#take)
4. [Take Verifiable Encryption](#take-verifiable-encryption)

## 1. Cancel

| Function                                |   Total CU |     Net CU |
| --------------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed`               |    151,880 |    151,880 |
| `process_cancel_ix`                     |    251,626 |     99,746 |

**Proving Time**
| SPP transfer proof | Swap circuit proof | Total |
| ------------------ | ------------------ | ----- |
|              63 ms |              18 ms | 81 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx |
| ---------------- | -------- | ----- |
|        559 bytes |        6 | 907 bytes |

## 2. Make

| Function                                |   Total CU |     Net CU |
| --------------------------------------- | ---------- | ---------- |
| `cpi_spp_transact`                      |    162,713 |    162,713 |
| `process_make_ix`                       |    257,789 |     95,076 |

**Proving Time**
| SPP transfer proof | Swap circuit proof | Total  |
| ------------------ | ------------------ | ------ |
|             112 ms |              19 ms | 132 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx |
| ---------------- | -------- | ----- |
|        910 bytes |        4 | 1192 bytes |

## 3. Take

| Function                                |   Total CU |     Net CU |
| --------------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed`               |    161,259 |    161,259 |
| `process_take_ix`                       |    260,024 |     98,765 |

**Proving Time**
| SPP transfer proof | Swap circuit proof | Total  |
| ------------------ | ------------------ | ------ |
|             113 ms |              29 ms | 142 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx |
| ---------------- | -------- | ----- |
|        745 bytes |        5 | 1060 bytes |

## 4. Take Verifiable Encryption

| Function                                |   Total CU |     Net CU |
| --------------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed`               |    161,251 |    161,251 |
| `process_take_verifiable_encryption_ix` |    394,199 |    232,948 |

**Proving Time**
| SPP transfer proof | Swap circuit proof | Total  |
| ------------------ | ------------------ | ------ |
|             111 ms |             134 ms | 245 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx |
| ---------------- | -------- | ----- |
|        792 bytes |        5 | 1107 bytes |

