# Confidential Swap -- CU Benchmark

Compute unit profiling for the confidential swap create/fill/fill_verifiable_encryption/cancel instructions, replayed under mollusk. The shielded-pool tree account is built directly (the program's `create_tree` init plus the input utxo hashes appended), and each instruction hashes its public input, verifies its own Groth16 proof, then CPIs SPP `transact` (the `cpi_spp_transact*` row). Only the swap program is profiled; the shielded-pool program is built plain, so the CU its CPI consumes is charged to the `cpi_spp_transact*` row as a black box and its internal functions do not appear here. Each instruction section also records its proving times (SPP transfer proof plus swap circuit proof) and its serialized transaction size: the instruction prefixed with a compute-budget limit ix, as a legacy transaction and as a v0 transaction with every non-signer account and the program id in one address lookup table (Solana's packet limit is 1232 bytes).

Regenerate with `just bench-swap`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Cancel](#cancel)
2. [Create swap](#create-swap)
3. [Fill](#fill)
4. [Fill Verifiable Encryption](#fill-verifiable-encryption)

## 1. Cancel

| Function                                       |   Total CU |     Net CU |
| ---------------------------------------------- | ---------- | ---------- |
| `cancel_public_input_hash`                     |      1,175 |      1,175 |
| `verify_cancel_zk_proof`                       |     93,367 |     93,367 |
| `cpi_spp_transact_signed`                      |    155,297 |    155,297 |
| `process_cancel`                               |    251,675 |      1,836 |

**Proving Time**
| SPP transfer proof | Swap circuit proof | Total |
| ------------------ | ------------------ | ----- |
|              57 ms |              15 ms | 73 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx | v0 + ALT Tx |
| ---------------- | -------- | --------- | ----------- |
|        559 bytes |        6 | 871 bytes |   814 bytes |

## 2. Create swap

| Function                                       |   Total CU |     Net CU |
| ---------------------------------------------- | ---------- | ---------- |
| `verify_create_zk_proof`                       |     93,368 |     93,368 |
| `cpi_spp_transact`                             |    162,992 |    162,992 |
| `process_create_swap`                          |    258,848 |      2,488 |

**Proving Time**
| SPP transfer proof | Swap circuit proof | Total  |
| ------------------ | ------------------ | ------ |
|             114 ms |              17 ms | 132 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        846 bytes |        4 | 1124 bytes |  1098 bytes |

## 3. Fill

| Function                                       |   Total CU |     Net CU |
| ---------------------------------------------- | ---------- | ---------- |
| `fill_public_input_hash`                       |        864 |        864 |
| `verify_fill_zk_proof`                         |     93,367 |     93,367 |
| `cpi_spp_transact_signed`                      |    164,710 |    164,710 |
| `process_fill`                                 |    259,954 |      1,013 |

**Proving Time**
| SPP transfer proof | Swap circuit proof | Total  |
| ------------------ | ------------------ | ------ |
|             119 ms |              27 ms | 146 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        745 bytes |        5 | 1056 bytes |   999 bytes |

## 4. Fill Verifiable Encryption

| Function                                       |   Total CU |     Net CU |
| ---------------------------------------------- | ---------- | ---------- |
| `fill_verifiable_encryption_public_input_hash` |      3,721 |      3,721 |
| `verify_fill_verifiable_encryption_zk_proof`   |    224,958 |    224,958 |
| `cpi_spp_transact_signed`                      |    164,702 |    164,702 |
| `process_fill_verifiable_encryption`           |    394,459 |      1,078 |

**Proving Time**
| SPP transfer proof | Swap circuit proof | Total  |
| ------------------ | ------------------ | ------ |
|             110 ms |             132 ms | 242 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        792 bytes |        5 | 1103 bytes |  1046 bytes |

