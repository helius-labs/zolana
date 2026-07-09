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
| `cpi_spp_transact_signed`                      |    154,454 |    154,454 |
| `process_cancel`                               |    250,854 |      1,858 |

**Proving Time**
| SPP transfer proof | Swap circuit proof | Total |
| ------------------ | ------------------ | ----- |
|              49 ms |              16 ms | 66 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx | v0 + ALT Tx |
| ---------------- | -------- | --------- | ----------- |
|        524 bytes |        6 | 836 bytes |   779 bytes |

## 2. Create swap

| Function                                       |   Total CU |     Net CU |
| ---------------------------------------------- | ---------- | ---------- |
| `verify_create_zk_proof`                       |     93,367 |     93,367 |
| `cpi_spp_transact`                             |    164,869 |    164,869 |
| `process_create_swap`                          |    260,586 |      2,350 |

**Proving Time**
| SPP transfer proof | Swap circuit proof | Total  |
| ------------------ | ------------------ | ------ |
|              97 ms |              26 ms | 123 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        884 bytes |        4 | 1162 bytes |  1136 bytes |

## 3. Fill

| Function                                       |   Total CU |     Net CU |
| ---------------------------------------------- | ---------- | ---------- |
| `fill_public_input_hash`                       |        864 |        864 |
| `verify_fill_zk_proof`                         |     93,367 |     93,367 |
| `cpi_spp_transact_signed`                      |    163,939 |    163,939 |
| `process_fill`                                 |    259,161 |        991 |

**Proving Time**
| SPP transfer proof | Swap circuit proof | Total  |
| ------------------ | ------------------ | ------ |
|              96 ms |              25 ms | 121 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        751 bytes |        5 | 1062 bytes |  1005 bytes |

## 4. Fill Verifiable Encryption

| Function                                       |   Total CU |     Net CU |
| ---------------------------------------------- | ---------- | ---------- |
| `fill_verifiable_encryption_public_input_hash` |      3,721 |      3,721 |
| `verify_fill_verifiable_encryption_zk_proof`   |    224,965 |    224,965 |
| `cpi_spp_transact_signed`                      |    164,059 |    164,059 |
| `process_fill_verifiable_encryption`           |    393,841 |      1,096 |

**Proving Time**
| SPP transfer proof | Swap circuit proof | Total  |
| ------------------ | ------------------ | ------ |
|              89 ms |             121 ms | 211 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        831 bytes |        5 | 1142 bytes |  1085 bytes |

