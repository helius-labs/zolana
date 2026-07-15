# Confidential Swap -- CU Benchmark

Compute unit profiling for the confidential swap make/take/take_verifiable_encryption/cancel instructions, replayed under mollusk. The shielded-pool tree account is built directly (the program's `create_tree` init plus the input utxo hashes appended), and each instruction hashes its public input, verifies its own Groth16 proof, then CPIs SPP `transact` (the `cpi_spp_transact*` row). Only the swap program is profiled; the shielded-pool program is built plain, so the CU its CPI consumes is charged to the `cpi_spp_transact*` row as a black box and its internal functions do not appear here. Each instruction section also records its proving times (SPP transfer proof plus swap circuit proof) and its serialized transaction size: the instruction prefixed with a compute-budget limit ix, as a legacy transaction and as a v0 transaction with every non-signer account and the program id in one address lookup table (Solana's packet limit is 1232 bytes).

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

| Function                             |   Total CU |     Net CU |
| ------------------------------------ | ---------- | ---------- |
| `cpi_spp_transact_signed`            |    155,297 |    155,297 |
| `process_cancel`                     |    252,641 |     97,344 |


**Proving Time**
| SPP transfer proof | Swap circuit proof | Total |
| ------------------ | ------------------ | ----- |
|              61 ms |              17 ms | 78 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx | v0 + ALT Tx |
| ---------------- | -------- | --------- | ----------- |
|        559 bytes |        6 | 871 bytes |   814 bytes |

## 2. Make

| Function                             |   Total CU |     Net CU |
| ------------------------------------ | ---------- | ---------- |
| `cpi_spp_transact`                   |    162,992 |    162,992 |
| `process_make`                       |    258,987 |     95,995 |

**Proving Time**
| SPP transfer proof | Swap circuit proof | Total  |
| ------------------ | ------------------ | ------ |
|             107 ms |              18 ms | 125 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        846 bytes |        4 | 1124 bytes |  1098 bytes |

## 3. Take

| Function                             |   Total CU |     Net CU |
| ------------------------------------ | ---------- | ---------- |
| `cpi_spp_transact_signed`            |    164,710 |    164,710 |
| `process_take`                       |    261,268 |     96,558 |

**Proving Time**
| SPP transfer proof | Swap circuit proof | Total  |
| ------------------ | ------------------ | ------ |
|             109 ms |              28 ms | 138 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        745 bytes |        5 | 1056 bytes |   999 bytes |

## 4. Take Verifiable Encryption

| Function                             |   Total CU |     Net CU |
| ------------------------------------ | ---------- | ---------- |
| `cpi_spp_transact_signed`            |    164,702 |    164,702 |
| `process_take_verifiable_encryption` |    395,782 |    231,080 |

**Proving Time**
| SPP transfer proof | Swap circuit proof | Total  |
| ------------------ | ------------------ | ------ |
|             107 ms |             133 ms | 241 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        792 bytes |        5 | 1103 bytes |  1046 bytes |

