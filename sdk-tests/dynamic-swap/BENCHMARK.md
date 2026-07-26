# Dynamic Swap -- CU Benchmark

Compute unit profiling for the dynamic-swap create_pair/update_price/create_escrow/settle instructions, replayed under mollusk. Every PDA account (Pair, Escrow) and the shielded-pool tree account are built directly, as if the prior instruction chain already ran -- only the ONE instruction under measurement is actually replayed. Only the dynamic-swap program is profiled; the shielded-pool program is built plain, so the CU its CPI consumes is charged to the `cpi_spp_transact*` row as a black box and its internal functions do not appear here. update_price never verifies a proof or CPI into SPP at all (the whole point of keeping it cheap); create_escrow and settle each verify their own Groth16 proof and then CPI SPP `transact`, which verifies its own. Each proof-carrying instruction's section also records its proving times (SPP transfer proof plus the dynamic-swap circuit proof) and its serialized transaction size: the instruction prefixed with a compute-budget limit ix, as a legacy transaction and as a v0 transaction with every non-signer account and the program id in one address lookup table (Solana's packet limit is 1232 bytes) -- create_escrow and settle already need the v0+ALT form to fit at all.

Regenerate with `just bench-dynamic-swap`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Create Escrow](#create-escrow)
2. [Create Pair](#create-pair)
3. [Settle](#settle)
4. [Update Price](#update-price)

## 1. Create Escrow

| Function                        |   Total CU |     Net CU |
| ------------------------------- | ---------- | ---------- |
| `cpi_spp_transact`              |    166,335 |    166,335 |
| `process_create_escrow_ix`      |    275,928 |    109,593 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|             116 ms |                      90 ms | 206 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        861 bytes |        9 | 1336 bytes |  1217 bytes |

## 2. Create Pair

| Function                        |   Total CU |     Net CU |
| ------------------------------- | ---------- | ---------- |
| `process_create_pair_ix`        |      9,094 |      9,094 |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx | v0 + ALT Tx |
| ---------------- | -------- | --------- | ----------- |
|        121 bytes |        3 | 397 bytes |   371 bytes |

## 3. Settle

| Function                        |   Total CU |     Net CU |
| ------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi` |    166,851 |    166,851 |
| `process_settle_ix`             |    266,535 |     99,684 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|             116 ms |                     132 ms | 249 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        811 bytes |        8 | 1221 bytes |  1071 bytes |

## 4. Update Price

| Function                        |   Total CU |     Net CU |
| ------------------------------- | ---------- | ---------- |
| `process_update_price_ix`       |         65 |         65 |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx | v0 + ALT Tx |
| ---------------- | -------- | --------- | ----------- |
|          9 bytes |        2 | 252 bytes |   257 bytes |

