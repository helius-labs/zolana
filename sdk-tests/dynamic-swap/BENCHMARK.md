# Dynamic Swap -- CU Benchmark

Compute unit profiling for the dynamic-swap create_pair/update_price/create_escrow/settle/cancel instructions, replayed under mollusk. Every PDA account (Pair, Escrow) and the shielded-pool tree account are built directly, as if the prior instruction chain already ran -- only the ONE instruction under measurement is actually replayed. Only the dynamic-swap program is profiled; the shielded-pool program is built plain, so the CU its CPI consumes is charged to the `cpi_spp_transact*` row as a black box and its internal functions do not appear here. update_price never verifies a proof or CPI into SPP at all (the whole point of keeping it cheap); create_escrow (taker-only, IN1_OUT2), settle (maker-funded, IN2_OUT3), and cancel (after expiry, IN1_OUT1) each verify their own Groth16 proof and then CPI SPP `transact`, which verifies its own. Each proof-carrying instruction's section also records its proving times (SPP transfer proof plus the dynamic-swap circuit proof) and its serialized transaction size: the instruction prefixed with a compute-budget limit ix, as a legacy transaction and as a v0 transaction with every non-signer account and the program id in one address lookup table (Solana's packet limit is 1232 bytes). Dropping the maker legs from create_escrow brought it and cancel back under the limit as plain legacy transactions; only settle still needs the v0+ALT form.

Regenerate with `just bench-dynamic-swap`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Cancel](#cancel)
2. [Create Escrow](#create-escrow)
3. [Create Pair](#create-pair)
4. [Settle](#settle)
5. [Update Price](#update-price)

## 1. Cancel

| Function                        |   Total CU |     Net CU |
| ------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi` |    161,106 |    161,106 |
| `process_cancel_ix`             |    262,084 |    100,978 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total |
| ------------------ | -------------------------- | ----- |
|              60 ms |                      35 ms | 95 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx | v0 + ALT Tx |
| ---------------- | -------- | --------- | ----------- |
|        550 bytes |       10 | 962 bytes |   812 bytes |

## 2. Create Escrow

| Function                        |   Total CU |     Net CU |
| ------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi` |    164,412 |    164,412 |
| `process_create_escrow_ix`      |    281,258 |    116,846 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|              72 ms |                      52 ms | 125 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        750 bytes |       10 | 1162 bytes |  1012 bytes |

## 3. Create Pair

| Function                        |   Total CU |     Net CU |
| ------------------------------- | ---------- | ---------- |
| `process_create_pair_ix`        |      3,109 |      3,109 |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx | v0 + ALT Tx |
| ---------------- | -------- | --------- | ----------- |
|        130 bytes |        3 | 407 bytes |   381 bytes |

## 4. Settle

| Function                        |   Total CU |     Net CU |
| ------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi` |    173,916 |    173,916 |
| `process_settle_ix`             |    279,233 |    105,317 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|             120 ms |                      82 ms | 203 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        809 bytes |       10 | 1253 bytes |  1072 bytes |

## 5. Update Price

| Function                        |   Total CU |     Net CU |
| ------------------------------- | ---------- | ---------- |
| `process_update_price_ix`       |         65 |         65 |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx | v0 + ALT Tx |
| ---------------- | -------- | --------- | ----------- |
|          9 bytes |        2 | 252 bytes |   257 bytes |

