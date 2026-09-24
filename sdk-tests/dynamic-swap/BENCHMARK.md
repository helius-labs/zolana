# Dynamic Swap -- CU Benchmark

Compute unit profiling for the dynamic-swap create_pair/update_price/create_escrow/settle/cancel/withdraw_liquidity/rebalance_liquidity instructions, replayed under mollusk. Every PDA account (Pair, Escrow) and the shielded-pool tree account are built directly, as if the prior instruction chain already ran -- only the ONE instruction under measurement is actually replayed. Only the dynamic-swap program is profiled; the shielded-pool program is built plain, so the CU its CPI consumes is charged to the `cpi_spp_*` row as a black box and its internal functions do not appear here. update_price never verifies a proof or CPI into SPP at all (the whole point of keeping it cheap); create_escrow (taker-only, IN1_OUT2), settle (pool-funded, maker-only, IN2_OUT3), cancel (after expiry, IN1_OUT1), withdraw_liquidity (IN1_OUT1 with an SPL withdrawal), and rebalance_liquidity (IN5_OUT4, dummy-padded) each verify their own Groth16 proof and then CPI SPP `transact`, which verifies its own. deposit_liquidity is proof-free (the program validates the public entry and forwards SPP's proofless deposit with its SPL settlement) and is not profiled here -- it would need token-program fixtures; its on-chain cost is dominated by the SPP deposit CPI. Each proof-carrying instruction's section also records its proving times (SPP transfer proof plus the dynamic-swap circuit proof) and its serialized transaction size, measured twice: as a legacy transaction, which must prefix a compute-budget limit ix and may not exceed 1232 bytes, and as the transaction v1 these instructions are actually sent as, which states its compute ceilings in the message header and may run to 4096 bytes.

Regenerate with `just bench-dynamic-swap`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Cancel](#cancel)
2. [Create Escrow](#create-escrow)
3. [Create Pair](#create-pair)
4. [Rebalance Liquidity](#rebalance-liquidity)
5. [Settle](#settle)
6. [Update Price](#update-price)
7. [Withdraw Liquidity](#withdraw-liquidity)

## 1. Cancel

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    134,067 |    134,067 |
| `process_cancel_ix`              |    237,220 |    103,153 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|              85 ms |                      51 ms | 137 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v1 Tx      |
| ---------------- | -------- | ---------- | ---------- |
|        616 bytes |       11 | 1061 bytes | 1033 bytes |

## 2. Create Escrow

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    138,513 |    138,513 |
| `process_create_escrow_ix`       |    249,151 |    110,638 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|              98 ms |                     118 ms | 216 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v1 Tx      |
| ---------------- | -------- | ---------- | ---------- |
|        824 bytes |       11 | 1269 bytes | 1241 bytes |

## 3. Create Pair

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `process_create_pair_ix`         |      3,192 |      3,192 |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx | v1 Tx     |
| ---------------- | -------- | --------- | --------- |
|        186 bytes |        3 | 463 bytes | 435 bytes |

## 4. Rebalance Liquidity

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    155,904 |    155,904 |
| `process_rebalance_liquidity_ix` |    261,301 |    105,397 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|             259 ms |                     187 ms | 447 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v1 Tx      |
| ---------------- | -------- | ---------- | ---------- |
|        863 bytes |       13 | 1406 bytes | 1378 bytes |

## 5. Settle

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    146,439 |    146,439 |
| `process_settle_ix`              |    257,189 |    110,750 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|             205 ms |                     127 ms | 333 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v1 Tx      |
| ---------------- | -------- | ---------- | ---------- |
|        974 bytes |       13 | 1517 bytes | 1489 bytes |

## 6. Update Price

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `process_update_price_ix`        |         69 |         69 |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx | v1 Tx     |
| ---------------- | -------- | --------- | --------- |
|          9 bytes |        2 | 252 bytes | 225 bytes |

## 7. Withdraw Liquidity

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    139,782 |    139,782 |
| `process_withdraw_liquidity_ix`  |    242,062 |    102,280 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|              86 ms |                      39 ms | 125 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v1 Tx      |
| ---------------- | -------- | ---------- | ---------- |
|        645 bytes |       14 | 1221 bytes | 1193 bytes |

