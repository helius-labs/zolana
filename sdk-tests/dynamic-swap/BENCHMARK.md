# Dynamic Swap -- CU Benchmark

Compute unit profiling for the dynamic-swap create_pair/update_price/create_escrow/settle/cancel/withdraw_liquidity/rebalance_liquidity instructions, replayed under mollusk. Every PDA account (Pair, Escrow) and the shielded-pool tree account are built directly, as if the prior instruction chain already ran -- only the ONE instruction under measurement is actually replayed. Only the dynamic-swap program is profiled; the shielded-pool program is built plain, so the CU its CPI consumes is charged to the `cpi_spp_*` row as a black box and its internal functions do not appear here. update_price never verifies a proof or CPI into SPP at all (the whole point of keeping it cheap); create_escrow (taker-only, IN1_OUT2), settle (pool-funded, maker-only, IN2_OUT3), cancel (after expiry, IN1_OUT1), withdraw_liquidity (IN1_OUT1 with an SPL withdrawal), and rebalance_liquidity (IN5_OUT4, dummy-padded) each verify their own Groth16 proof and then CPI SPP `transact`, which verifies its own. deposit_liquidity is proof-free (the program validates the public entry and forwards SPP's proofless deposit with its SPL settlement) and is not profiled here -- it would need token-program fixtures; its on-chain cost is dominated by the SPP deposit CPI. Each proof-carrying instruction's section also records its proving times (SPP transfer proof plus the dynamic-swap circuit proof) and its serialized transaction size: the instruction prefixed with a compute-budget limit ix, as a legacy transaction and as a v0 transaction with every non-signer account and the program id in one address lookup table (Solana's packet limit is 1232 bytes).

The settle fixture exercises the private refund branch (`execution_price < min_price`) while preserving the same IN2_OUT3 transaction shape as a fill.

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
| `cpi_spp_transact_signed_multi`  |    161,106 |    161,106 |
| `process_cancel_ix`              |    260,645 |     99,539 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|              70 ms |                      48 ms | 119 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx | v0 + ALT Tx |
| ---------------- | -------- | --------- | ----------- |
|        550 bytes |       10 | 962 bytes |   812 bytes |

## 2. Create Escrow

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    164,418 |    164,418 |
| `process_create_escrow_ix`       |    277,846 |    113,428 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|              79 ms |                     126 ms | 205 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        758 bytes |       10 | 1170 bytes |  1020 bytes |

## 3. Create Pair

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `process_create_pair_ix`         |      3,192 |      3,192 |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx | v0 + ALT Tx |
| ---------------- | -------- | --------- | ----------- |
|        186 bytes |        3 | 463 bytes |   437 bytes |

## 4. Rebalance Liquidity

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    189,303 |    189,303 |
| `process_rebalance_liquidity_ix` |    294,511 |    105,208 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|             267 ms |                     197 ms | 464 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        809 bytes |        8 | 1187 bytes |  1068 bytes |

## 5. Settle

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    175,430 |    175,430 |
| `process_settle_ix`              |    294,052 |    118,622 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|             139 ms |                     120 ms | 259 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        911 bytes |       11 | 1388 bytes |  1176 bytes |

## 6. Update Price

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `process_update_price_ix`        |         69 |         69 |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx | v0 + ALT Tx |
| ---------------- | -------- | --------- | ----------- |
|          9 bytes |        2 | 252 bytes |   257 bytes |

## 7. Withdraw Liquidity

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    167,290 |    167,290 |
| `process_withdraw_liquidity_ix`  |    269,360 |    102,070 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|              69 ms |                      41 ms | 110 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        579 bytes |       13 | 1122 bytes |   848 bytes |
