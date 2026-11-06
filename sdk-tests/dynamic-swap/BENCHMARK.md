# Dynamic Swap -- CU Benchmark

Compute unit profiling for the dynamic-swap create_pair/update_price/create_escrow/settle/cancel/withdraw_liquidity/rebalance_liquidity instructions, replayed under mollusk. Every PDA account (Pair, Escrow) and the shielded-pool tree account are built directly, as if the prior instruction chain already ran -- only the ONE instruction under measurement is actually replayed. Only the dynamic-swap program is profiled; the shielded-pool program is built plain, so the CU its CPI consumes is charged to the `cpi_spp_*` row as a black box and its internal functions do not appear here. update_price never verifies a proof or CPI into SPP at all (the whole point of keeping it cheap), and neither does skip_expired, which advances the FIFO order queue past an expired head; deposit_liquidity (the maker's shielded note into a pool note, IN1_OUT2 with one compact output), create_escrow (taker-only, IN1_OUT2), settle (pool-funded, maker-only, IN2_OUT4 with one compact output), cancel (after expiry, IN1_OUT2 with one compact output), withdraw_liquidity (IN1_OUT2 with one compact output and an SPL withdrawal), and rebalance_liquidity (IN5_OUT4, dummy-padded) each verify their own Groth16 proof and then CPI SPP `transact`, which verifies its own. Each proof-carrying instruction's section also records its proving times (SPP transfer proof plus the dynamic-swap circuit proof) and the serialized size of the version 1 transaction these instructions are sent as, which states its compute ceilings in the message header and may run to 4096 bytes.

Regenerate with `just bench-dynamic-swap`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Cancel](#cancel)
2. [Create Escrow](#create-escrow)
3. [Create Pair](#create-pair)
4. [Deposit Liquidity](#deposit-liquidity)
5. [Rebalance Liquidity](#rebalance-liquidity)
6. [Settle](#settle)
7. [Skip Expired](#skip-expired)
8. [Update Price](#update-price)
9. [Withdraw Liquidity](#withdraw-liquidity)

## 1. Cancel

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    141,047 |    141,047 |
| `process_cancel_ix`              |    241,394 |    100,347 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|              87 ms |                     889 ms | 977 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx      |
| ---------------- | -------- | ---------- |
|        616 bytes |       11 | 1033 bytes |

## 2. Create Escrow

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    143,046 |    143,046 |
| `process_create_escrow_ix`       |    254,388 |    111,342 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total   |
| ------------------ | -------------------------- | ------- |
|              92 ms |                    1074 ms | 1167 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx      |
| ---------------- | -------- | ---------- |
|        824 bytes |       12 | 1242 bytes |

## 3. Create Pair

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `process_create_pair_ix`         |      3,224 |      3,224 |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx     |
| ---------------- | -------- | --------- |
|        186 bytes |        3 | 435 bytes |

## 4. Deposit Liquidity

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    141,182 |    141,182 |
| `process_deposit_liquidity_ix`   |    243,571 |    102,389 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|              88 ms |                     680 ms | 768 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx      |
| ---------------- | -------- | ---------- |
|        635 bytes |        9 | 1018 bytes |

## 5. Rebalance Liquidity

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    157,871 |    157,871 |
| `process_rebalance_liquidity_ix` |    275,553 |    117,682 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total   |
| ------------------ | -------------------------- | ------- |
|             299 ms |                    2494 ms | 2793 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx      |
| ---------------- | -------- | ---------- |
|        863 bytes |       13 | 1378 bytes |

## 6. Settle

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    151,449 |    151,449 |
| `process_settle_ix`              |    262,854 |    111,405 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total   |
| ------------------ | -------------------------- | ------- |
|             169 ms |                    1922 ms | 2092 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx      |
| ---------------- | -------- | ---------- |
|        974 bytes |       13 | 1489 bytes |

## 7. Skip Expired

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `process_skip_expired_ix`        |        286 |        286 |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx     |
| ---------------- | -------- | --------- |
|          1 bytes |        3 | 250 bytes |

## 8. Update Price

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `process_update_price_ix`        |         68 |         68 |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx     |
| ---------------- | -------- | --------- |
|          9 bytes |        2 | 225 bytes |

## 9. Withdraw Liquidity

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    145,122 |    145,122 |
| `process_withdraw_liquidity_ix`  |    247,716 |    102,594 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|              85 ms |                     676 ms | 762 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx      |
| ---------------- | -------- | ---------- |
|        645 bytes |       14 | 1193 bytes |

