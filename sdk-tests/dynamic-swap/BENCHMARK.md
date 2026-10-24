# Dynamic Swap -- CU Benchmark

Compute unit profiling for the dynamic-swap create_pair/update_price/create_escrow/settle/cancel/withdraw_liquidity/rebalance_liquidity instructions, replayed under mollusk. Every PDA account (Pair, Escrow) and the shielded-pool tree account are built directly, as if the prior instruction chain already ran -- only the ONE instruction under measurement is actually replayed. Only the dynamic-swap program is profiled; the shielded-pool program is built plain, so the CU its CPI consumes is charged to the `cpi_spp_*` row as a black box and its internal functions do not appear here. update_price never verifies a proof or CPI into SPP at all (the whole point of keeping it cheap), and neither does skip_expired, which advances the FIFO order queue past an expired head; deposit_liquidity (the maker's shielded note into a pool note, IN1_OUT2 with one compact output), create_escrow (taker-only, IN1_OUT2), settle (pool-funded, maker-only, IN2_OUT4 with one compact output), cancel (after expiry, IN1_OUT2 with one compact output), withdraw_liquidity (IN1_OUT2 with one compact output and an SPL withdrawal), and rebalance_liquidity (IN5_OUT4, dummy-padded) each verify their own Groth16 proof and then CPI SPP `transact`, which verifies its own. Each proof-carrying instruction's section also records its proving times (SPP transfer proof plus the dynamic-swap circuit proof) and the serialized size of the version 1 transaction these instructions are sent as, which states its compute ceilings in the message header and may run to 4096 bytes.

These measurements are the baseline from the former gnark application circuits.
The Rust `zolana-program` circuit migration changes proof generation and verifier
keys; the tables have not been measured again for that implementation.
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
| `cpi_spp_transact_signed_multi`  |    140,910 |    140,910 |
| `process_cancel_ix`              |    242,529 |    101,619 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|             106 ms |                      61 ms | 168 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx      |
| ---------------- | -------- | ---------- |
|        616 bytes |       11 | 1033 bytes |

## 2. Create Escrow

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    140,608 |    140,608 |
| `process_create_escrow_ix`       |    251,256 |    110,648 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|             152 ms |                     152 ms | 304 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx      |
| ---------------- | -------- | ---------- |
|        824 bytes |       11 | 1241 bytes |

## 3. Create Pair

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `process_create_pair_ix`         |      3,194 |      3,194 |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx     |
| ---------------- | -------- | --------- |
|        186 bytes |        3 | 435 bytes |

## 4. Deposit Liquidity

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    139,474 |    139,474 |
| `process_deposit_liquidity_ix`   |    241,499 |    102,025 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|             109 ms |                      45 ms | 154 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx      |
| ---------------- | -------- | ---------- |
|        635 bytes |        8 | 1017 bytes |

## 5. Rebalance Liquidity

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    161,674 |    161,674 |
| `process_rebalance_liquidity_ix` |    264,049 |    102,375 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|             333 ms |                     233 ms | 566 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx      |
| ---------------- | -------- | ---------- |
|        863 bytes |       13 | 1378 bytes |

## 6. Settle

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    149,513 |    149,513 |
| `process_settle_ix`              |    258,747 |    109,234 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|             192 ms |                     164 ms | 356 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx      |
| ---------------- | -------- | ---------- |
|        974 bytes |       13 | 1489 bytes |

## 7. Skip Expired

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `process_skip_expired_ix`        |        322 |        322 |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx     |
| ---------------- | -------- | --------- |
|          1 bytes |        3 | 250 bytes |

## 8. Update Price

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `process_update_price_ix`        |         69 |         69 |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx     |
| ---------------- | -------- | --------- |
|          9 bytes |        2 | 225 bytes |

## 9. Withdraw Liquidity

| Function                         |   Total CU |     Net CU |
| -------------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed_multi`  |    144,465 |    144,465 |
| `process_withdraw_liquidity_ix`  |    261,718 |    117,253 |

**Proving Time**
| SPP transfer proof | Dynamic-swap circuit proof | Total  |
| ------------------ | -------------------------- | ------ |
|             118 ms |                      50 ms | 168 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx      |
| ---------------- | -------- | ---------- |
|        645 bytes |       14 | 1193 bytes |

