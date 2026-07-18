# Timelock Escrow -- CU Benchmark

Compute unit profiling for the timelock escrow escrow/withdraw instructions, replayed under mollusk. The shielded-pool tree account is built directly (the program's `create_tree` init plus the input utxo hashes appended), and each instruction verifies its own Groth16 proof, then CPIs SPP `transact` (the `cpi_spp_transact*` row). Only the timelock escrow program is profiled; the shielded-pool program is built plain, so the CU its CPI consumes is charged to the `cpi_spp_transact*` row as a black box and its internal functions do not appear here. Each instruction section also records its proving times (SPP transfer proof plus the escrow/withdraw circuit proof) and its serialized transaction size: the instruction prefixed with a compute-budget limit ix, as a legacy transaction and as a v0 transaction with every non-signer account and the program id in one address lookup table (Solana's packet limit is 1232 bytes).

Regenerate with `just bench-escrow`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Escrow](#escrow)
2. [Withdraw](#withdraw)

## 1. Escrow

| Function                  |   Total CU |     Net CU |
| ------------------------- | ---------- | ---------- |
| `cpi_spp_transact`        |    162,178 |    162,178 |
| `process_escrow_ix`       |    257,763 |     95,585 |

**Proving Time**
| SPP transfer proof | Escrow circuit proof | Total  |
| ------------------ | -------------------- | ------ |
|             112 ms |                15 ms | 127 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v0 + ALT Tx |
| ---------------- | -------- | ---------- | ----------- |
|        748 bytes |        4 | 1026 bytes |  1000 bytes |

## 2. Withdraw

| Function                  |   Total CU |     Net CU |
| ------------------------- | ---------- | ---------- |
| `cpi_spp_transact_signed` |    155,219 |    155,219 |
| `process_withdraw_ix`     |    252,567 |     97,348 |

**Proving Time**
| SPP transfer proof | Escrow circuit proof | Total |
| ------------------ | -------------------- | ----- |
|              59 ms |                15 ms | 74 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx | v0 + ALT Tx |
| ---------------- | -------- | --------- | ----------- |
|        559 bytes |        6 | 871 bytes |   814 bytes |

