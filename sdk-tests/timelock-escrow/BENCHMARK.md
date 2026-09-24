# Timelock Escrow -- CU Benchmark

Compute unit profiling for the timelock escrow escrow/withdraw instructions, replayed under mollusk. The shielded-pool tree account is built directly (the program's `create_tree` init plus the input utxo hashes appended), and each instruction verifies its own Groth16 proof, then CPIs SPP `transact` (the `invoke_transact` row). Only the timelock escrow program is profiled; the shielded-pool program is built plain, so the CU its CPI consumes is charged to the `invoke_transact` row as a black box and its internal functions do not appear here. Each instruction section also records its proving times (SPP transfer proof plus the escrow/withdraw circuit proof) and its serialized transaction size, measured twice: as a legacy transaction, which must prefix a compute-budget limit ix and may not exceed 1232 bytes, and as the transaction v1 these instructions are actually sent as, which states its compute ceilings in the message header and may run to 4096 bytes. The protocol now sits between the two, so the legacy column is what a row would have to fit to be sendable the old way, not a limit that binds today.

Regenerate with `just bench-escrow`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Escrow](#escrow)
2. [Withdraw](#withdraw)

## 1. Escrow

| Function              |   Total CU |     Net CU |
| --------------------- | ---------- | ---------- |
| `invoke_transact`     |    147,234 |    147,234 |
| `process_escrow_ix`   |    245,563 |     98,329 |

**Proving Time**
| SPP transfer proof | Escrow circuit proof | Total  |
| ------------------ | -------------------- | ------ |
|             160 ms |                21 ms | 181 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx  | v1 Tx      |
| ---------------- | -------- | ---------- | ---------- |
|        740 bytes |        9 | 1151 bytes | 1123 bytes |

## 2. Withdraw

| Function              |   Total CU |     Net CU |
| --------------------- | ---------- | ---------- |
| `invoke_transact`     |    138,353 |    138,353 |
| `process_withdraw_ix` |    237,798 |     99,445 |

**Proving Time**
| SPP transfer proof | Escrow circuit proof | Total  |
| ------------------ | -------------------- | ------ |
|              90 ms |                15 ms | 106 ms |

**Transaction Size**
| Instruction Data | Accounts | Legacy Tx | v1 Tx     |
| ---------------- | -------- | --------- | --------- |
|        580 bytes |        9 | 959 bytes | 931 bytes |

