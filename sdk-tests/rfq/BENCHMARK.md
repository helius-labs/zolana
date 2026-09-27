# RFQ Settlement -- CU Benchmark

Compute unit profiling for a confidential RFQ settlement, replayed under mollusk. The settlement is a single shielded-pool `transact` co-signed by a maker and a taker that swaps SOL for USDC with no escrow and no custom program: the maker spends one SOL UTXO and receives USDC, the taker spends one USDC UTXO and receives SOL (shape IN2_OUT2, eddsa rail). The shielded-pool program is built with `profile-program`, so its `#[profile]` functions appear in the CU table; the tree account is built directly (the program's `create_tree` init plus the input utxo hashes appended). The section also records the SPP transfer proving time (warm, key already loaded) and the serialized size of the version 1 transaction, which states its compute ceilings in the message header.

Regenerate with `just bench-rfq`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Settlement](#settlement)

## 1. Settlement

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      1,875 |      1,875 |
| `fill_output_owner_pk_hashes` |      1,828 |      1,828 |
| `apply_tree`                  |     30,667 |     30,667 |
| `verify_groth16`              |     93,350 |     93,350 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    155,148 |     27,397 |
| `process_instruction`         |    155,198 |         50 |

**Proving Time**
| SPP transfer proof |
| ------------------ |
|             116 ms |

**Transaction Size**
| Instruction Data | Accounts | v1 Tx |
| ---------------- | -------- | ----- |
|        617 bytes |        4 | 963 bytes |

