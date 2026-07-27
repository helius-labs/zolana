# BN254 batch verify — measured CU only

Every CU and byte cell must come from a LiteSVM (or mollusk) run with agave batch
syscalls registered at agave prices. **Do not invent numbers.**

Packet limits: **1232** (today) and **4096** (SIMD-0296; size sim or agave feature gate).

## Syscall pin

Agave `5134c411` — `program-runtime/src/execution_budget.rs` MSM / pairing_check costs.

## Table (fill by `just bench-batch-matrix`)

| Use case | Incarnation | N | CU | Bytes legacy | Bytes v0+ALT | Limit |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| RFQ | legacy | 1 | | | | 1232 |
| Forester | legacy ×N | 2 | | | | 1232 |
| Forester | batch many | 2 | | | | 1232 |
| Forester | batch many | 4 | | | | 1232 |
| Forester | batch many | 8 | | | | 4096 |
| Forester | batch many | 16 | | | | 4096 |
| BatchTransact | batch | 2 | | | | |
| BatchTransact | batch | 4 | | | | 4096 |
| Swap make | legacy | 2 | | | | 1232 |
| Swap make | batch | 2 | | | | 1232 |
| Swap take | legacy | 2 | | | | 1232 |
| Swap take | batch | 2 | | | | 1232 |
| Swap cancel | legacy | 2 | | | | 1232 |
| Swap cancel | batch | 2 | | | | 1232 |
| Swap take_ve | legacy | 2 | | | | 1232 |
| Swap take_ve | batch | 2 | | | | 1232 |
| Create escrow | legacy | 2 | | | | 1232 |
| Create escrow | batch | 2 | | | | 1232 |
| Settle | legacy | 2 | | | | 1232 |
| Settle | batch | 2 | | | | 1232 |
| Escrow | legacy | 2 | | | | 1232 |
| Escrow | batch | 2 | | | | 1232 |
| Withdraw | legacy | 2 | | | | 1232 |
| Withdraw | batch | 2 | | | | 1232 |
