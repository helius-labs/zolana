# Shielded Pool -- CU Benchmark

Compute unit profiling for the shielded-pool deposit and transact instructions, replayed under mollusk from litesvm-built account state: proof-free SOL and SPL shields, plus Groth16-proven (2,3) eddsa transact shapes -- a shielded transfer and SOL/SPL withdrawals. Event emittance is broken out as dedicated rows: `emit_proofless_event` (deposit), `build_transact_event` + `emit_general_event` (transact); each `emit_*_event` total includes the self-CPI invoke and the re-entrant `process_instruction` event no-op.

Regenerate with `just bench-shielded-pool`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Deposit sol](#deposit-sol)
2. [Deposit spl](#deposit-spl)
3. [Transfer](#transfer)
4. [Withdrawal sol](#withdrawal-sol)
5. [Withdrawal spl](#withdrawal-spl)

## 1. Deposit sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `validate_and_parse`          |        517 |        517 |
| `deposit_utxo_hash`           |      4,531 |      4,531 |
| `append_deposit_leaf`         |     22,732 |     22,732 |
| `settle_sol`                  |      1,224 |      1,224 |
| `process_instruction`         |         36 |         36 |
| `emit_general_event`          |      2,108 |      2,072 |
| `emit_proofless_event`        |      2,950 |        842 |
| `process_deposit`             |     33,334 |      1,380 |
| `process_instruction`         |     33,390 |         56 |

## 2. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `validate_and_parse`          |        862 |        862 |
| `deposit_utxo_hash`           |      4,531 |      4,531 |
| `append_deposit_leaf`         |     22,732 |     22,732 |
| `settle_spl`                  |      1,195 |      1,195 |
| `process_instruction`         |         36 |         36 |
| `emit_general_event`          |      2,124 |      2,088 |
| `emit_proofless_event`        |      2,976 |        852 |
| `process_deposit`             |     33,674 |      1,378 |
| `process_instruction`         |     33,730 |         56 |

## 3. Transfer

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      1,845 |      1,845 |
| `validate_and_parse`          |         33 |         33 |
| `apply_tree`                  |     26,434 |     26,434 |
| `transact_external_data_hash` |      1,448 |      1,448 |
| `build_transact_event`        |        458 |        458 |
| `public_input_hash`           |     20,697 |     20,697 |
| `verify_groth16`              |     93,344 |     93,344 |
| `process_instruction`         |         36 |         36 |
| `emit_general_event`          |      2,338 |      2,302 |
| `process_transact_ix`         |    147,934 |      1,337 |
| `process_instruction`         |    147,989 |         55 |

## 4. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      1,845 |      1,845 |
| `validate_and_parse`          |        429 |        429 |
| `apply_tree`                  |     26,434 |     26,434 |
| `transact_external_data_hash` |      1,446 |      1,446 |
| `build_transact_event`        |        486 |        486 |
| `public_input_hash`           |     21,948 |     21,948 |
| `verify_groth16`              |     93,344 |     93,344 |
| `settle_sol`                  |      1,243 |      1,243 |
| `process_instruction`         |         36 |         36 |
| `emit_general_event`          |      2,360 |      2,324 |
| `process_transact_ix`         |    150,910 |      1,375 |
| `process_instruction`         |    150,965 |         55 |

## 5. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `check_input_signers`         |      1,845 |      1,845 |
| `validate_and_parse`          |      1,132 |      1,132 |
| `apply_tree`                  |     26,434 |     26,434 |
| `transact_external_data_hash` |      1,452 |      1,452 |
| `build_transact_event`        |        485 |        485 |
| `public_input_hash`           |     22,838 |     22,838 |
| `verify_groth16`              |     93,344 |     93,344 |
| `settle_spl`                  |      1,208 |      1,208 |
| `process_instruction`         |         36 |         36 |
| `emit_general_event`          |      2,376 |      2,340 |
| `process_transact_ix`         |    152,482 |      1,368 |
| `process_instruction`         |    152,537 |         55 |

