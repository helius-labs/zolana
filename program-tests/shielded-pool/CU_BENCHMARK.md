# Shielded Pool -- CU Benchmark

Compute unit profiling for feasible shielded-pool instruction families, replayed under mollusk from litesvm-built account state: protocol creation, tree pause, proof-free SOL/SPL shields, all ten Groth16-proven EdDSA transact shapes (including the 1x8 split shape), and SOL/SPL withdrawals. Each proof-bearing replay has an enforced ceiling; the fast cu_budget_contract separately pins every proofless administration variant.

Regenerate with `just bench-shielded-pool`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Deposit sol](#deposit-sol)
2. [Deposit sol batch 3](#deposit-sol-batch-3)
3. [Deposit spl](#deposit-spl)
4. [Transfer](#transfer)
5. [Withdrawal sol](#withdrawal-sol)
6. [Withdrawal spl](#withdrawal-spl)
7. [Baseline comparison](#baseline-comparison)

## 1. Create protocol config

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,224 |      1,224 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     38,530 |     37,275 |
| `process_instruction`         |     38,581 |         51 |

## 2. Deposit sol batch 3

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_sol`                  |      1,224 |      1,224 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     50,034 |     48,779 |
| `process_instruction`         |     50,085 |         51 |

## 3. Deposit spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `settle_spl_deposit`          |      1,330 |      1,330 |
| `process_instruction`         |         31 |         31 |
| `process_deposit`             |     39,383 |     38,022 |
| `process_instruction`         |     39,434 |         51 |

## 4. Transfer

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      2,887 |      2,887 |
| `fill_owner_signer_hashes`    |      1,001 |      1,001 |
| `apply_input_tree`            |      3,592 |      3,592 |
| `apply_output_tree`           |     28,964 |     28,964 |
| `verify_groth16`              |     93,351 |     93,351 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    165,114 |     35,288 |
| `process_instruction`         |    165,164 |         50 |

## 5. Withdrawal sol

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      2,887 |      2,887 |
| `fill_owner_signer_hashes`    |      1,001 |      1,001 |
| `apply_input_tree`            |      3,592 |      3,592 |
| `apply_output_tree`           |     28,964 |     28,964 |
| `verify_groth16`              |     93,351 |     93,351 |
| `settle_sol`                  |      1,243 |      1,243 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    169,208 |     38,139 |
| `process_instruction`         |    169,258 |         50 |

## 6. Withdrawal spl

| Function                      |   Total CU |     Net CU |
| ----------------------------- | ---------- | ---------- |
| `fill_output_owner_pk_hashes` |      2,887 |      2,887 |
| `fill_owner_signer_hashes`    |      1,001 |      1,001 |
| `apply_input_tree`            |      3,592 |      3,592 |
| `apply_output_tree`           |     28,964 |     28,964 |
| `verify_groth16`              |     93,351 |     93,351 |
| `settle_spl_withdrawal`       |      1,263 |      1,263 |
| `process_instruction`         |         31 |         31 |
| `process_transact_ix`         |    170,913 |     39,824 |
| `process_instruction`         |    170,963 |         50 |

## Baseline comparison

Compared with expanded pre-TODO baseline commit `d02f3455`. Negative deltas are
CU improvements.

| Case | Phase | Baseline total | Current total | Total delta | Baseline net | Current net | Net delta |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Deposit SOL | `settle_sol` | 1,224 | 1,224 | +0 (+0.00%) | 1,224 | 1,224 | +0 (+0.00%) |
| Deposit SOL | `process_instruction` (dispatch) | 31 | 31 | +0 (+0.00%) | 31 | 31 | +0 (+0.00%) |
| Deposit SOL | `process_deposit` | 38,410 | 38,530 | +120 (+0.31%) | 37,155 | 37,275 | +120 (+0.32%) |
| Deposit SOL | `process_instruction` (total) | 38,460 | 38,581 | +121 (+0.31%) | 50 | 51 | +1 (+2.00%) |
| Deposit SOL batch 3 | `settle_sol` | 1,224 | 1,224 | +0 (+0.00%) | 1,224 | 1,224 | +0 (+0.00%) |
| Deposit SOL batch 3 | `process_instruction` (dispatch) | 31 | 31 | +0 (+0.00%) | 31 | 31 | +0 (+0.00%) |
| Deposit SOL batch 3 | `process_deposit` | 49,908 | 50,034 | +126 (+0.25%) | 48,653 | 48,779 | +126 (+0.26%) |
| Deposit SOL batch 3 | `process_instruction` (total) | 49,958 | 50,085 | +127 (+0.25%) | 50 | 51 | +1 (+2.00%) |
| Deposit SPL | `settle_spl_deposit` | 1,330 | 1,330 | +0 (+0.00%) | 1,330 | 1,330 | +0 (+0.00%) |
| Deposit SPL | `process_instruction` (dispatch) | 31 | 31 | +0 (+0.00%) | 31 | 31 | +0 (+0.00%) |
| Deposit SPL | `process_deposit` | 39,395 | 39,383 | -12 (-0.03%) | 38,034 | 38,022 | -12 (-0.03%) |
| Deposit SPL | `process_instruction` (total) | 39,445 | 39,434 | -11 (-0.03%) | 50 | 51 | +1 (+2.00%) |
| Transfer | `fill_output_owner_pk_hashes` | 2,882 | 2,887 | +5 (+0.17%) | 2,882 | 2,887 | +5 (+0.17%) |
| Transfer | `fill_owner_signer_hashes` | 971 | 1,001 | +30 (+3.09%) | 971 | 1,001 | +30 (+3.09%) |
| Transfer | `apply_input_tree` | 3,387 | 3,592 | +205 (+6.05%) | 3,387 | 3,592 | +205 (+6.05%) |
| Transfer | `apply_output_tree` | 28,870 | 28,964 | +94 (+0.33%) | 28,870 | 28,964 | +94 (+0.33%) |
| Transfer | `verify_groth16` | 93,351 | 93,351 | +0 (+0.00%) | 93,351 | 93,351 | +0 (+0.00%) |
| Transfer | `process_instruction` (dispatch) | 31 | 31 | +0 (+0.00%) | 31 | 31 | +0 (+0.00%) |
| Transfer | `process_transact_ix` | 164,799 | 165,114 | +315 (+0.19%) | 35,307 | 35,288 | -19 (-0.05%) |
| Transfer | `process_instruction` (total) | 164,850 | 165,164 | +314 (+0.19%) | 51 | 50 | -1 (-1.96%) |
| Withdraw SOL | `fill_output_owner_pk_hashes` | 2,882 | 2,887 | +5 (+0.17%) | 2,882 | 2,887 | +5 (+0.17%) |
| Withdraw SOL | `fill_owner_signer_hashes` | 971 | 1,001 | +30 (+3.09%) | 971 | 1,001 | +30 (+3.09%) |
| Withdraw SOL | `apply_input_tree` | 3,387 | 3,592 | +205 (+6.05%) | 3,387 | 3,592 | +205 (+6.05%) |
| Withdraw SOL | `apply_output_tree` | 28,870 | 28,964 | +94 (+0.33%) | 28,870 | 28,964 | +94 (+0.33%) |
| Withdraw SOL | `verify_groth16` | 93,351 | 93,351 | +0 (+0.00%) | 93,351 | 93,351 | +0 (+0.00%) |
| Withdraw SOL | `settle_sol` | 1,243 | 1,243 | +0 (+0.00%) | 1,243 | 1,243 | +0 (+0.00%) |
| Withdraw SOL | `process_instruction` (dispatch) | 31 | 31 | +0 (+0.00%) | 31 | 31 | +0 (+0.00%) |
| Withdraw SOL | `process_transact_ix` | 168,934 | 169,208 | +274 (+0.16%) | 38,199 | 38,139 | -60 (-0.16%) |
| Withdraw SOL | `process_instruction` (total) | 168,985 | 169,258 | +273 (+0.16%) | 51 | 50 | -1 (-1.96%) |
| Withdraw SPL | `fill_output_owner_pk_hashes` | 2,882 | 2,887 | +5 (+0.17%) | 2,882 | 2,887 | +5 (+0.17%) |
| Withdraw SPL | `fill_owner_signer_hashes` | 971 | 1,001 | +30 (+3.09%) | 971 | 1,001 | +30 (+3.09%) |
| Withdraw SPL | `apply_input_tree` | 3,387 | 3,592 | +205 (+6.05%) | 3,387 | 3,592 | +205 (+6.05%) |
| Withdraw SPL | `apply_output_tree` | 28,870 | 28,964 | +94 (+0.33%) | 28,870 | 28,964 | +94 (+0.33%) |
| Withdraw SPL | `verify_groth16` | 93,351 | 93,351 | +0 (+0.00%) | 93,351 | 93,351 | +0 (+0.00%) |
| Withdraw SPL | `settle_spl_withdrawal` | 1,262 | 1,263 | +1 (+0.08%) | 1,262 | 1,263 | +1 (+0.08%) |
| Withdraw SPL | `process_instruction` (dispatch) | 31 | 31 | +0 (+0.00%) | 31 | 31 | +0 (+0.00%) |
| Withdraw SPL | `process_transact_ix` | 170,627 | 170,913 | +286 (+0.17%) | 39,873 | 39,824 | -49 (-0.12%) |
| Withdraw SPL | `process_instruction` (total) | 170,678 | 170,963 | +285 (+0.17%) | 51 | 50 | -1 (-1.96%) |
