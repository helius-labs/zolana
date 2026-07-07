# Confidential Swap -- CU Benchmark

Compute unit profiling for the confidential swap create/fill/fill_verifiable_encryption/cancel instructions, replayed under mollusk. The shielded-pool tree account is built directly (the program's `create_tree` init plus the input utxo hashes appended), and each instruction hashes its public input, verifies its own Groth16 proof, then CPIs SPP `transact` (the `cpi_spp_transact*` row). Only the swap program is profiled; the shielded-pool program is built plain, so the CU its CPI consumes is charged to the `cpi_spp_transact*` row as a black box and its internal functions do not appear here. Serialized transaction sizes and proving times for both rails are appended below.

Regenerate with `just bench-swap`.

## Definitions

- **Total CU**: Compute units consumed by the function including all children
- **Net CU**: Compute units consumed by the function itself (excluding children)

## Table of Contents

1. [Cancel](#cancel)
2. [Create swap](#create-swap)
3. [Fill](#fill)
4. [Fill Verifiable Encryption](#fill-verifiable-encryption)

## 1. Cancel

| Function                                       |   Total CU |     Net CU |
| ---------------------------------------------- | ---------- | ---------- |
| `cancel_public_input_hash`                     |      1,175 |      1,175 |
| `verify_cancel_zk_proof`                       |     93,367 |     93,367 |
| `cpi_spp_transact_signed`                      |    154,454 |    154,454 |
| `process_cancel`                               |    250,854 |      1,858 |

## 2. Create swap

| Function                                       |   Total CU |     Net CU |
| ---------------------------------------------- | ---------- | ---------- |
| `create_public_input_hash`                     |      2,379 |      2,379 |
| `verify_create_zk_proof`                       |     93,367 |     93,367 |
| `cpi_spp_transact`                             |    164,883 |    164,883 |
| `process_create_swap`                          |    263,152 |      2,523 |

## 3. Fill

| Function                                       |   Total CU |     Net CU |
| ---------------------------------------------- | ---------- | ---------- |
| `fill_public_input_hash`                       |        864 |        864 |
| `verify_fill_zk_proof`                         |     93,367 |     93,367 |
| `cpi_spp_transact_signed`                      |    163,943 |    163,943 |
| `process_fill`                                 |    259,165 |        991 |

## 4. Fill Verifiable Encryption

| Function                                       |   Total CU |     Net CU |
| ---------------------------------------------- | ---------- | ---------- |
| `fill_verifiable_encryption_public_input_hash` |      3,721 |      3,721 |
| `verify_fill_verifiable_encryption_zk_proof`   |    224,905 |    224,905 |
| `cpi_spp_transact_signed`                      |    164,059 |    164,059 |
| `process_fill_verifiable_encryption`           |    393,781 |      1,096 |

## Transaction Sizes

Serialized transaction size per instruction, prefixed with a compute-budget limit ix. `legacy` is the v0-less transaction; `v0 + ALT` sinks every non-signer account and the program id into one address lookup table. Solana's packet limit is 1232 bytes.

| Instruction                | ix data (B) | accounts | legacy tx (B) | v0 + ALT tx (B) |
| -------------------------- | ----------- | -------- | ------------- | --------------- |
| create swap                |         949 |        4 |          1227 |            1201 |
| fill                       |         751 |        5 |          1062 |            1005 |
| fill_verifiable_encryption |         831 |        5 |          1142 |            1085 |
| cancel                     |         524 |        6 |           836 |             779 |

## Proving Times

| Instruction  | SPP transfer proof | Swap circuit proof |    Total |
| ------------ | ------------------ | ------------------ | -------- |
| create swap  |              99 ms |              25 ms |   124 ms |
| fill         |              91 ms |              23 ms |   115 ms |
| fill_verifiable_encryption |              96 ms |             118 ms |   215 ms |
| cancel       |              50 ms |              18 ms |    69 ms |
