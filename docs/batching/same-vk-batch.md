# Same-vk multi-proof batching

Fold two or more proofs under one verifying key in a single instruction. The
measured full-path savings at N=2 are 13.6% for BatchTransact and 22.5% for
NullifierTreeMany (2026-07-29, `just bench-batch-dual`). Both paths clear the
10% gate and are recommended.

## 1. `BatchTransact` (SPP)

N pure-shielded transfers with the same circuit, no public settlement legs,
one RLC.

**Program:** `programs/shielded-pool`, `process_batch_transact_ix`, tag 53  
**Cap:** `MAX_BATCH_TRANSACT` = 4  
**Builder:** `zolana_interface::instruction::BatchTransact`  
**SDK:** `zolana_client::plan_batch_transact` (size gate with solo fallback) and `zolana_wallet::create_batch_transfer_sync`

### Instruction data

```text
data = u8 count
     | count times:
         u16 le body_len
         TransactIxData body   // same circuit, empty interface_transfers
```

The accounts match the pure-shielded transact layout. All entries must share
one `circuit`. A mismatch fails with `MismatchedCircuitType`. A public
interface transfer fails with `InvalidTransactShape`.

### Size (measured builders, empty bodies)

| N | Bytes legacy | Bytes v0+ALT | Limit |
| ---: | ---: | ---: | --- |
| 2 | 741 | 715 | 1232 |
| 4 | 1201 | 1175 | 1232 |

Complete bodies are larger. A wallet (2,3) entry with ciphertexts measures 773
bytes, so the N=2 batch does not fit the 1232-byte packet and the plan API
falls back to solo. Compact (1,1) entries without inline ciphertexts fit at
N=2. See [examples.md](./examples.md).

### CU (measured full path)

The N=2 dual with (1,1) entries measures 307296 CU legacy against 265553 CU
batch, a 13.6% saving. Fold-only CU (same-vk Independent, one public input):

| N | Fold syscall CU |
| ---: | ---: |
| 1 | 72603 |
| 2 | 92395 |
| 4 | 131784 |
| 8 | 207730 |
| 16 | 358107 |

## 2. `BatchUpdateNullifierTreeMany` (forester)

N same-vk address-append proofs in one RLC, tag 52.

**Cap:** `MAX_BATCH_NULLIFIER_UPDATES` = 16  
**Builder:** `zolana_interface::instruction::BatchUpdateNullifierTreeMany`

### Size (measured builders)

| N | Bytes legacy | Bytes v0+ALT | Limit |
| ---: | ---: | ---: | --- |
| 2 | 672 | 646 | 1232 |
| 4 | 1060 | 1034 | 1232 |
| 8 | 1836 | 1810 | 4096 size simulation |
| 16 | 3388 | 3362 | 4096 size simulation |

### CU (measured full path)

The N=2 dual with zkp batch 10 measures 198110 CU legacy against 153484 CU
batch, a 22.5% saving.

## Rules

1. Same verifying key. Different circuits do not share the cheap Independent fold.
2. Two or more proofs. One proof is a solo verify and the fold overhead is waste.
3. Check the size before the CU. The plan API does this for you.
4. Do not mix in a foreign app key for CU. That shape is [no-boost](./no-boost.md).

## Regenerate the numbers

```bash
just bench-batch-matrix    # sizes, writes CU_MATRIX.md
just bench-batch-fold-cu   # fold-only syscall CU, writes FOLD_CU.md
just bench-batch-dual      # full-path duals, writes BATCH_CU_RESULTS.md
```
