# Same-vk multi-proof batching (the winning pattern)

Fold **N ≥ 2 proofs under one verifying key** in a single instruction. This is where RLC amortization shows up: measured full-path savings at N=2 are **13.6%** (BatchTransact) and **22.5%** (NullifierTreeMany) — both **recommended** under the ≥10% gate.

## 1. `BatchTransact` (SPP)

**What:** N pure-shielded transfers, same circuit type, no public settlement legs, one RLC.

**Where:** `programs/shielded-pool` → `process_batch_transact_ix`  
**Tag:** `BatchTransact` (see `zolana_interface` / event tags)  
**Cap:** `MAX_BATCH_TRANSACT = 4`  
**Builder:** `zolana_interface::instruction::BatchTransact`  
**SDK:** `zolana_client::plan_batch_transact` (size-gated, solo fallback), `zolana_wallet::create_batch_transfer_sync`

### Wire

```text
data = u8 count
     | repeated count times:
         u16 le body_len
         TransactIxData body   // same circuit; empty interface_transfers
```

Accounts match a normal multi-entry pure-shielded path (shared tree, fee payer, etc. — see builder). All entries must share `circuit`; mismatched circuit → `MismatchedCircuitType`. Any public interface transfer → `InvalidTransactShape`.

### Size (measured builders)

| N | Bytes legacy | Bytes v0+ALT | Limit |
| ---: | ---: | ---: | --- |
| 2 | 741 | 715 | 1232 |
| 4 | 1201 | 1175 | 1232 |

### CU (measured full path)

N=2 dual (`just bench-batch-dual`, (1,1) entries): 307 296 legacy vs 265 553 batch — **13.6% saved, recommended**. Practical N today is 2: with complete bodies, N=4 exceeds the 1232-byte packet even for (1,1). Fold-only (same-vk Independent, 1 public input):

| N | Fold syscall CU |
| ---: | ---: |
| 1 | 72 603 |
| 2 | 92 395 |
| 4 | 131 784 |

See [measured.md](./measured.md).

## 2. `BatchUpdateNullifierTreeMany` (forester)

**What:** N same-vk address-append (nullifier tree batch update) proofs in one RLC.

**Where:** forester / interface builders (`BatchUpdateNullifierTree` many variant)  
**Typical N @1232:** 2, 4  
**N @4096-sim (size only unless cluster supports larger packets):** 8, 16

### Size (measured builders)

| N | Bytes legacy | Bytes v0+ALT | Limit |
| ---: | ---: | ---: | --- |
| 2 | 672 | 646 | 1232 |
| 4 | 1060 | 1034 | 1232 |
| 8 | 1836 | 1810 | 4096-sim |
| 16 | 3388 | 3362 | 4096-sim |

### CU (measured full path)

N=2 dual (zkp batch 10): 198 110 legacy vs 153 484 batch — **22.5% saved, recommended**.

## Rules of thumb

1. **Same VK** — different circuits or rails do not share a cheap Independent fold the way same-vk does.
2. **N ≥ 2** — N=1 is solo verify; do not pay fold overhead.
3. **Size before CU** — @1232, BatchTransact N=4 is already near the packet limit; more entries need ALTs or future larger packets, not heroics in the ix body.
4. **Do not mix in a foreign app VK** for CU — that is [no-boost](./no-boost.md) mixed-key k=2.

## Regenerating numbers

```bash
just bench-batch-matrix    # sizes → CU_MATRIX.md
just bench-batch-fold-cu   # fold-only syscall CU
just bench-batch-dual      # full-path same-vk dual → BATCH_CU_RESULTS.md
```
