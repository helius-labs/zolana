# Same-vk multi-proof batching (the winning pattern)

Fold **N ≥ 2 proofs under one verifying key** in a single instruction. This is where RLC amortization shows up (fold-only ~36% at N=2; full-path promotion requires ≥10% measured savings).

## 1. `BatchTransact` (SPP)

**What:** N pure-shielded transfers, same circuit type, no public settlement legs, one RLC.

**Where:** `programs/shielded-pool` → `process_batch_transact_ix`  
**Tag:** `BatchTransact` (see `zolana_interface` / event tags)  
**Cap:** `MAX_BATCH_TRANSACT = 4`  
**Builder:** `zolana_interface::instruction::BatchTransact`

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

### CU

Full-path dual (N× `Transact` vs one `BatchTransact`) is the promotion gate. Fold-only (same-vk Independent, 1 public input):

| N | Fold syscall CU |
| ---: | ---: |
| 1 | 72 603 |
| 2 | 92 395 |
| 4 | 131 784 |

See [measured.md](./measured.md). Recommend in product docs only after full-path Δ ≥ 10%.

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

### CU

Same rule: promote as recommended only with full-path dual ≥10% vs N singles.

## Rules of thumb

1. **Same VK** — different circuits or rails do not share a cheap Independent fold the way same-vk does.
2. **N ≥ 2** — N=1 is solo verify; do not pay fold overhead.
3. **Size before CU** — @1232, BatchTransact N=4 is already near the packet limit; more entries need ALTs or future larger packets, not heroics in the ix body.
4. **Do not mix in a foreign app VK** for CU — that is [no-boost](./no-boost.md) mixed-key k=2.

## Regenerating numbers

```bash
just bench-batch-matrix    # sizes → CU_MATRIX.md
just bench-batch-fold-cu   # fold-only syscall CU
# full-path same-vk dual (when harness exists):
# just bench-batch-same-vk-cu
```
