# Measured batch CU snapshot

Sources and regeneration:

- `program-libs/groth16-batch/CU_MATRIX.md`: sizes and the main table (`just bench-batch-matrix`)
- `program-libs/groth16-batch/BATCH_CU_RESULTS.md`: full-path duals (`just bench-batch-dual`)
- `program-libs/groth16-batch/FOLD_CU.md`: fold-only syscall CU (`just bench-batch-fold-cu`)

Measured on 2026-07-27 to 2026-07-29 at agave pin 7090028bb.

## Policy gate

Recommend a path only when the full-path saving is 10% or more against the
legacy path with the same semantics. Fold-only numbers show the verify leg and
are not a full-path claim.

## Full-path duals

### Same-vk multi (`just bench-batch-dual`)

One transaction per leg: N solo instructions against one batch instruction, CU
read from the VM on the SBF program with proofs.

| Use case | Legacy CU | Batch CU | Delta | Saved | Status |
| --- | ---: | ---: | ---: | ---: | --- |
| BatchTransact N=2 against 2 solo Transact, (1,1) entries | 307296 | 265553 | 41743 | 13.6% | recommended |
| NullifierTreeMany N=2 against 2 solo updates, zkp batch 10 | 198110 | 153484 | 44626 | 22.5% | recommended |

Shape notes: the transact entries use (1,1) because a (2,3) N=2 batch exceeds
the 1232-byte packet. The nullifier updates use zkp batch 10
(`batch_address-append_40_10.key`).

### Mixed-key k=2, app plus SPP: no boost

| Use case | Legacy CU | Batch CU | Delta | Status |
| --- | ---: | ---: | ---: | --- |
| Swap take | 269481 | 270878 | -1397 | do not implement |
| Swap cancel | 260690 | 262078 | -1388 | do not implement |
| Swap make | n/a | n/a | blocked by the circuit, same shape |

## Fold-only (syscall layout at agave prices)

Same-vk Independent, one public input (`just bench-batch-fold-cu`):

| N | Fold CU | Against N solo verifies |
| ---: | ---: | ---: |
| 1 | 72603 | baseline |
| 2 | 92395 | about 36% lower |
| 4 | 131784 | about 55% lower |
| 8 | 207730 | about 64% lower |
| 16 | 358107 | about 69% lower |

The apply side still scales with N, so the full-path saving is smaller than
the fold-only saving.

## Packet sizes (builders, empty bodies)

| Builder | Legacy tx | v0+ALT | Limit |
| --- | ---: | ---: | --- |
| BatchTransact N=2 | 741 | 715 | 1232 |
| BatchTransact N=4 | 1201 | 1175 | 1232 |
| NullifierTreeMany N=4 | 1060 | 1034 | 1232 |
| NullifierTreeMany N=8 | 1836 | 1810 | 4096 size simulation |

A wallet (2,3) entry with ciphertexts measures 773 bytes and the N=2
batch probe 1831 bytes, so wallet batching waits for larger packets.
