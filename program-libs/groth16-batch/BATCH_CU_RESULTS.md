# Batch dual CU (LiteSVM + agave batch syscalls)

| Use case | Legacy CU | Batch CU | Delta |
| --- | ---: | ---: | ---: |
| Swap make | n/a | n/a | PDA data_hash blocked by SPP circuit |
| Swap take | 269481 | 270878 | -1397 |
| Swap cancel | 260690 | 262078 | -1388 |


## Dual LiteSVM full-path CU (just bench-batch-cu)

| Use case | Legacy CU | Batch CU | Delta |
| --- | ---: | ---: | ---: |
| Swap take | 269481 | 270878 | -1397 |
| Swap cancel | 260690 | 262078 | -1388 |
| Swap make | n/a | n/a | PDA-owned `data_hash` output rejected by SPP circuit |

Batch mixed-key k=2 is slightly higher than legacy for these shapes: solo app verify is cheap relative to SPP, and the RLC still pays n+3k pairing structure.

Prover fix: rebuild `target/prover-server` after circuit changes; re-download keys to match `proving-keys.lock`.
