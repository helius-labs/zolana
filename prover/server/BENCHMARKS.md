# SPP proving benchmarks

Results appended by `scripts/bench_spp.sh` (`just prover bench-spp`), which
runs `BenchmarkProveByShape` over both ownership rails (solana, p256) and
every supported shape. Times are proving only; circuit compilation and
Groth16 setup are excluded.

## 2026-06-12 — 32e4fac (spp/1-circuit) — Apple M5 Pro — benchtime 5x (solana rail only, pre-p256 bench)

| Rail / shape | Proving time (ms/op) | Constraints | MB/op | allocs/op |
|---|---|---|---|---|
| inputs_1_outputs_2 | 46.2 | 25408 | 27.4 | 3542 |
| inputs_2_outputs_2 | 87.7 | 46335 | 69.9 | 4221 |
| inputs_3_outputs_3 | 127.5 | 68498 | 128.2 | 5226 |
| inputs_5_outputs_3 | 172.5 | 110419 | 172.7 | 6430 |
| inputs_1_outputs_8 | 65.1 | 32776 | 56.3 | 4037 |

## 2026-06-12 21:31 UTC — 32e4fac (spp/1-circuit) — Apple M5 Pro — benchtime 5x

| Rail / shape | Proving time (ms/op) | Constraints | MB/op | allocs/op |
|---|---|---|---|---|
| solana/inputs_1_outputs_2 | 48.8 | 25408 | 27.4 | 3440 |
| solana/inputs_2_outputs_2 | 81.3 | 46335 | 69.9 | 4273 |
| solana/inputs_3_outputs_3 | 130.6 | 68498 | 128.2 | 5246 |
| solana/inputs_5_outputs_3 | 181.0 | 110419 | 172.7 | 6442 |
| solana/inputs_1_outputs_8 | 67.7 | 32776 | 56.3 | 3941 |
| p256/inputs_1_outputs_2 | 317.4 | 182721 | 460.5 | 706358 |
| p256/inputs_2_outputs_2 | 379.1 | 203648 | 464.8 | 708615 |
| p256/inputs_3_outputs_3 | 372.3 | 225811 | 496.2 | 749527 |
| p256/inputs_5_outputs_3 | 492.6 | 267732 | 595.7 | 664499 |
| p256/inputs_1_outputs_8 | 339.7 | 190089 | 462.0 | 706574 |

## 2026-06-12 21:34 UTC — 32e4fac (spp/1-circuit) — Apple M5 Pro — benchtime 5x

| Rail / shape | Proving time (ms/op) | Constraints | MB/op | allocs/op |
|---|---|---|---|---|
| solana/inputs_1_outputs_2 | 49.0 | 25408 | 27.4 | 3440 |
| solana/inputs_2_outputs_2 | 88.5 | 46335 | 69.9 | 4280 |
| solana/inputs_3_outputs_3 | 141.9 | 68498 | 128.2 | 5214 |
| solana/inputs_5_outputs_3 | 188.3 | 110419 | 172.7 | 6242 |
| solana/inputs_1_outputs_8 | 75.4 | 32776 | 56.3 | 4016 |
| p256/inputs_1_outputs_2 | 353.0 | 182721 | 464.3 | 791414 |
| p256/inputs_2_outputs_2 | 394.6 | 203648 | 462.9 | 666143 |
| p256/inputs_3_outputs_3 | 380.0 | 225811 | 498.1 | 792005 |
| p256/inputs_5_outputs_3 | 483.9 | 267732 | 597.6 | 706690 |
| p256/inputs_1_outputs_8 | 333.1 | 190089 | 465.8 | 791955 |
