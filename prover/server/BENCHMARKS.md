# SPP proving benchmarks

Results appended by `scripts/bench_spp.sh` (`just prover bench-spp`), which
runs `BenchmarkProveByShape` over both ownership rails (solana, p256) and
every supported shape. Times are proving only; circuit compilation and
Groth16 setup are excluded.

## 2026-06-12 — 32e4fac — Apple M5 Pro — benchtime 5x (solana rail only, pre-p256 bench)

| Rail / shape | Proving time (ms/op) | Constraints | MB/op | allocs/op |
|---|---|---|---|---|
| inputs_1_outputs_2 | 46.2 | 25408 | 27.4 | 3542 |
| inputs_2_outputs_2 | 87.7 | 46335 | 69.9 | 4221 |
| inputs_3_outputs_3 | 127.5 | 68498 | 128.2 | 5226 |
| inputs_5_outputs_3 | 172.5 | 110419 | 172.7 | 6430 |
| inputs_1_outputs_8 | 65.1 | 32776 | 56.3 | 4037 |

## 2026-06-12 21:31 UTC — 32e4fac — Apple M5 Pro — benchtime 5x

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

## 2026-06-12 21:34 UTC — 32e4fac — Apple M5 Pro — benchtime 5x

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

## 2026-08-08 — f06ae285 — RTX 5090 + EPYC 9655 (48 vCPU) — benchtime 10x warm

CPU rows run the stock `groth16.Prove`. GPU rows run gnark v0.15.0
`backend/accelerated/icicle` (`-tags=icicle`, `PROVER_GPU=on`, CUDA 12.8).
Warm is the steady-state per-proof wall. Cold is the first prove per proving
system (NTT domain init plus device pinning). The very first GPU prove of the
process also pays the ICICLE backend load (405 ms row). Every proof verified
against the pinned production vk. The GPU path still runs the witness solve
on the CPU, which sets the ~65 ms floor that makes small shapes slower on GPU.

| Circuit / shape | Constraints | CPU warm (ms) | GPU warm (ms) | GPU/CPU | GPU cold (ms) |
|---|---|---|---|---|---|
| transfer-ring/1_1 | 27166 | 38.1 | 66.4 | 0.57x | 405 |
| transfer-ring/1_2 | 29148 | 38.7 | 68.0 | 0.57x | 65 |
| transfer-ring/2_2 | 52138 | 65.7 | 98.5 | 0.67x | 99 |
| transfer-ring/2_3 | 54136 | 69.0 | 102.2 | 0.67x | 100 |
| transfer-ring/3_3 | 77143 | 105.0 | 87.5 | 1.20x | 93 |
| transfer-ring/4_3 | 100159 | 124.2 | 94.7 | 1.31x | 99 |
| transfer-ring/4_4 | 102181 | 130.3 | 95.7 | 1.36x | 100 |
| transfer-ring/5_3 | 123184 | 145.3 | 109.0 | 1.33x | 112 |
| transfer-ring/5_4 | 125214 | 146.9 | 109.9 | 1.34x | 110 |
| transfer-ring/1_8 | 41208 | 57.0 | 79.9 | 0.71x | 83 |
| transfer-confidential/1_1 | 27124 | 34.7 | 64.7 | 0.54x | 65 |
| transfer-confidential/1_2 | 29081 | 36.4 | 65.9 | 0.55x | 66 |
| transfer-confidential/2_2 | 52058 | 65.4 | 97.1 | 0.67x | 97 |
| transfer-confidential/2_3 | 54031 | 67.7 | 99.2 | 0.68x | 105 |
| transfer-confidential/3_3 | 77025 | 104.6 | 89.2 | 1.17x | 88 |
| transfer-confidential/4_3 | 100028 | 126.1 | 97.6 | 1.29x | 100 |
| transfer-confidential/4_4 | 102025 | 126.8 | 102.4 | 1.24x | 105 |
| transfer-confidential/5_3 | 123040 | 143.1 | 113.8 | 1.26x | 113 |
| transfer-confidential/5_4 | 125045 | 142.1 | 113.6 | 1.25x | 112 |
| transfer-confidential/1_8 | 40991 | 56.8 | 80.6 | 0.70x | 82 |
| transfer-ring-authority/1_1 | 26386 | 34.4 | 66.2 | 0.52x | 66 |
| transfer-ring-authority/2_2 | 50572 | 64.0 | 97.0 | 0.66x | 98 |
| transfer-ring-authority/3_3 | 74785 | 102.9 | 90.9 | 1.13x | 92 |
| transfer-ring-authority/4_4 | 99025 | 122.9 | 99.4 | 1.24x | 102 |
| transfer-p256-ring/1_1 | 218657 | 238.0 | 161.2 | 1.48x | 155 |
| transfer-p256-ring/1_2 | 220641 | 236.0 | 154.6 | 1.53x | 149 |
| transfer-p256-ring/2_2 | 243645 | 251.4 | 166.8 | 1.51x | 159 |
| transfer-p256-ring/2_3 | 245645 | 262.4 | 171.8 | 1.53x | 167 |
| transfer-p256-ring/3_3 | 268666 | 337.3 | 198.9 | 1.70x | 185 |
| transfer-p256-ring/4_3 | 291696 | 351.1 | 217.7 | 1.61x | 215 |
| transfer-p256-ring/4_4 | 293720 | 350.5 | 216.3 | 1.62x | 222 |
| transfer-p256-ring/5_3 | 314735 | 379.5 | 232.4 | 1.63x | 234 |
| transfer-p256-ring/5_4 | 316767 | 364.7 | 234.2 | 1.56x | 236 |
| transfer-p256-ring/1_8 | 232713 | 249.6 | 164.8 | 1.51x | 160 |
| merge/8_1 | 180470 | 222.7 | 144.5 | 1.54x | 337 |
| merge-ring/8_1 | 180740 | 219.9 | 144.9 | 1.52x | 149 |

## 2026-08-08 — ea22f870 — RTX 5090 + EPYC 9655 (48 vCPU) — TestProveLoadMixedShapes

Concurrent load through the production dispatch, every proof verified.
Mixed load is ring 2_2 + ring 2_3 + p256_ring 2_3. GPU rows run the stock
gnark v0.15.0 icicle backend with the patched CUDA MSM. The pinned gnark fork
carries a byte-identical `backend/accelerated`, so these rows hold under the
pin. Re-measure on the fork build before quoting them for a release.

| build | m=1 | m=4 | m=16 |
|---|---|---|---|
| gpu (`PROVER_GPU=on`) | 356 ms wall (cold), 2.8 proofs/s | 8.8 proofs/s | 8.5 proofs/s |
| cpu (same binary, `PROVER_GPU=off`) | 77 ms wall | 11.0 proofs/s | 18.0 proofs/s |

Saturated single-shape capacity, same box, all proofs verified:

| load | backend | saturated | latency at saturation |
|---|---|---|---|
| ring 2_2 only | cpu m=48 | 38.9 proofs/s | med 1.18 s |
| ring 2_2 only | cpu m=16 | 29.4 proofs/s | med 0.51 s |
| p256_ring 2_3 only | cpu m=32 | 10.0 proofs/s | med 3.0 s |
| ring 2_2 only | gpu m=8 | 10.2 proofs/s | med 0.49 s |
| p256_ring 2_3 only | gpu m=8 | 5.4 proofs/s | med 1.0 s |
| mixed 2:1 ring:p256 | hybrid auto m=16 | 14.0 proofs/s | med 0.40 s |
