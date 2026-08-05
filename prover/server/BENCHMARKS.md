# SPP proving benchmarks

Results written by `scripts/bench_spp.sh` (`just prover bench-spp`, or
`just prover bench-spp-all` for every pinned shape), which runs
`BenchmarkSppTransfer` over the four spp_transaction variants:

| Variant | Circuit | Key prefix |
|---|---|---|
| `confidential` | default-zone, output owners bound to public tags | `transfer_confidential` |
| `zone` | custom-zone transfer, owners private | `transfer_zone` |
| `zone_authority` | anonymous zone-authority transfer, no owner signature | `transfer_zone_authority` |
| `p256` | custom-zone transfer with the emulated P256 gadget | `transfer_p256_zone` |

One timed operation is one server-side proof: `ProveTransfer` /
`ProveP256Transfer`, i.e. witness assembly plus `groth16.Prove`. Circuit
compilation and Groth16 setup are excluded, and the proving key is the
committed one pinned by `prover/provingkeys/proving-keys.lock` -- the section
header records which key version produced the rows, and rows from different
versions are not comparable. `BenchmarkSppWitness` measures witness assembly
alone (well under 1% of a proof) when a regression needs attributing.

`transfer_zone_authority` has pinned keys for square shapes only (1x1, 2x2,
3x3, 4x4); every other variant covers all ten supported shapes. Combinations
with no pinned key are skipped and listed under their results table.

While loading, the benchmark checks each key's constraint system against
`prover/fingerprint.KeyPinned`, so a row can never be attributed to a key set it
did not come from. That check found `transfer_zone_authority_2_2.key` sitting 2
constraints below the current circuit sources (50572 against 50574): the pinned
key set predates a circuit change. Proofs with that key still verify, since its
proving key, verifying key, and the exported on-chain verifying key all come from
the same older revision, but that key cannot be regenerated from source until the
next rotation. `prover/fingerprint.KnownKeyDrift` records the difference and
`TestKnownKeyDriftIsComplete` fails if any other key drifts.

Results are newest first: the script inserts each run directly below the marker.

<!-- results -->

## 2026-08-05 12:39 UTC — 6280d1d1 (jorrit/experiment-poseidon-eddsa-nullifiers) — Apple M5 Pro — benchtime 5x

Proving keys `proving-keys/a59db5a9f609686a`, GOMAXPROCS 18, shapes: all pinned shapes.

| Variant / shape | Proving time (ms/op) | Constraints | MB/op | allocs/op |
|---|---|---|---|---|
| confidential/1x1 | 53.1 | 27124 | 38.7 | 3920 |
| confidential/1x2 | 57.5 | 29081 | 39.1 | 4031 |
| confidential/2x2 | 100.6 | 52058 | 90.0 | 4764 |
| confidential/2x3 | 99.4 | 54031 | 90.3 | 4935 |
| confidential/3x3 | 143.9 | 77025 | 128.6 | 5488 |
| confidential/4x3 | 176.7 | 100028 | 200.1 | 6184 |
| confidential/4x4 | 178.4 | 102025 | 200.4 | 6351 |
| confidential/5x3 | 208.0 | 123040 | 215.1 | 6781 |
| confidential/5x4 | 208.6 | 125045 | 215.5 | 6952 |
| confidential/1x8 | 79.0 | 40991 | 57.4 | 5142 |
| zone/1x1 | 52.3 | 27166 | 38.6 | 3878 |
| zone/1x2 | 54.5 | 29148 | 39.1 | 4078 |
| zone/2x2 | 96.4 | 52138 | 90.0 | 4814 |
| zone/2x3 | 100.8 | 54136 | 90.4 | 5015 |
| zone/3x3 | 144.2 | 77143 | 128.6 | 5593 |
| zone/4x3 | 179.0 | 100159 | 200.1 | 6291 |
| zone/4x4 | 183.4 | 102181 | 200.4 | 6502 |
| zone/5x3 | 203.9 | 123184 | 215.1 | 6912 |
| zone/5x4 | 210.2 | 125214 | 215.5 | 7116 |
| zone/1x8 | 78.9 | 41208 | 57.4 | 5346 |
| zone_authority/1x1 | 53.9 | 26386 | 38.5 | 3807 |
| zone_authority/2x2 | 98.7 | 50572 | 89.6 | 4727 |
| zone_authority/3x3 | 145.8 | 74785 | 128.1 | 5437 |
| zone_authority/4x4 | 177.8 | 99025 | 199.8 | 6303 |
| p256/1x1 | 331.2 | 218657 | 411.5 | 124921 |
| p256/1x2 | 337.9 | 220641 | 412.0 | 125082 |
| p256/2x2 | 363.7 | 243645 | 505.1 | 125873 |
| p256/2x3 | 363.1 | 245645 | 489.8 | 125528 |
| p256/3x3 | 482.5 | 268666 | 599.8 | 125956 |
| p256/4x3 | 486.6 | 291696 | 587.3 | 125957 |
| p256/4x4 | 482.7 | 293720 | 587.7 | 126246 |
| p256/5x3 | 494.4 | 314735 | 591.9 | 126464 |
| p256/5x4 | 508.1 | 316767 | 592.3 | 126702 |
| p256/1x8 | 359.0 | 232713 | 506.6 | 126608 |

Skipped, no proving key pinned for the shape: zone_authority/1x2 zone_authority/2x3 zone_authority/4x3 zone_authority/5x3 zone_authority/5x4 zone_authority/1x8

## Legacy results

Everything under this heading predates the current benchmark. It was produced by
the removed `BenchmarkProveByShape`, which ran a `groth16.Setup` per shape
instead of loading the committed keys and labelled the variants as "rails"; its
p256 rows also come from a since-superseded circuit. Kept for history, not
comparable to the results above.

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
