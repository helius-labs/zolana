# Batch Account Simple Circuit — Proving Benchmarks

The simplified batch account circuit proves that N UTXO commitments fold into a
single public Poseidon hash chain (length N), that every real amount lies in the
public `[MinAmount, MaxAmount]` band, and that the real amounts sum to
`AggregateAmount`. Dummy UTXOs still hash into the chain but are exempt from the
band check and excluded from the aggregate.

It differs from the canonical [`batch_account`](../batch_account/BENCHMARKS.md)
circuit in two ways:

- **Simplified leaf hash**: `Poseidon(blinding, amount, dataHash, zoneDataHash)`
  — a single 4-input Poseidon, versus the canonical two-Poseidon UTXO hash over
  8 fields.
- **No owner/asset binding**: the simplified UTXO carries no owner or asset, so
  there are no public owner/asset inputs and no per-UTXO equality checks.

## Groth16 proving time by batch size

Measured with `BenchmarkProveByCount` (one prove per size, `-benchtime=1x`).
`ns/op` is `groth16.Prove` only; `groth16.Setup` runs once per size and is not
timed.

| N (UTXOs) | Constraints | Prove time | Mem/op | Allocs/op |
|----------:|------------:|-----------:|-------:|----------:|
| 10        | 6,472       | 0.014 s    | 3.5 MB   | 2,771  |
| 100       | 66,862      | 0.124 s    | 133 MB   | 4,849  |
| 200       | 133,962     | 0.215 s    | 279 MB   | 5,760  |
| 500       | 335,263     | 0.585 s    | 508 MB   | 6,468  |
| 1,000     | 670,765     | 0.93 s     | 867 MB   | 8,578  |
| 2,000     | 1,341,768   | 1.79 s     | 1.15 GB  | 12,710 |
| 5,000     | 3,354,778   | 3.72 s     | 1.82 GB  | 25,156 |
| 10,000    | 6,709,795   | 8.18 s     | 3.06 GB  | 44,695 |

## Comparison vs canonical `batch_account`

| N (UTXOs) | Constraints (simple) | Constraints (canonical) | Prove simple | Prove canonical | Speedup |
|----------:|---------------------:|------------------------:|-------------:|----------------:|--------:|
| 10        | 6,472                | 9,752                   | 0.014 s      | 0.027 s         | 1.9x    |
| 100       | 66,862               | 99,662                  | 0.124 s      | 0.173 s         | 1.4x    |
| 200       | 133,962              | 199,562                 | 0.215 s      | 0.324 s         | 1.5x    |
| 500       | 335,263              | 499,263                 | 0.585 s      | 0.648 s         | 1.1x    |
| 1,000     | 670,765              | 998,765                 | 0.93 s       | 1.30 s          | 1.4x    |
| 2,000     | 1,341,768            | 1,997,768               | 1.79 s       | 3.55 s          | 2.0x    |
| 5,000     | 3,354,778            | 4,994,778               | 3.72 s       | 9.08 s          | 2.4x    |
| 10,000    | 6,709,795            | 9,989,795               | 8.18 s       | 15.30 s         | 1.9x    |

## Notes

- **~671 constraints per UTXO** vs ~999 for the canonical circuit — about a
  third fewer, from dropping the second Poseidon (the owner/blinding inner hash
  folds into a single 4-input hash) and the owner/asset equality checks.
- The constraint reduction is essentially fixed per UTXO, so the ratio holds
  across all N; proving-time speedup is noisier at a single sample per size but
  tracks the constraint count and trends toward ~2x at the larger sizes.
- `groth16.Setup` (untimed) still dominates wall clock at large N.

## Environment

- CPU: Apple M5 Pro (18 logical cores)
- OS/arch: darwin/arm64
- Curve: BN254, Groth16 (gnark)

## Reproduce

```bash
cd prover/server

# correctness (valid with/without dummies, plus out-of-band rejection)
go test ./circuits/batch_account_simple -run TestBatchAccountSimple -v

# proving-time benchmarks, per size (run large sizes individually)
go test -bench='BenchmarkProveByCount/utxos_500$'   ./circuits/batch_account_simple -benchtime=1x -run='^$' -timeout=60m
go test -bench='BenchmarkProveByCount/utxos_10000$' ./circuits/batch_account_simple -benchtime=1x -run='^$' -timeout=60m
```
