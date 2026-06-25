# Batch Account Circuit — Proving Benchmarks

The batch account circuit proves that N UTXO commitments fold into a single
public Poseidon hash chain (length N), that every real UTXO shares one public
owner and asset, that every real amount lies in the public `[MinAmount,
MaxAmount]` band, and that the real amounts sum to `AggregateAmount`. Dummy
UTXOs still hash into the chain but are exempt from the owner/asset/band checks
and excluded from the aggregate.

## Groth16 proving time by batch size

Measured with `BenchmarkProveByCount` (one prove per size, `-benchtime=1x`).
`ns/op` is `groth16.Prove` only; `groth16.Setup` runs once per size and is not
timed.

| N (UTXOs) | Constraints | Prove time | Mem/op | Allocs/op |
|----------:|------------:|-----------:|-------:|----------:|
| 10        | 9,752       | 0.027 s    | 5.6 MB   | 2,888  |
| 100       | 99,662      | 0.173 s    | 176 MB   | 4,951  |
| 200       | 199,562     | 0.324 s    | 344 MB   | 5,492  |
| 500       | 499,263     | 0.648 s    | 622 MB   | 6,255  |
| 1,000     | 998,765     | 1.30 s     | 920 MB   | 9,187  |
| 2,000     | 1,997,768   | 3.55 s     | 1.25 GB  | 12,547 |
| 5,000     | 4,994,778   | 9.08 s     | 2.76 GB  | 24,719 |
| 10,000    | 9,989,795   | 15.30 s    | 4.94 GB  | 45,322 |

## Notes

- **~999 constraints per UTXO** — essentially exactly linear in N (one canonical
  UTXO hash, one hash-chain step, a 64-bit range pair, and the owner/asset
  equality checks per UTXO).
- **Prove time** is slightly super-linear: the `n·log n` FFT/MSM term shows at
  the top end (500 -> 5,000 is 10x the constraints but ~14x the time).
- `groth16.Setup` (untimed) dominates wall clock at large N: the 1k/2k/5k batch
  took ~3.6 min total despite ~14 s of actual proving, and the 10k setup+prove
  run took ~4.4 min total.

## Environment

- CPU: Apple M5 Pro (18 logical cores)
- OS/arch: darwin/arm64
- Curve: BN254, Groth16 (gnark)

## Reproduce

```bash
cd prover/server

# correctness (valid with/without dummies, plus out-of-band rejection)
go test ./circuits/batch_account -run TestBatchAccount -v

# proving-time benchmarks, per size (run large sizes individually)
go test -bench='BenchmarkProveByCount/utxos_500$'   ./circuits/batch_account -benchtime=1x -run='^$' -timeout=60m
go test -bench='BenchmarkProveByCount/utxos_10000$' ./circuits/batch_account -benchtime=1x -run='^$' -timeout=60m
```
