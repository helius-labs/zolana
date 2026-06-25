# Batch Account Minimal Circuit — Proving Benchmarks

The minimal batch account circuit proves that N UTXO commitments fold into a
single public Poseidon hash chain (length N), that every real amount lies in the
public `[MinAmount, MaxAmount]` band, and that the real amounts sum to
`AggregateAmount`. Dummy UTXOs still hash into the chain but are exempt from the
band check and excluded from the aggregate.

It is the smallest member of the batch_account family. Its leaf is a single
2-input Poseidon:

- **Minimal leaf hash**: `Poseidon(amount, blinding)`.
- **No owner/asset/data hashes**: the UTXO carries only amount and blinding.

Compare with [`batch_account`](../batch_account/BENCHMARKS.md) (canonical
8-field UTXO hash, owner/asset binding) and
[`batch_account_simple`](../batch_account_simple/BENCHMARKS.md)
(`Poseidon(blinding, amount, dataHash, zoneDataHash)`, no owner/asset).

## Groth16 proving time by batch size

Measured with `BenchmarkProveByCount` (one prove per size, `-benchtime=1x`).
`ns/op` is `groth16.Prove` only; `groth16.Setup` runs once per size and is not
timed.

| N (UTXOs) | Constraints | Prove time | Mem/op | Allocs/op |
|----------:|------------:|-----------:|-------:|----------:|
| 10        | 5,902       | 0.012 s    | 3.3 MB   | 2,681  |
| 100       | 61,162      | 0.094 s    | 102 MB   | 4,431  |
| 200       | 122,562     | 0.159 s    | 233 MB   | 5,947  |
| 500       | 306,763     | 0.453 s    | 503 MB   | 6,462  |
| 1,000     | 613,765     | 0.86 s     | 727 MB   | 8,675  |
| 2,000     | 1,227,768   | 1.71 s     | 1.13 GB  | 12,780 |
| 5,000     | 3,069,778   | 3.73 s     | 1.78 GB  | 25,130 |
| 10,000    | 6,139,795   | 7.57 s     | 2.97 GB  | 45,086 |

## Three-way comparison

Constraints per UTXO (the slope dominates everything else):

| Circuit      | Leaf hash                                          | Constraints/UTXO |
|--------------|----------------------------------------------------|-----------------:|
| canonical    | 2 Poseidons (8 fields) + owner/asset equality      | ~999             |
| simple       | `Poseidon(blinding, amount, dataHash, zoneDataHash)` | ~671           |
| minimal      | `Poseidon(amount, blinding)`                       | ~614             |

Constraints by size:

| N (UTXOs) | minimal   | simple    | canonical |
|----------:|----------:|----------:|----------:|
| 10        | 5,902     | 6,472     | 9,752     |
| 100       | 61,162    | 66,862    | 99,662    |
| 500       | 306,763   | 335,263   | 499,263   |
| 1,000     | 613,765   | 670,765   | 998,765   |
| 5,000     | 3,069,778 | 3,354,778 | 4,994,778 |
| 10,000    | 6,139,795 | 6,709,795 | 9,989,795 |

Prove time by size:

| N (UTXOs) | minimal | simple  | canonical |
|----------:|--------:|--------:|----------:|
| 10        | 0.012 s | 0.014 s | 0.027 s   |
| 100       | 0.094 s | 0.124 s | 0.173 s   |
| 500       | 0.453 s | 0.585 s | 0.648 s   |
| 1,000     | 0.86 s  | 0.93 s  | 1.30 s    |
| 2,000     | 1.71 s  | 1.79 s  | 3.55 s    |
| 5,000     | 3.73 s  | 3.72 s  | 9.08 s    |
| 10,000    | 7.57 s  | 8.18 s  | 15.30 s   |

## Notes

- **~614 constraints per UTXO**, the lowest of the three. The drop from simple
  (~671) is just the smaller leaf hash (2-input vs 4-input Poseidon); both shed
  the canonical circuit's second Poseidon and owner/asset checks, which is the
  bulk of the saving versus canonical (~999).
- minimal and simple are close because they differ only by the leaf-hash arity;
  both are roughly 1.6x fewer constraints than canonical, with proving time
  trending toward ~2x faster at the larger sizes.
- `groth16.Setup` (untimed) still dominates wall clock at large N.

## Environment

- CPU: Apple M5 Pro (18 logical cores)
- OS/arch: darwin/arm64
- Curve: BN254, Groth16 (gnark)

## Reproduce

```bash
cd prover/server

# correctness (valid with/without dummies, plus out-of-band rejection)
go test ./circuits/batch_account_minimal -run TestBatchAccountMinimal -v

# proving-time benchmarks, per size (run large sizes individually)
go test -bench='BenchmarkProveByCount/utxos_500$'   ./circuits/batch_account_minimal -benchtime=1x -run='^$' -timeout=60m
go test -bench='BenchmarkProveByCount/utxos_10000$' ./circuits/batch_account_minimal -benchtime=1x -run='^$' -timeout=60m
```
