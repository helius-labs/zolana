# Timelock escrow circuit benchmarks

Constraint profiles for the timelock escrow program's create and withdraw circuits. These measurements cover circuit
size and constraint attribution. Proving time and Solana compute units require
separate measurements.

## Snapshot

Recorded on 2026-10-28 with BN254:

- Zolana: `aae7ddec275242f132e4c791ad0ae750856ee606` with working-tree circuit changes.
- Xark CLI: `xark 0.3.0 (e9dab1f74670)`.
- Xark dependency checkout: `e9dab1f7467029087bf79322d6d3163ee689a30c`.
- Rust: `1.98.1`.

| Circuit | Constraints | Variables | Witness-generation operations |
| --- | ---: | ---: | ---: |
| [Escrow, capacity 5](../src/circuits/escrow.rs) | 15,670 | 15,290 | 10,530 |
| [Withdraw](../src/circuits/withdraw.rs) | 5,536 | 5,526 | 4,410 |

These are Xark's profiled R1CS counts, including input range checks, before
proving-key setup. Compare them with profiles from the same compiler revision.

## Comparison with the previous published snapshot

| Measurement | Escrow before | Escrow now | Withdraw before | Withdraw now |
| --- | ---: | ---: | ---: | ---: |
| Raw profile constraints | 17,946 | 15,670 | 6,310 | 5,536 |
| Reduced setup constraints | 17,444 | 15,216 | 6,141 | 5,411 |
| QAP domain size | 32,768 | 16,384 | 8,192 | 8,192 |

The previous snapshot used SDK `3e866da2c` and Xark CLI `38c0de6fec56`.
This comparison includes the earlier nonzero-chain initialization improvement,
default-ring hash specialization, input-ordering changes and the Xark borrow/equality
optimizations. Protocol hashes and escrow behavior are preserved; the circuit-specific
test proving/verifying keys were regenerated. Domain size is not a proving-time measurement.

## Constraint kinds

| Kind | Escrow | Share | Withdraw | Share |
| --- | ---: | ---: | ---: | ---: |
| `Mul` | 10,090 | 64.4% | 4,301 | 77.7% |
| `RangeCheck` | 5,178 | 33.0% | 1,217 | 22.0% |
| `Equality` | 372 | 2.4% | 13 | 0.2% |
| `Or` | 14 | <0.1% | 1 | <0.1% |
| `Comparison` | 16 | 0.1% | 4 | <0.1% |
| **Total** | **15,670** | **100%** | **5,536** | **100%** |

Percentages are rounded. Range checks account for integer widths; equality
includes explicit assertions and bit reconstruction. Comparisons also incur
range checks, counted in `RangeCheck`.

## Functions

Costs include each function's callees, so rows overlap. Names are reported by
Xark; a chain joins equal-cost functions that always occur together.

### Escrow

| Function or chain | Constraints | Share of circuit |
| --- | ---: | ---: |
| `execute` | 11,411 | 72.8% |
| `poseidon` | 9,374 | 59.8% |
| `pow` | 9,294 | 59.3% |
| `new_mut` | 5,404 | 34.5% |
| `check` | 5,222 | 33.3% |
| `hash_with_ring` | 4,317 | 27.5% |

### Withdraw

| Function or chain | Constraints | Share of circuit |
| --- | ---: | ---: |
| `execute` | 4,386 | 79.2% |
| `poseidon` | 4,286 | 77.4% |
| `pow` | 4,281 | 77.3% |
| `hash` | 2,098 | 37.9% |
| `new_mut` → `spend` → `spend_with_hash` | 2,319 | 41.9% |
| `check` | 1,978 | 35.7% |

## Source lines

The current profiles attribute constraints to the generated compiler entrypoint
at `target/zk/timelock-escrow-program/.entries/<circuit>/src/lib.rs`.
The JSON call chains identify work inside SDK functions beneath these lines.

| Line | Source | Escrow | Withdraw |
| --- | --- | ---: | ---: |
| 3 | `#[circuit]`: input range checks | 4,258 | 1,149 |
| 5 | `program.execute().expect("valid program transaction")` | 11,411 | 4,386 |
| 6 | `require_eq(*checked.public_hash(), public_hash)` | 1 | 1 |

## Reproduce

Run from the workspace root with the matching Xark CLI on `PATH` and
`XARK_SOURCE` set to the dependency checkout. Generate the compiler entrypoint
crates through the existing Zolana build command:

```sh
cargo run --release -p spr-cli -- zk compile \
  -p timelock-escrow-program --skip-keys --skip-wasm
```

Print the source-line, function and constraint-kind breakdown in the terminal:

```sh
xark profile target/zk/timelock-escrow-program/.entries/escrow \
  --out target/benchmarks/timelock-escrow/escrow

xark profile target/zk/timelock-escrow-program/.entries/withdraw \
  --out target/benchmarks/timelock-escrow/withdraw
```

Capture machine-readable summaries for comparisons:

```sh
mkdir -p target/benchmarks/timelock-escrow
for circuit in escrow withdraw; do
  xark profile "target/zk/timelock-escrow-program/.entries/$circuit" \
    --out "target/benchmarks/timelock-escrow/$circuit" --json \
    > "target/benchmarks/timelock-escrow/$circuit-summary.json"
done
```

Each circuit's output directory contains `profile.json` with per-constraint
attribution and the compiled artifacts. The separate `*-summary.json` files
contain aggregated `total`, `kinds`, `functions` and `lines` tables. Profiling
outputs stay under the ignored `target/` directory, separate from proving keys.

For example, inspect the highest-cost lines and their call chains:

```sh
jq '.lines[:3]' target/benchmarks/timelock-escrow/escrow-summary.json
jq '.functions[:6]' target/benchmarks/timelock-escrow/withdraw-summary.json
```
