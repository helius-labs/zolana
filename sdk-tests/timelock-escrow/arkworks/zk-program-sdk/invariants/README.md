# zk-program-sdk Invariants

Test-coverage checklist derived from the SDK builtins. Detailed invariants
live in the per-type files; [`../../spec.md`](../../spec.md) remains the DSL
source of truth. Every test in [`../tests/unit/`](../tests/unit) exists to cover
one or more IDs below, and an invariant is ticked only when a passing test
covers it. [`PROMPT.md`](PROMPT.md) is the extraction prompt for the next builtin.

Marker legend: `- [x]` covered by a passing test in `tests/unit/`, named on its
`Covered by:` line; `- [ ]` uncovered, or partial with a `Partial coverage:` line
stating what is missing.

| File | Covers |
|---|---|
| `circuit_var.md` | `CircuitVar` operators; for now `+` and `+=` |
| `cross-cutting.md` | native and R1CS agreement, the export format, setup/proving shape, the constraint-only `ZkCircuit` statement |

ID prefixes: `INV-CV-ADD`, `INV-XC`. IDs are stable once assigned -- never renumber.

## Coverage Matrix

| Operation | File | Semantics | Constraint | Completeness | Soundness | Shape | Error | Equivalence | Interop | Properties |
|---|---|---|---|---|---|---|---|---|---|---|
| `CircuitVar +`, `+=` | `circuit_var.md` | INV-CV-ADD-01..04 | INV-CV-ADD-05..12, INV-XC-04 | INV-CV-ADD-13, INV-CV-ADD-30 | INV-CV-ADD-14, INV-CV-ADD-15, INV-CV-ADD-32, INV-CV-ADD-33, INV-XC-01 | INV-CV-ADD-16, INV-CV-ADD-17, INV-XC-03 | INV-CV-ADD-18..20, INV-XC-05 | INV-CV-ADD-21..25, INV-CV-ADD-31 | INV-CV-ADD-26..29, INV-XC-02 | INV-CV-ADD-01, INV-CV-ADD-04, INV-CV-ADD-13, INV-CV-ADD-14, INV-CV-ADD-16, INV-CV-ADD-18, INV-CV-ADD-19, INV-XC-01 |

The Properties column lists the invariants a proptest in `properties.rs` also
covers over random field elements.

## Summary

- Total invariants: 38
  - circuit_var.md: 33 (`CircuitVar +` 33)
  - cross-cutting.md: 5
- Critical (soundness: an under-constrained circuit or a wrong constraint): 9
- High (semantics or shape): 21
- Medium (cost or diagnostics): 8
- Covered: 38 / 38
- Partial: 0
- SPEC_DIVERGENCE items: none. `../../spec.md` states that `+` and `+=` wrap
  around the modulus and that a sum is free; INV-CV-ADD-01, -05 and -06 pin
  exactly that.
- INSUFFICIENT_INFO items: none. `../../spec.md` does not describe the
  constraint-only `ZkCircuit`; INV-XC-04 and -05 are derived from
  `src/client/zk_circuit.rs` and `src/prover/synthesis.rs` alone.

## Test Coverage (2026-09-27)

The suite runs in two lanes. `just test-zk-program-sdk-unit`
(`cargo test -p zk-program-sdk --test unit`) needs nothing installed and runs
every test except those that spawn an external tool. `just
test-zk-program-sdk-external` adds the test-only `external-tools` feature,
which compiles in `circuit_var/add/external.rs`, `circuit_var/add/picus.rs` and
the circom, snarkjs and Picus harness modules; it needs circom 2.2.3, snarkjs
0.7.6, `run-picus` and the cvc5 solver on PATH. The invariants those modules
cover (INV-CV-ADD-21..29, -31..33 and the snarkjs half of INV-XC-02) are
covered only in the external lane. The compiled circom output and the throwaway
power-4 ptau are cached under `CARGO_TARGET_TMPDIR/zk-program-sdk-unit`, each
behind a file lock.

`testing::check_private_variables` (INV-CV-ADD-15) perturbs one private
variable at a time with random values. It finds a variable no constraint
binds, but it does not prove the witness unique: variables that can move
together are not detected. That needs a determinism checker such as Picus;
for `CircuitVar +`, INV-CV-ADD-32 closes the gap.

What covering `CircuitVar +` found:

- arkworks 0.6 (gr1cs) inlines `a + b` into the assertion row exactly as
  derived by hand: A = {1: 1, 2: 1, 3: -1}, B = {0: 1}, C = {} (INV-CV-ADD-07).
- circom writes the same linear constraint as `0 * 0 = C`; the normalizer
  compares them as linear forms scaled to a leading coefficient of 1
  (INV-CV-ADD-21).
- ark-circom 0.6.0's own wasm runtime ignores circom's `exceptionHandler`, so
  a failed `===` still returns a witness. The harness installs a handler that
  aborts, as circom's runtime does (INV-CV-ADD-24).
- snarkjs's `wtns calculate` reduces an input of p to 0 and accepts the claim
  (p - 1) + 1 = p. The SDK refuses p at the byte boundary (INV-CV-ADD-20), and
  circom's wasm refuses it when passed unreduced (INV-CV-ADD-24).
- A `Field` constant operand is part of the circuit: a proof input whose
  constant differs from the placeholder's builds a different row, which
  `check_constraints` refuses (INV-CV-ADD-17). A constant fixed in the
  circuit, as in `PlusFive`, exports a row every honest witness satisfies
  (INV-CV-ADD-30).
- Picus proves the sum of every add fixture fixed by its operands, and flags
  b in (a + b) - b and an operand of the unasserted fixture as free
  (INV-CV-ADD-32, -33). The Picus export orders wires as outputs, public
  inputs, private inputs, then inverse hints; with no gadget witness it is
  byte-identical to the snarkjs export (INV-CV-ADD-31).

## Adding a builtin

1. Run [`PROMPT.md`](PROMPT.md) for the builtin to add its section, with new IDs, to its type's file.
2. Add a matrix row.
3. Create `tests/unit/<type>/<op>/` with the same files as `tests/unit/circuit_var/add/`: `fixtures.rs`, `vectors.rs`, `<op>.circom`, `native.rs`, `r1cs.rs`, `external.rs`, `picus.rs` and `properties.rs`. Put `#![cfg(feature = "external-tools")]` first in every file that spawns an external tool.
4. Tick each invariant, with its `Covered by:` line, as its test lands, and update the counts above.

The harness (`tests/unit/harness/`) and `cross-cutting.md` stay shared.
