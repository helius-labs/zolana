# zolana-program Invariants

Coverage index for the builtins and protocol types under [`../src/circuit/`](../src/circuit/).
The per-type checklists define the claims and point to their tests; [`../spec.md`](../spec.md)
is the DSL reference and [`PROMPT.md`](PROMPT.md) defines the extraction format.
This index describes tested fixtures, edge vectors, generated inputs and bounded tool runs.
It does not claim a proof over every possible program or witness.

## Reading the matrix

IDs and inclusive ranges refer to entries in the linked file. `[partial]` means the
postcondition is not established, `[finding]` means an inherited failing reproduction is
ignored. A listed ID covers only the exact domain, widths and fixture scope of its
invariant.

`shared fixture`, `range-check fixture` and similar labels identify representative coverage,
not a separate proof of the operation in that row. The Interop column includes both
`wtns check` and Groth16; consult the invariant to distinguish them. The Properties column
identifies proptests, with shared property coverage labelled explicitly. `N/A` names an
inapplicable operation-specific error.

## Coverage matrix

| Operation | File | Semantics | Constraint | Completeness | Soundness | Shape | Error | Equivalence | Interop | Properties |
|---|---|---|---|---|---|---|---|---|---|---|
| `CircuitVar +`, `+=` | [circuit_var.md](circuit_var.md) | INV-CV-ADD-01..04 | INV-CV-ADD-05..12 | INV-CV-ADD-13, INV-CV-ADD-30 | INV-CV-ADD-14..15, INV-CV-ADD-32..33 | INV-CV-ADD-16..17 | INV-CV-ADD-18..20 | INV-CV-ADD-21..25, INV-CV-ADD-31 | INV-CV-ADD-26..29 | INV-CV-ADD-01, INV-CV-ADD-04, INV-CV-ADD-13..14, INV-CV-ADD-16, INV-CV-ADD-18..19 |
| `CircuitVar -`, `-=` | [circuit_var.md](circuit_var.md) | INV-CV-SUB-01..05 | INV-CV-SUB-06..12 | INV-CV-SUB-13..14 | INV-CV-SUB-15..18 | INV-CV-SUB-19..20 | INV-CV-SUB-21..23 | INV-CV-SUB-24..29 | INV-CV-SUB-30..33 | INV-CV-SUB-01, INV-CV-SUB-04, INV-CV-SUB-13, INV-CV-SUB-15, INV-CV-SUB-19, INV-CV-SUB-21..22 |
| `CircuitVar *`, `*=` | [circuit_var.md](circuit_var.md) | INV-CV-MUL-01..05 | INV-CV-MUL-06..14 | INV-CV-MUL-15..16 | INV-CV-MUL-17..21 | INV-CV-MUL-22..23 | INV-CV-MUL-24..27 | INV-CV-MUL-28..33 | INV-CV-MUL-34..37 | INV-CV-MUL-01, INV-CV-MUL-04, INV-CV-MUL-15, INV-CV-MUL-17, INV-CV-MUL-22, INV-CV-MUL-24..25 |
| `CircuitVar` unary `-` | [circuit_var.md](circuit_var.md) | INV-CV-NEG-01..05 | INV-CV-NEG-06..12 | INV-CV-NEG-13 | INV-CV-NEG-14..17 | INV-CV-NEG-18 | INV-CV-NEG-19..21 | INV-CV-NEG-22..27 | INV-CV-NEG-28..31 | INV-CV-NEG-01, INV-CV-NEG-04, INV-CV-NEG-13..14, INV-CV-NEG-18..20 |
| `CircuitVar::inverse` | [circuit_var.md](circuit_var.md) | INV-CV-INV-01..03 | INV-CV-INV-04..09 | INV-CV-INV-10 | INV-CV-INV-11..16 | INV-CV-INV-17 | INV-CV-INV-18..24 | INV-CV-INV-25..28 | INV-CV-INV-29..31 | INV-CV-INV-10, INV-CV-INV-12..13, INV-CV-INV-18..19, INV-CV-INV-23 |
| `CircuitVar::div` | [circuit_var.md](circuit_var.md) | INV-CV-DIV-01..03 | INV-CV-DIV-04..07 | INV-CV-DIV-08 | INV-CV-DIV-09..13 | INV-CV-DIV-14 | INV-CV-DIV-15..21 | INV-CV-DIV-22..25 | INV-CV-DIV-26..27 | INV-CV-DIV-08, INV-CV-DIV-11, INV-CV-DIV-15..16, INV-CV-DIV-20 |
| `CircuitVar::pow` | [circuit_var.md](circuit_var.md) | INV-CV-POW-01..04 | INV-CV-POW-05..08 | INV-CV-POW-09 | INV-CV-POW-10..14 | INV-CV-POW-15 | INV-CV-POW-16..18 | INV-CV-POW-19..23 | INV-CV-POW-24..26 | INV-CV-POW-01, INV-CV-POW-09, INV-CV-POW-16..17 |
| `CircuitVar::check_bits` | [circuit_var.md](circuit_var.md) | INV-CV-BITS-01..02 | INV-CV-BITS-09, INV-CV-BITS-13..15 | INV-CV-BITS-16 | INV-CV-BITS-17..20, INV-CV-BITS-23 | INV-CV-BITS-24 | INV-CV-BITS-25..29 | INV-CV-BITS-30, INV-CV-BITS-34 | witness + 253-bit proof: INV-CV-BITS-35..36 | INV-CV-BITS-01, INV-CV-BITS-16 |
| `CircuitVar::check_is_bool` | [circuit_var.md](circuit_var.md) | INV-CV-BITS-03 | INV-CV-BITS-10, INV-CV-BITS-14 | INV-CV-BITS-16 | INV-CV-BITS-19, INV-CV-BITS-37 | INV-CV-BITS-24 | INV-CV-BITS-03, INV-CV-BITS-29 | INV-CV-BITS-33 | range-check fixture: INV-CV-BITS-35..36 | INV-CV-BITS-37 |
| `CircuitVar::to_bits_le` | [circuit_var.md](circuit_var.md) | INV-CV-BITS-04, INV-CV-BITS-06..07 | INV-CV-BITS-12..15 | INV-CV-BITS-16 | INV-CV-BITS-18..19, INV-CV-BITS-21 | INV-CV-BITS-24 | INV-CV-BITS-25..29 | INV-CV-BITS-31, INV-CV-BITS-34 | range-check fixture: INV-CV-BITS-35..36 | INV-CV-BITS-06, INV-CV-BITS-16 |
| `from_bits_le` | [circuit_var.md](circuit_var.md) | INV-CV-BITS-05..06, INV-CV-BITS-08 | INV-CV-BITS-11, INV-CV-BITS-13..14 | INV-CV-BITS-16 | INV-CV-BITS-18..19, INV-CV-BITS-22 | INV-CV-BITS-24 | N/A: infallible for validated Bool inputs; fixture diagnostics INV-CV-BITS-29 | INV-CV-BITS-32 | range-check fixture: INV-CV-BITS-35..36 | INV-CV-BITS-06, INV-CV-BITS-16 |
| `constant`, `zero`, `value` | [circuit_var.md](circuit_var.md) | INV-CV-CONST-01..03, INV-CV-CONST-06..07 | INV-CV-CONST-04 | shared fixture: INV-CV-ADD-30 | shared fixture: INV-CV-ADD-14 | constant operand fixture: INV-CV-ADD-17 | INV-CV-CONST-05 | shared fixture: INV-CV-ADD-21 | shared fixture: INV-CV-ADD-29 | INV-CV-CONST-07 |
| `Bool::constant`, `TryFrom`, `From<Bool>` | [bool.md](bool.md) | INV-BOOL-CONV-01..03 | INV-BOOL-CONV-04..07 | INV-BOOL-CONV-08 | INV-BOOL-CONV-09..11 | INV-BOOL-CONV-12 | INV-BOOL-CONV-13..16 | INV-BOOL-CONV-17 | INV-BOOL-CONV-18 | INV-BOOL-CONV-14 |
| `Bool::not` | [bool.md](bool.md) | INV-BOOL-GATE-01..03 | INV-BOOL-GATE-04, INV-BOOL-GATE-06, INV-BOOL-GATE-08 | INV-BOOL-GATE-09 | INV-BOOL-GATE-10..11, INV-BOOL-GATE-13..14 | INV-BOOL-GATE-15 | INV-BOOL-GATE-16..17, INV-BOOL-GATE-19 | INV-BOOL-GATE-22..25 | witness checks: INV-BOOL-GATE-26..27 | INV-BOOL-GATE-02, INV-BOOL-GATE-10..11, INV-BOOL-GATE-16..17, INV-BOOL-GATE-19 |
| `Bool::and` | [bool.md](bool.md) | INV-BOOL-GATE-01..03 | INV-BOOL-GATE-05..08 | INV-BOOL-GATE-09 | INV-BOOL-GATE-10..14 | INV-BOOL-GATE-15 | INV-BOOL-GATE-16..19 | INV-BOOL-GATE-20, INV-BOOL-GATE-23..25 | witness checks: INV-BOOL-GATE-26..27 | INV-BOOL-GATE-02, INV-BOOL-GATE-10..11, INV-BOOL-GATE-16..17, INV-BOOL-GATE-19 |
| `Bool::or` | [bool.md](bool.md) | INV-BOOL-GATE-01..03 | INV-BOOL-GATE-05..06, INV-BOOL-GATE-08 | INV-BOOL-GATE-09 | INV-BOOL-GATE-10..14 | INV-BOOL-GATE-15 | INV-BOOL-GATE-16..19 | INV-BOOL-GATE-20, INV-BOOL-GATE-23..25 | witness checks: INV-BOOL-GATE-26..27 | INV-BOOL-GATE-02, INV-BOOL-GATE-10..11, INV-BOOL-GATE-16..17, INV-BOOL-GATE-19 |
| `Bool::xor` | [bool.md](bool.md) | INV-BOOL-GATE-01..03 | INV-BOOL-GATE-05..06, INV-BOOL-GATE-08 | INV-BOOL-GATE-09 | INV-BOOL-GATE-10..14 | INV-BOOL-GATE-15 | INV-BOOL-GATE-16..19 | INV-BOOL-GATE-20, INV-BOOL-GATE-23..25 | witness checks: INV-BOOL-GATE-26..27 | INV-BOOL-GATE-02, INV-BOOL-GATE-10..11, INV-BOOL-GATE-16..17, INV-BOOL-GATE-19 |
| `Bool::nand` | [bool.md](bool.md) | INV-BOOL-GATE-01..03 | INV-BOOL-GATE-05..06, INV-BOOL-GATE-08 | INV-BOOL-GATE-09 | INV-BOOL-GATE-10..14 | INV-BOOL-GATE-15 | INV-BOOL-GATE-16..19 | INV-BOOL-GATE-20, INV-BOOL-GATE-23..25 | witness checks: INV-BOOL-GATE-26..27 | INV-BOOL-GATE-02, INV-BOOL-GATE-10..11, INV-BOOL-GATE-16..17, INV-BOOL-GATE-19 |
| `Bool::implies` | [bool.md](bool.md) | INV-BOOL-GATE-01..03 | INV-BOOL-GATE-05..06, INV-BOOL-GATE-08 | INV-BOOL-GATE-09 | INV-BOOL-GATE-10..14 | INV-BOOL-GATE-15 | INV-BOOL-GATE-16..19 | INV-BOOL-GATE-21, INV-BOOL-GATE-23..25 | witness checks: INV-BOOL-GATE-26..27 | INV-BOOL-GATE-02, INV-BOOL-GATE-10..11, INV-BOOL-GATE-16..17, INV-BOOL-GATE-19 |
| `Bool::all` | [bool.md](bool.md) | INV-BOOL-FOLD-01..02 | INV-BOOL-FOLD-03..05 | INV-BOOL-FOLD-06 | INV-BOOL-FOLD-07..11 | INV-BOOL-FOLD-12 | INV-BOOL-FOLD-13..15 | INV-BOOL-FOLD-16, INV-BOOL-FOLD-18..20 | INV-BOOL-FOLD-21 | INV-BOOL-FOLD-02, INV-BOOL-FOLD-13, INV-BOOL-FOLD-15 |
| `Bool::any` | [bool.md](bool.md) | INV-BOOL-FOLD-01..02 | INV-BOOL-FOLD-03..05 | INV-BOOL-FOLD-06 | INV-BOOL-FOLD-07..11 | INV-BOOL-FOLD-12 | INV-BOOL-FOLD-13..15 | INV-BOOL-FOLD-17..20 | INV-BOOL-FOLD-21 | INV-BOOL-FOLD-02, INV-BOOL-FOLD-13, INV-BOOL-FOLD-15 |
| `Bool::select` / `Select` | [bool.md](bool.md) | INV-BOOL-SEL-01..02 | INV-BOOL-SEL-03..05 | INV-BOOL-SEL-06 | INV-BOOL-SEL-07..11 | INV-BOOL-SEL-12 | INV-BOOL-SEL-13..14 | INV-BOOL-SEL-15..18 | INV-BOOL-SEL-19 | INV-BOOL-SEL-02, INV-BOOL-SEL-13..14 |
| `Bool::assert_true` | [bool.md](bool.md) | INV-BOOL-ASSERT-01..02 | INV-BOOL-ASSERT-03 | INV-BOOL-ASSERT-05 | INV-BOOL-ASSERT-06..08, INV-BOOL-ASSERT-10 | INV-BOOL-ASSERT-11 | INV-BOOL-ASSERT-12..13 | shared fixture: INV-BOOL-ASSERT-14..15 | witness checks: INV-BOOL-ASSERT-16 | INV-BOOL-ASSERT-02, INV-BOOL-ASSERT-13 |
| `Bool::assert_false` | [bool.md](bool.md) | INV-BOOL-ASSERT-01..02 | INV-BOOL-ASSERT-03 | INV-BOOL-ASSERT-05 | INV-BOOL-ASSERT-06..08, INV-BOOL-ASSERT-10 | INV-BOOL-ASSERT-11 | INV-BOOL-ASSERT-12..13 | shared fixture: INV-BOOL-ASSERT-14..15 | witness checks: INV-BOOL-ASSERT-16 | INV-BOOL-ASSERT-02, INV-BOOL-ASSERT-13 |
| `Bool::assert_true_if` | [bool.md](bool.md) | INV-BOOL-ASSERT-01..02 | INV-BOOL-ASSERT-03..04 | INV-BOOL-ASSERT-05 | INV-BOOL-ASSERT-06..07, INV-BOOL-ASSERT-09..10 | INV-BOOL-ASSERT-11 | INV-BOOL-ASSERT-12..13 | INV-BOOL-ASSERT-14..15 | witness checks: INV-BOOL-ASSERT-16 | INV-BOOL-ASSERT-02, INV-BOOL-ASSERT-13 |
| `Bool::is_equal` | [bool.md](bool.md) | INV-BOOL-EQ-01, INV-BOOL-EQ-03 | INV-BOOL-EQ-04 | INV-BOOL-EQ-08 | INV-BOOL-EQ-09..12 | INV-BOOL-EQ-13 | INV-BOOL-EQ-14..15 | INV-BOOL-EQ-16..17 | is_equal witness fixture: INV-BOOL-EQ-19 | INV-BOOL-EQ-03, INV-BOOL-EQ-15 |
| `Bool::assert_equal` | [bool.md](bool.md) | INV-BOOL-EQ-02..03 | INV-BOOL-EQ-05 | INV-BOOL-EQ-08 | INV-BOOL-EQ-09..12 | INV-BOOL-EQ-13 | INV-BOOL-EQ-14..15 | shared fixture: INV-BOOL-EQ-16..17 | is_equal witness fixture: INV-BOOL-EQ-19 | INV-BOOL-EQ-03, INV-BOOL-EQ-15 |
| `Bool::assert_not_equal` | [bool.md](bool.md) | INV-BOOL-EQ-02..03 | INV-BOOL-EQ-06 | INV-BOOL-EQ-08 | INV-BOOL-EQ-09..12, INV-BOOL-EQ-20 | INV-BOOL-EQ-13 | INV-BOOL-EQ-14..15 | shared fixture: INV-BOOL-EQ-16..17 | is_equal witness fixture: INV-BOOL-EQ-19 | INV-BOOL-EQ-03, INV-BOOL-EQ-15 |
| `Bool::assert_equal_if` | [bool.md](bool.md) | INV-BOOL-EQ-02..03 | INV-BOOL-EQ-07 | INV-BOOL-EQ-08 | INV-BOOL-EQ-09..12 | INV-BOOL-EQ-13 | INV-BOOL-EQ-14..15 | shared fixture: INV-BOOL-EQ-16..17 | is_equal witness fixture: INV-BOOL-EQ-19 | INV-BOOL-EQ-03, INV-BOOL-EQ-15 |
| `Uint::TryFrom<CircuitVar>` | [uint.md](uint.md) | INV-UINT-CONSTRUCT-01..02 | INV-UINT-CONSTRUCT-03..05 | INV-UINT-CONSTRUCT-07 | INV-UINT-CONSTRUCT-08..09, INV-UINT-CONSTRUCT-15 | INV-UINT-CONSTRUCT-06 | INV-UINT-CONSTRUCT-10..11 | INV-UINT-CONSTRUCT-12, INV-UINT-PICUS-01..02 [partial] | INV-UINT-CONSTRUCT-13..14 | INV-UINT-CONSTRUCT-15 |
| `Uint::constant / zero` | [uint.md](uint.md) | INV-UINT-CONST-01..02, INV-UINT-CONST-05 | INV-UINT-CONST-03 | identity/constant fixture: INV-UINT-CONST-01 | INV-UINT-CONST-04 | no added relation: INV-UINT-CONST-03 | native width rejection and wrong claims: INV-UINT-CONST-01, INV-UINT-CONST-04 | shared fixture: INV-UINT-CONSTRUCT-12 | shared fixture: INV-UINT-CONSTRUCT-14 | INV-UINT-CONST-05 |
| `Uint::From<Bool>` | [uint.md](uint.md) | INV-UINT-BOOL-01 | INV-UINT-BOOL-02 | identity/constant fixture: INV-UINT-BOOL-01 | INV-UINT-BOOL-03..04 | no added relation: INV-UINT-BOOL-02 | N/A: no operation-specific failure after valid input construction | shared fixture: INV-UINT-CONSTRUCT-12 | shared fixture: INV-UINT-CONSTRUCT-14 | INV-UINT-BOOL-04 |
| `Uint::From<Uint> for CircuitVar` | [uint.md](uint.md) | INV-UINT-INTO-01 | INV-UINT-INTO-02 | identity/constant fixture: INV-UINT-INTO-01 | INV-UINT-INTO-03..04 | no added relation: INV-UINT-INTO-02 | N/A: no operation-specific failure after valid input construction | shared fixture: INV-UINT-CONSTRUCT-12 | shared fixture: INV-UINT-CONSTRUCT-14 | INV-UINT-INTO-04 |
| `Uint::alias widening` | [uint.md](uint.md) | INV-UINT-WIDEN-01 | INV-UINT-WIDEN-02 | identity/constant fixture: INV-UINT-WIDEN-01 | INV-UINT-WIDEN-03..04 | no added relation: INV-UINT-WIDEN-02 | N/A: no operation-specific failure after valid input construction | shared fixture: INV-UINT-CONSTRUCT-12 | shared fixture: INV-UINT-CONSTRUCT-14 | INV-UINT-WIDEN-04 |
| `Uint::alias narrowing` | [uint.md](uint.md) | INV-UINT-NARROW-01 | INV-UINT-NARROW-02 | INV-UINT-NARROW-01..02 | INV-UINT-NARROW-03 | INV-UINT-NARROW-04 | INV-UINT-NARROW-05 | INV-UINT-NARROW-06, INV-UINT-PICUS-06 [partial] | INV-UINT-NARROW-07 | macro-expanded proptest: INV-UINT-NARROW-04 |
| `Uint::add` | [uint.md](uint.md) | INV-UINT-ADD-01, INV-UINT-ADD-07 | INV-UINT-ADD-02, INV-UINT-ARITH-02 | INV-UINT-ADD-03 | INV-UINT-ADD-05 | INV-UINT-ADD-04 | N/A: compile-time result-width bounds; dishonest claims in INV-UINT-ADD-05 | INV-UINT-ADD-06, INV-UINT-PICUS-03 [partial] | checked-arithmetic witness/proof fixtures: INV-UINT-ARITH-03..04 | INV-UINT-ADD-07 |
| `Uint::mul` | [uint.md](uint.md) | INV-UINT-MUL-01, INV-UINT-MUL-07 | INV-UINT-MUL-02, INV-UINT-ARITH-02 | INV-UINT-MUL-03 | INV-UINT-MUL-05 | INV-UINT-MUL-04 | N/A: compile-time result-width bounds; dishonest claims in INV-UINT-MUL-05 | INV-UINT-MUL-06, INV-UINT-PICUS-03 [partial] | checked-arithmetic witness/proof fixtures: INV-UINT-ARITH-03..04 | INV-UINT-MUL-07 |
| `Uint::sum` | [uint.md](uint.md) | INV-UINT-SUM-01, INV-UINT-SUM-07 | INV-UINT-SUM-02 | INV-UINT-SUM-03 | INV-UINT-SUM-05, INV-UINT-SUM-08 | INV-UINT-SUM-04 | N/A: compile-time width bounds; dishonest claims in INV-UINT-SUM-05 | INV-UINT-SUM-06, INV-UINT-PICUS-05 [partial] | INV-UINT-SUM-09 | INV-UINT-SUM-08 |
| `Uint::checked_add` | [uint.md](uint.md) | INV-UINT-CHECKED-ADD-01 | INV-UINT-CHECKED-ADD-02, INV-UINT-ARITH-01..02 | INV-UINT-CHECKED-ADD-03 | INV-UINT-CHECKED-ADD-05, INV-UINT-CHECKED-ADD-08 | INV-UINT-CHECKED-ADD-04 | INV-UINT-CHECKED-ADD-07 | INV-UINT-CHECKED-ADD-06, INV-UINT-PICUS-03 [partial] | checked-arithmetic witness/proof fixtures: INV-UINT-ARITH-03..04 | INV-UINT-CHECKED-ADD-08 |
| `Uint::checked_mul` | [uint.md](uint.md) | INV-UINT-CHECKED-MUL-01 | INV-UINT-CHECKED-MUL-02, INV-UINT-ARITH-01..02 | INV-UINT-CHECKED-MUL-03 | INV-UINT-CHECKED-MUL-05, INV-UINT-CHECKED-MUL-08 | INV-UINT-CHECKED-MUL-04 | INV-UINT-CHECKED-MUL-07 | INV-UINT-CHECKED-MUL-06, INV-UINT-PICUS-03 [partial] | checked-arithmetic witness/proof fixtures: INV-UINT-ARITH-03..04 | INV-UINT-CHECKED-MUL-08 |
| `Uint::checked_sub` | [uint.md](uint.md) | INV-UINT-CHECKED-SUB-01 | INV-UINT-CHECKED-SUB-02, INV-UINT-ARITH-01..02 | INV-UINT-CHECKED-SUB-03 | INV-UINT-CHECKED-SUB-05, INV-UINT-CHECKED-SUB-08 | INV-UINT-CHECKED-SUB-04 | INV-UINT-CHECKED-SUB-07 | INV-UINT-CHECKED-SUB-06, INV-UINT-PICUS-03 [partial] | checked-arithmetic witness/proof fixtures: INV-UINT-ARITH-03..04 | INV-UINT-CHECKED-SUB-08 |
| `Uint::is_less_than` | [uint.md](uint.md) | INV-UINT-LT-01, INV-UINT-LT-06 | INV-UINT-ORDER-01..02 | INV-UINT-LT-02 | INV-UINT-LT-04 | INV-UINT-LT-03 | Claim refusal: INV-UINT-LT-04 | INV-UINT-LT-05, INV-UINT-PICUS-04 [partial] | INV-UINT-LT-07 | INV-UINT-LT-06 |
| `Uint::is_less_or_equal` | [uint.md](uint.md) | INV-UINT-LE-01, INV-UINT-LE-06 | INV-UINT-ORDER-01 | INV-UINT-LE-02 | INV-UINT-LE-04 | INV-UINT-LE-03 | Claim refusal: INV-UINT-LE-04 | INV-UINT-LE-05, INV-UINT-PICUS-04 [partial] | shared fixture: INV-UINT-LT-07 | INV-UINT-LE-06 |
| `Uint::min` | [uint.md](uint.md) | INV-UINT-MIN-01, INV-UINT-MIN-06 | shared range-check costs: INV-UINT-CONSTRUCT-03..04 | INV-UINT-MIN-02 | INV-UINT-MIN-04 | INV-UINT-MIN-03 | Claim refusal: INV-UINT-MIN-04 | INV-UINT-MIN-05, INV-UINT-PICUS-04 [partial] | shared fixture: INV-UINT-LT-07 | INV-UINT-MIN-06 |
| `Uint::max` | [uint.md](uint.md) | INV-UINT-MAX-01, INV-UINT-MAX-06 | shared range-check costs: INV-UINT-CONSTRUCT-03..04 | INV-UINT-MAX-02 | INV-UINT-MAX-04 | INV-UINT-MAX-03 | Claim refusal: INV-UINT-MAX-04 | INV-UINT-MAX-05, INV-UINT-PICUS-04 [partial] | shared fixture: INV-UINT-LT-07 | INV-UINT-MAX-06 |
| `Uint::is_equal (cross-width)` | [uint.md](uint.md) | INV-UINT-EQ-01, INV-UINT-EQ-06 | shared range-check costs: INV-UINT-CONSTRUCT-03..04 | INV-UINT-EQ-02 | INV-UINT-EQ-04, INV-UINT-EQ-07 | INV-UINT-EQ-03 | Claim refusal: INV-UINT-EQ-04 | INV-UINT-EQ-05, INV-UINT-PICUS-04 [partial] | shared fixture: INV-UINT-LT-07 | INV-UINT-EQ-06 |
| `Uint::Assert::is_equal` | [uint.md](uint.md) | INV-UINT-TRAIT-EQ-01, INV-UINT-TRAIT-EQ-06 | shared range-check costs: INV-UINT-CONSTRUCT-03..04 | INV-UINT-TRAIT-EQ-02 | INV-UINT-TRAIT-EQ-04 | INV-UINT-TRAIT-EQ-03 | Claim refusal: INV-UINT-TRAIT-EQ-04 | INV-UINT-TRAIT-EQ-05, INV-UINT-PICUS-04 [partial] | shared fixture: INV-UINT-LT-07 | INV-UINT-TRAIT-EQ-06 |
| `Uint::assert_less_than` | [uint.md](uint.md) | INV-UINT-ASSERT-LT-01 | shared input bounds: INV-UINT-CONSTRUCT-03..04 | acceptance vectors: INV-UINT-ASSERT-LT-01 | INV-UINT-ASSERT-LT-03, INV-UINT-ASSERT-LT-06 | INV-UINT-ASSERT-LT-04 | INV-UINT-ASSERT-LT-02 | INV-UINT-ASSERT-LT-05 | shared fixture: INV-UINT-LT-07 | INV-UINT-ASSERT-LT-06 |
| `Uint::assert_less_or_equal` | [uint.md](uint.md) | INV-UINT-ASSERT-LE-01 | shared input bounds: INV-UINT-CONSTRUCT-03..04 | acceptance vectors: INV-UINT-ASSERT-LE-01 | INV-UINT-ASSERT-LE-03, INV-UINT-ASSERT-LE-06 | INV-UINT-ASSERT-LE-04 | INV-UINT-ASSERT-LE-02 | INV-UINT-ASSERT-LE-05 | shared fixture: INV-UINT-LT-07 | INV-UINT-ASSERT-LE-06 |
| `Uint::assert_equal (cross-width)` | [uint.md](uint.md) | INV-UINT-ASSERT-EQ-01 | shared input bounds: INV-UINT-CONSTRUCT-03..04 | acceptance vectors: INV-UINT-ASSERT-EQ-01 | INV-UINT-ASSERT-EQ-03, INV-UINT-ASSERT-EQ-06 | INV-UINT-ASSERT-EQ-04 | INV-UINT-ASSERT-EQ-02 | INV-UINT-ASSERT-EQ-05 | shared fixture: INV-UINT-LT-07 | INV-UINT-ASSERT-EQ-06 |
| `Uint::assert_not_equal (cross-width)` | [uint.md](uint.md) | INV-UINT-ASSERT-NE-01 | shared input bounds: INV-UINT-CONSTRUCT-03..04 | acceptance vectors: INV-UINT-ASSERT-NE-01 | INV-UINT-ASSERT-NE-03, INV-UINT-ASSERT-NE-06 | INV-UINT-ASSERT-NE-04 | INV-UINT-ASSERT-NE-02 | INV-UINT-ASSERT-NE-05 | shared fixture: INV-UINT-LT-07 | INV-UINT-ASSERT-NE-06 |
| `Uint::Assert::assert_equal` | [uint.md](uint.md) | INV-UINT-TRAIT-ASSERT-EQ-01 | shared input bounds: INV-UINT-CONSTRUCT-03..04 | acceptance vectors: INV-UINT-TRAIT-ASSERT-EQ-01 | INV-UINT-TRAIT-ASSERT-EQ-03, INV-UINT-TRAIT-ASSERT-EQ-06 | INV-UINT-TRAIT-ASSERT-EQ-04 | INV-UINT-TRAIT-ASSERT-EQ-02 | INV-UINT-TRAIT-ASSERT-EQ-05 | shared fixture: INV-UINT-LT-07 | INV-UINT-TRAIT-ASSERT-EQ-06 |
| `Uint::Assert::assert_not_equal` | [uint.md](uint.md) | INV-UINT-TRAIT-ASSERT-NE-01 | shared input bounds: INV-UINT-CONSTRUCT-03..04 | acceptance vectors: INV-UINT-TRAIT-ASSERT-NE-01 | INV-UINT-TRAIT-ASSERT-NE-03, INV-UINT-TRAIT-ASSERT-NE-06 | INV-UINT-TRAIT-ASSERT-NE-04 | INV-UINT-TRAIT-ASSERT-NE-02 | INV-UINT-TRAIT-ASSERT-NE-05 | shared fixture: INV-UINT-LT-07 | INV-UINT-TRAIT-ASSERT-NE-06 |
| `Uint::assert_in_range` | [uint.md](uint.md) | INV-UINT-RANGE-01 | shared input bounds: INV-UINT-CONSTRUCT-03..04 | acceptance vectors: INV-UINT-RANGE-01 | INV-UINT-RANGE-04 | INV-UINT-RANGE-03 | INV-UINT-RANGE-02 | INV-UINT-RANGE-05 | shared fixture: INV-UINT-LT-07 | random_u64_relations test; see scope note: INV-UINT-RANGE-01 |
| `Uint::Assert::assert_equal_if` | [uint.md](uint.md) | INV-UINT-IF-01 | shared input bounds: INV-UINT-CONSTRUCT-03..04 | acceptance vectors: INV-UINT-IF-01 | INV-UINT-IF-04, INV-UINT-IF-06 | INV-UINT-IF-03 | INV-UINT-IF-02 | INV-UINT-IF-05 | shared fixture: INV-UINT-LT-07 | INV-UINT-IF-06 |
| `Uint::assert_zero` | [uint.md](uint.md) | INV-UINT-ASSERT-ZERO-01 | shared input bounds: INV-UINT-CONSTRUCT-03..04 | acceptance vectors: INV-UINT-ASSERT-ZERO-01 | INV-UINT-ASSERT-ZERO-04, INV-UINT-ASSERT-ZERO-06 | INV-UINT-ASSERT-ZERO-03 | INV-UINT-ASSERT-ZERO-02 | INV-UINT-ASSERT-ZERO-05 | shared fixture: INV-UINT-LT-07 | INV-UINT-ASSERT-ZERO-06 |
| `Uint::assert_not_zero` | [uint.md](uint.md) | INV-UINT-ASSERT-NONZERO-01 | shared input bounds: INV-UINT-CONSTRUCT-03..04 | acceptance vectors: INV-UINT-ASSERT-NONZERO-01 | INV-UINT-ASSERT-NONZERO-04, INV-UINT-ASSERT-NONZERO-06 | INV-UINT-ASSERT-NONZERO-03 | INV-UINT-ASSERT-NONZERO-02 | INV-UINT-ASSERT-NONZERO-05 | shared fixture: INV-UINT-LT-07 | INV-UINT-ASSERT-NONZERO-06 |
| `Uint::Select::select` | [uint.md](uint.md) | INV-UINT-SELECT-01 | shared input bounds: INV-UINT-CONSTRUCT-03..04 | honest fixtures: INV-UINT-SELECT-01..02 | INV-UINT-SELECT-03 | INV-UINT-SELECT-02 | Claim refusal: INV-UINT-SELECT-03 | INV-UINT-SELECT-04, INV-UINT-PICUS-04 [partial] | INV-UINT-SELECT-05 | random_u64_relations test; see scope note: INV-UINT-SELECT-01 |
| `Uint::is_zero` | [uint.md](uint.md) | INV-UINT-ZERO-01 | shared input bounds: INV-UINT-CONSTRUCT-03..04 | honest fixtures: INV-UINT-ZERO-01..02 | INV-UINT-ZERO-03, INV-UINT-ZERO-06 | INV-UINT-ZERO-02 | Claim refusal: INV-UINT-ZERO-03 | INV-UINT-ZERO-04, INV-UINT-PICUS-04 [partial] | INV-UINT-ZERO-05 | INV-UINT-ZERO-06 |
| `Uint::div_rem` | [uint.md](uint.md) | INV-UINT-DIV-01 | INV-UINT-DIV-05 | INV-UINT-DIV-03 | INV-UINT-DIV-06..07, INV-UINT-DIV-09 | INV-UINT-DIV-04 | INV-UINT-DIV-02 | INV-UINT-DIV-08, INV-UINT-PICUS-04 [partial] | INV-UINT-DIV-10 | INV-UINT-DIV-09 |
| `Bytes::constant`, `default`, `bytes`; allocation | [bytes.md](bytes.md) | INV-BYTES-ALLOC-01..03 | INV-BYTES-ALLOC-04..06 | INV-BYTES-ALLOC-07 | INV-BYTES-ALLOC-08, INV-BYTES-ALLOC-10, INV-BYTES-ALLOC-12 [partial] | INV-BYTES-ALLOC-13 | INV-BYTES-ALLOC-09 | INV-BYTES-ALLOC-11 | INV-BYTES-ALLOC-14 | shared fixture: INV-BYTES-PACK-11 |
| `Bytes::try_from` (split, owned/borrowed) | [bytes.md](bytes.md) | INV-BYTES-SPLIT-01 | INV-BYTES-SPLIT-02..05 | INV-BYTES-SPLIT-06 | INV-BYTES-SPLIT-07..08, INV-BYTES-SPLIT-16, INV-BYTES-SPLIT-17 [partial] | INV-BYTES-SPLIT-09 | INV-BYTES-SPLIT-10..13 | INV-BYTES-SPLIT-14 | INV-BYTES-SPLIT-15 | INV-BYTES-SPLIT-16 |
| `CircuitVar::try_from(Bytes)` (pack, owned/borrowed) | [bytes.md](bytes.md) | INV-BYTES-PACK-01 | INV-BYTES-PACK-02..03, INV-BYTES-PACK-09 | INV-BYTES-PACK-04 | INV-BYTES-PACK-05..06, INV-BYTES-PACK-11..12, INV-BYTES-PACK-13 [partial] | INV-BYTES-PACK-14 | INV-BYTES-PACK-07 | INV-BYTES-PACK-08 | INV-BYTES-PACK-10 | INV-BYTES-PACK-11 |
| `Bytes::assert_equal` | [bytes.md](bytes.md) | INV-BYTES-ASSERT-01 | INV-BYTES-ASSERT-06..07, INV-BYTES-ASSERT-14 | INV-BYTES-ASSERT-16 | INV-BYTES-ASSERT-09, INV-BYTES-ASSERT-13, INV-BYTES-ASSERT-17 | INV-BYTES-ASSERT-08 | INV-BYTES-ASSERT-18 | INV-BYTES-ASSERT-12 | INV-BYTES-ASSERT-19 | INV-BYTES-ASSERT-13 |
| `Bytes::assert_equal_if` | [bytes.md](bytes.md) | INV-BYTES-ASSERT-02 | INV-BYTES-ASSERT-07, INV-BYTES-ASSERT-14 | INV-BYTES-ASSERT-16 | INV-BYTES-ASSERT-09, INV-BYTES-ASSERT-13, INV-BYTES-ASSERT-17 | INV-BYTES-ASSERT-08 | INV-BYTES-ASSERT-18 | INV-BYTES-ASSERT-12 | INV-BYTES-ASSERT-19 | INV-BYTES-ASSERT-13 |
| `Bytes::assert_not_equal` | [bytes.md](bytes.md) | INV-BYTES-ASSERT-03 | INV-BYTES-ASSERT-07, INV-BYTES-ASSERT-14 | INV-BYTES-ASSERT-16 | INV-BYTES-ASSERT-10, INV-BYTES-ASSERT-13, INV-BYTES-ASSERT-17 | INV-BYTES-ASSERT-08 | INV-BYTES-ASSERT-05, INV-BYTES-ASSERT-18 | INV-BYTES-ASSERT-12 | INV-BYTES-ASSERT-19 | INV-BYTES-ASSERT-13 |
| `Bytes::is_equal` | [bytes.md](bytes.md) | INV-BYTES-ASSERT-04 | INV-BYTES-ASSERT-07, INV-BYTES-ASSERT-14 | INV-BYTES-ASSERT-16 | INV-BYTES-ASSERT-11, INV-BYTES-ASSERT-13, INV-BYTES-ASSERT-17, INV-BYTES-ASSERT-15 [partial] | INV-BYTES-ASSERT-08 | INV-BYTES-ASSERT-18 | INV-BYTES-ASSERT-12 | INV-BYTES-ASSERT-19 | INV-BYTES-ASSERT-13 |
| `Bytes::select` | [bytes.md](bytes.md) | INV-BYTES-SELECT-01 | INV-BYTES-SELECT-02..03 | INV-BYTES-SELECT-10 | INV-BYTES-SELECT-05, INV-BYTES-SELECT-08, INV-BYTES-SELECT-09 [partial] | INV-BYTES-SELECT-04 | INV-BYTES-SELECT-11 | INV-BYTES-SELECT-06 | INV-BYTES-SELECT-07 | INV-BYTES-SELECT-08 |
| `Bytes<N>::hash_bytes` | [bytes.md](bytes.md) | INV-HASH-BYTES-02..03 | INV-HASH-BYTES-05..06 | INV-HASH-BYTES-08 | INV-HASH-BYTES-04, INV-HASH-BYTES-09..10, INV-HASH-BYTES-15..16 [partial] | INV-HASH-BYTES-07 | INV-HASH-BYTES-11 | INV-HASH-BYTES-01, INV-HASH-BYTES-12, INV-HASH-BYTES-14 | INV-HASH-BYTES-13 | INV-HASH-BYTES-14 |
| `Assert::is_equal` | [ops.md](ops.md) | INV-ASSERT-01 | INV-ASSERT-11..13 | INV-ASSERT-25..26 | INV-ASSERT-29, INV-ASSERT-32 | INV-ASSERT-34..35 | INV-ASSERT-36..39 | INV-ASSERT-43, INV-ASSERT-45 | INV-ASSERT-47 | INV-ASSERT-01, INV-ASSERT-25, INV-ASSERT-29, INV-ASSERT-35..37 |
| `Assert::assert_equal` | [ops.md](ops.md) | INV-ASSERT-02 | INV-ASSERT-10, INV-ASSERT-19 | INV-ASSERT-25..26 | INV-ASSERT-27, INV-ASSERT-32 | INV-ASSERT-34..35 | INV-ASSERT-36..39 | shared fixture: INV-ASSERT-43..44 | INV-ASSERT-47 | INV-ASSERT-02, INV-ASSERT-25, INV-ASSERT-35..37 |
| `Assert::assert_not_equal` | [ops.md](ops.md) | INV-ASSERT-03 | INV-ASSERT-20..21 | INV-ASSERT-25..26 | INV-ASSERT-28, INV-ASSERT-32 | INV-ASSERT-34..35 | INV-ASSERT-36..39 | INV-ASSERT-40..42, INV-ASSERT-45 | INV-ASSERT-46, INV-ASSERT-48 | INV-ASSERT-03, INV-ASSERT-21, INV-ASSERT-25, INV-ASSERT-28, INV-ASSERT-35..37 |
| `Assert::assert_equal_if` | [ops.md](ops.md) | INV-ASSERT-04..05 | INV-ASSERT-14..18 | INV-ASSERT-25..26 | INV-ASSERT-30..31 | INV-ASSERT-34..35 | INV-ASSERT-36..39 | INV-ASSERT-44..45 | INV-ASSERT-47 | INV-ASSERT-04..05, INV-ASSERT-25, INV-ASSERT-35..37 |
| `assert_equal_unless` | [ops.md](ops.md) | INV-ASSERT-09 | same conditional equality: INV-ASSERT-14 | INV-ASSERT-25..26 | INV-ASSERT-49 | INV-ASSERT-34..35 | INV-ASSERT-36..39 | shared fixture: INV-ASSERT-43..44 | shared fixture: INV-ASSERT-48 | shared fixture: INV-ASSERT-04..05 |
| `all_equal / array is_equal` | [ops.md](ops.md) | INV-ASSERT-06, INV-ASSERT-08 | INV-ASSERT-23..24 | INV-ASSERT-25..26 | INV-ASSERT-29 | INV-ASSERT-34..35 | INV-ASSERT-36..39 | shared fixture: INV-ASSERT-43..44 | shared fixture: INV-ASSERT-48 | INV-ASSERT-06, INV-ASSERT-25, INV-ASSERT-29, INV-ASSERT-35..37 |
| `assert_all_equal / array assert_equal` | [ops.md](ops.md) | INV-ASSERT-07..08 | INV-ASSERT-22 | INV-ASSERT-25..26 | INV-ASSERT-33 | INV-ASSERT-34..35 | INV-ASSERT-36..39 | shared fixture: INV-ASSERT-43..44 | shared fixture: INV-ASSERT-48 | INV-ASSERT-07, INV-ASSERT-25, INV-ASSERT-35..37 |
| `assert_all_equal_if / array assert_equal_if` | [ops.md](ops.md) | INV-ASSERT-07..08 | INV-ASSERT-22 | INV-ASSERT-25..26 | INV-ASSERT-33 | INV-ASSERT-34..35 | INV-ASSERT-36..39 | shared fixture: INV-ASSERT-43..44 | shared fixture: INV-ASSERT-48 | INV-ASSERT-07, INV-ASSERT-25, INV-ASSERT-35..37 |
| `CircuitVar::assert_product` | [ops.md](ops.md) | INV-ASSERT-PRODUCT-01 | INV-ASSERT-PRODUCT-02..03 | INV-ASSERT-PRODUCT-04 | INV-ASSERT-PRODUCT-05..07, INV-ASSERT-PRODUCT-12 | INV-ASSERT-PRODUCT-08 | INV-ASSERT-PRODUCT-09 | INV-ASSERT-PRODUCT-10 | INV-ASSERT-PRODUCT-11 | INV-ASSERT-PRODUCT-01, INV-ASSERT-PRODUCT-04..05, INV-ASSERT-PRODUCT-08 |
| `Select` for `CircuitVar` | [ops.md](ops.md) | INV-SELECT-01..03 | INV-SELECT-04..10 | INV-SELECT-11 | INV-SELECT-12..17 | INV-SELECT-18 | INV-SELECT-19 | INV-SELECT-20..21 | INV-SELECT-22..23 | INV-SELECT-01, INV-SELECT-03, INV-SELECT-11..12, INV-SELECT-18..19 |
| `Select` for arrays | [ops.md](ops.md) | INV-SELECT-03 | INV-SELECT-10 | INV-SELECT-11 | INV-SELECT-17 | INV-SELECT-18 | INV-SELECT-19 | shared fixture: INV-SELECT-20 | shared fixture: INV-SELECT-23 | INV-SELECT-03, INV-SELECT-11, INV-SELECT-18..19 |
| `poseidon` (all supported arities) | [gadgets.md](gadgets.md) | INV-POSEIDON-01, INV-POSEIDON-03 | INV-POSEIDON-05..07 | INV-POSEIDON-08 | INV-POSEIDON-09..11, INV-POSEIDON-18 | INV-POSEIDON-12 | INV-POSEIDON-04, INV-POSEIDON-13 | INV-POSEIDON-02, INV-POSEIDON-14..15, INV-POSEIDON-19 [partial] | INV-POSEIDON-16..17 | INV-POSEIDON-02, INV-POSEIDON-18 |
| `nonzero_hash_chain` | [gadgets.md](gadgets.md) | INV-HASH-CHAIN-01..02 | INV-HASH-CHAIN-03..05 | INV-HASH-CHAIN-06 | INV-HASH-CHAIN-07..09, INV-HASH-CHAIN-16 | INV-HASH-CHAIN-10 | INV-HASH-CHAIN-11 | INV-HASH-CHAIN-12..13, INV-HASH-CHAIN-17 [partial] | INV-HASH-CHAIN-14..15 | INV-HASH-CHAIN-16 |
| `is_in` | [gadgets.md](gadgets.md) | INV-MEMBER-01..02 | INV-MEMBER-03..04, INV-MEMBER-26, INV-MEMBER-28 | INV-MEMBER-05 | INV-MEMBER-06..07 | INV-MEMBER-08 | INV-MEMBER-09 | INV-MEMBER-10, INV-MEMBER-12..13 | INV-MEMBER-11 | INV-MEMBER-12 |
| `assert_in` | [gadgets.md](gadgets.md) | INV-MEMBER-14 | INV-MEMBER-15..16, INV-MEMBER-27 | INV-MEMBER-17 | INV-MEMBER-18, INV-MEMBER-24 | INV-MEMBER-19 | INV-MEMBER-20..21 | INV-MEMBER-22, INV-MEMBER-25 | INV-MEMBER-23 | INV-MEMBER-24 |
| `one_hot` | [gadgets.md](gadgets.md) | INV-INDEX-01 | INV-INDEX-02..03, INV-INDEX-26, INV-INDEX-28 | INV-INDEX-04 | INV-INDEX-05..07, INV-INDEX-12 | INV-INDEX-08 | INV-INDEX-09 | INV-INDEX-10, INV-INDEX-13 | INV-INDEX-11 | INV-INDEX-12 |
| `select_index` | [gadgets.md](gadgets.md) | INV-INDEX-14 | INV-INDEX-15..16, INV-INDEX-27 | INV-INDEX-17 | INV-INDEX-18..19, INV-INDEX-24 | INV-INDEX-20 | INV-INDEX-21 | INV-INDEX-22, INV-INDEX-25 | INV-INDEX-23 | INV-INDEX-24 |
| `Asset::hash`, `DataHash` | [asset.md](asset.md) | INV-ASSET-03..07 | INV-ASSET-09..11 | INV-ASSET-12 | INV-ASSET-13..15, INV-ASSET-16 [partial] | INV-ASSET-17 | INV-ASSET-08 | INV-ASSET-01..02 | INV-ASSET-18..19 | INV-ASSET-01, INV-ASSET-07..08, INV-ASSET-12..13 |
| `Asset::constant`, `sol`, default | [asset.md](asset.md) | INV-ASSET-03, INV-ASSET-05, INV-ASSET-24 | INV-ASSET-10, INV-ASSET-26 | shared fixture: INV-ASSET-12 | INV-ASSET-29 | INV-ASSET-17 | N/A: constant mint construction | INV-ASSET-01, INV-ASSET-03 | shared fixture: INV-ASSET-19 | shared fixture: INV-ASSET-01 |
| `Asset` Assert methods | [asset.md](asset.md) | INV-ASSET-20..24 | INV-ASSET-25..27 | truth-table fixtures: INV-ASSET-20..23 | INV-ASSET-28..31 | shared fixture: INV-ASSET-17 | INV-ASSET-32 | native equality: INV-ASSET-20..23 | shared fixture: INV-ASSET-19 | INV-ASSET-22 |
| `Asset::select` | [asset.md](asset.md) | INV-ASSET-33 | INV-ASSET-34 | INV-ASSET-35 | INV-ASSET-36 | shared fixture: INV-ASSET-17 | wrong-branch witness: INV-ASSET-36 | chosen native mint: INV-ASSET-33 | shared fixture: INV-ASSET-19 | shared fixture: INV-ASSET-01 |
| `OwnerKey::identity`; `Owner::hash`, `DataHash`, tag check | [owner.md](owner.md) | INV-OWNER-04..10 | INV-OWNER-15..17 | INV-OWNER-18 | INV-OWNER-19..21, INV-OWNER-22 [partial] | INV-OWNER-23 | INV-OWNER-11..14 | INV-OWNER-01..03 | INV-OWNER-24..25 | INV-OWNER-01, INV-OWNER-05, INV-OWNER-11..12, INV-OWNER-18..19 |
| `OwnerKey` / `Owner` Assert methods | [owner.md](owner.md) | INV-OWNER-26..28 | INV-OWNER-29 | native relation fixtures: INV-OWNER-27..28 | INV-OWNER-30..32 | shared fixture: INV-OWNER-23 | refused equality claims: INV-OWNER-30..32 | native key/owner equality: INV-OWNER-26..27 | shared fixture: INV-OWNER-25 | shared fixture: INV-OWNER-01 |
| `OwnerKey` / `Owner::select` | [owner.md](owner.md) | INV-OWNER-33..34 | INV-OWNER-35 | INV-OWNER-36 | INV-OWNER-37 | shared fixture: INV-OWNER-23 | wrong branch: INV-OWNER-34, INV-OWNER-37 | native chosen owner: INV-OWNER-33 | shared fixture: INV-OWNER-25 | shared fixture: INV-OWNER-01 |
| `PublicTransfer::hash` | [transfer.md](transfer.md) | INV-TRANSFER-03 | transaction flows: INV-TX-06..07 | transaction flows: INV-TX-08 | transaction flows: INV-TX-10..12 | transaction fixtures: INV-TX-06, INV-TX-08 | transaction validation: INV-TX-14 | INV-TRANSFER-01..02 | settlement proof: INV-TX-20 | INV-TRANSFER-01 |
| `program::transaction_hash` | [transfer.md](transfer.md) | INV-TRANSFER-04..06 | transaction flows: INV-TX-06..07 | transaction flows: INV-TX-08 | transaction flows: INV-TX-10..12 | transaction fixtures: INV-TX-06, INV-TX-08 | INV-TRANSFER-07 | native finalized transaction: INV-TX-01 | settlement proof: INV-TX-20 | INV-TRANSFER-04..05 |
| `Utxo::hash`, nullifier, `SpentInput` | [utxo.md](utxo.md) | INV-UTXO-06..10 | INV-UTXO-15 | INV-UTXO-16 | INV-UTXO-17..22, INV-UTXO-23 [partial] | INV-UTXO-24 | INV-UTXO-12..14 | INV-UTXO-01..05, INV-UTXO-11 | INV-UTXO-25..26 | INV-UTXO-01, INV-UTXO-07, INV-UTXO-12, INV-UTXO-16..17 |
| `Utxo::dummy` | [utxo.md](utxo.md) | INV-UTXO-09..10 | INV-UTXO-15 | INV-UTXO-16 | INV-UTXO-22 | INV-UTXO-24 | dummy-only tag exception: INV-UTXO-22 | INV-UTXO-11 | shared fixture: INV-UTXO-26 | shared fixture: INV-UTXO-01 |
| `UtxoTrait::transfer` (token/data) | [utxo.md](utxo.md) | INV-LEDGER-01 | INV-LEDGER-07..10 | INV-LEDGER-11 | INV-LEDGER-12..14, INV-LEDGER-15..16 [partial] | check_constraints transfer fixtures: INV-LEDGER-11 | INV-LEDGER-17..21, INV-LEDGER-22 | native balances: INV-LEDGER-01 | transfer witness / withdrawal proof fixtures: INV-LEDGER-23..24 | INV-LEDGER-01, INV-LEDGER-11, INV-LEDGER-17 |
| `UtxoTrait::transfer_all` (token/data) | [utxo.md](utxo.md) | INV-LEDGER-02 | INV-LEDGER-07..10 | INV-LEDGER-11 | INV-LEDGER-12..14, INV-LEDGER-15..16 [partial] | check_constraints transfer fixtures: INV-LEDGER-11 | INV-LEDGER-17..21, INV-LEDGER-22 | native balances: INV-LEDGER-02 | transfer witness / withdrawal proof fixtures: INV-LEDGER-23..24 | INV-LEDGER-11, INV-LEDGER-17 |
| `UtxoTrait::withdraw` (token/data) | [utxo.md](utxo.md) | INV-LEDGER-03 | INV-LEDGER-07..10 | INV-LEDGER-11 | INV-LEDGER-12..14, INV-LEDGER-15..16 [partial] | check_constraints transfer fixtures: INV-LEDGER-11 | INV-LEDGER-17..21, INV-LEDGER-22 | native balances: INV-LEDGER-03 | transfer witness / withdrawal proof fixtures: INV-LEDGER-23..24 | INV-LEDGER-03, INV-LEDGER-11, INV-LEDGER-17 |
| `UtxoTrait::withdraw_all` (token/data) | [utxo.md](utxo.md) | INV-LEDGER-04 | INV-LEDGER-07..10 | INV-LEDGER-11 | INV-LEDGER-12..14, INV-LEDGER-15..16 [partial] | check_constraints transfer fixtures: INV-LEDGER-11 | INV-LEDGER-17..21, INV-LEDGER-22 | native balances: INV-LEDGER-04 | transfer witness / withdrawal proof fixtures: INV-LEDGER-23..24 | INV-LEDGER-11, INV-LEDGER-17 |
| `UtxoTrait::deposit` (token/data) | [utxo.md](utxo.md) | INV-LEDGER-05 | INV-LEDGER-07..10 | INV-LEDGER-11 | INV-LEDGER-12..14, INV-LEDGER-15..16 [partial] | check_constraints transfer fixtures: INV-LEDGER-11 | INV-LEDGER-17..21, INV-LEDGER-22 | native balances: INV-LEDGER-05 | transfer witness / withdrawal proof fixtures: INV-LEDGER-23..24 | INV-LEDGER-11, INV-LEDGER-17 |
| `UtxoTrait::amount / owner / asset` (token/data) | [utxo.md](utxo.md) | INV-LEDGER-06 | INV-LEDGER-07..10 | INV-LEDGER-11 | INV-LEDGER-12..14, INV-LEDGER-15..16 [partial] | check_constraints transfer fixtures: INV-LEDGER-11 | INV-LEDGER-17..21, INV-LEDGER-22 | native owner/asset: INV-LEDGER-06 | transfer witness / withdrawal proof fixtures: INV-LEDGER-23..24 | INV-LEDGER-11, INV-LEDGER-17 |
| `TokenUtxos::new_mut` | [utxo.md](utxo.md) | INV-TOKEN-02 | INV-TOKEN-03..04 | INV-TOKEN-05 | INV-TOKEN-06..08 | spend fixtures: INV-TOKEN-03, INV-TOKEN-05 | INV-TOKEN-09..10 | INV-TOKEN-01 | refresh/payment fixtures: INV-TX-17..18 | INV-TOKEN-01 |
| `TokenUtxos::new_init` | [utxo.md](utxo.md) | INV-TX-01..03 | INV-TX-06..07 | INV-TX-08 | INV-TX-09..12, INV-TX-13 [partial] | transaction fixtures: INV-TX-06, INV-TX-08 | INV-TX-14..15 | INV-TX-01..03 | refresh/payment fixtures; burns have no separate proof: INV-TX-17..18 | INV-TX-01 |
| `TokenUtxos::new_burn` | [utxo.md](utxo.md) | INV-TX-01..03 | INV-TX-06..07 | INV-TX-08 | INV-TX-09..12, INV-TX-13 [partial] | transaction fixtures: INV-TX-06, INV-TX-08 | INV-TX-14..15 | INV-TX-01..03 | refresh/payment fixtures; burns have no separate proof: INV-TX-17..18 | INV-TX-01 |
| `TokenUtxos::change` | [utxo.md](utxo.md) | INV-TX-01..03, INV-TX-22 | INV-TX-06..07 | INV-TX-08 | INV-TX-09..12, INV-TX-13 [partial], INV-TX-23 | transaction fixtures: INV-TX-06, INV-TX-08 | INV-TX-14..15 | INV-TX-01..03 | refresh/payment fixtures; burns have no separate proof: INV-TX-17..18 | INV-TX-01 |
| `DataUtxo::new_mut` | [utxo.md](utxo.md) | INV-DATA-02 | INV-DATA-06..07 | INV-DATA-08 | INV-DATA-09..10 | held/fresh fixtures: INV-DATA-06, INV-DATA-08 | INV-DATA-11..12 | native state: INV-DATA-01 | funded counter update fixture: INV-TX-19 | shared fixture: INV-TX-01 |
| `DataUtxo::new_init` | [utxo.md](utxo.md) | INV-DATA-03 | INV-DATA-06..07 | INV-DATA-08 | INV-DATA-09..10 | held/fresh fixtures: INV-DATA-06, INV-DATA-08 | INV-DATA-11..12 | native state: INV-DATA-01 | funded counter update fixture: INV-TX-19 | shared fixture: INV-TX-01 |
| `DataUtxo::new_burn` | [utxo.md](utxo.md) | INV-DATA-01 | INV-DATA-06..07 | INV-DATA-08 | INV-DATA-09..10 | held/fresh fixtures: INV-DATA-06, INV-DATA-08 | INV-DATA-11..12 | native state: INV-DATA-01 | funded counter update fixture: INV-TX-19 | shared fixture: INV-TX-01 |
| `UtxoData / checked_utxo_data` | [utxo.md](utxo.md) | INV-DATA-04 | INV-DATA-06..07 | INV-DATA-08 | INV-DATA-09..10 | held/fresh fixtures: INV-DATA-06, INV-DATA-08 | INV-DATA-05, INV-DATA-11..12 | native state: INV-DATA-04 | funded counter update fixture: INV-TX-19 | shared fixture: INV-TX-01 |
| `TxContext output blindings / output tree` | [transaction.md](transaction.md) | INV-TX-01..03 | INV-TX-06..07 | INV-TX-08 | INV-TX-09..12, INV-TX-13 [partial], INV-TX-21 [partial] | native/proving transaction shapes: INV-TX-06, INV-TX-08 | INV-TX-14..15 | INV-TX-01..03 | INV-TX-16..20 | random transaction oracle: INV-TX-01 |
| `ConfidentialTransaction::check / transaction hashes` | [transaction.md](transaction.md) | INV-TX-01, INV-TX-03..04, INV-TX-22 | INV-TX-06..07 | INV-TX-08 | INV-TX-09..12, INV-TX-13 [partial], INV-TX-21 [partial], INV-TX-23 | native/proving transaction shapes: INV-TX-06, INV-TX-08 | INV-TX-14..15 | INV-TX-01, INV-TX-03..04 | INV-TX-16..20 | random transaction oracle: INV-TX-01 |
| `PublicInputs / public hash` | [transaction.md](transaction.md) | INV-TX-05 | INV-TX-06..07 | INV-TX-08 | INV-TX-09..12, INV-TX-13 [partial], INV-TX-21 [partial] | native/proving transaction shapes: INV-TX-06, INV-TX-08 | INV-TX-14..15 | INV-TX-05 | INV-TX-16..20 | random transaction oracle: INV-TX-01 |

## Scope of shared fixtures

- Field arithmetic has operation-specific circom references and snarkjs proofs. Bit
  methods share range-check interoperability; the 253-bit proof is a range-check fixture.
  Constant construction and identity conversions introduce no separate nonlinear relation.
- Bool gate witnesses cover the gate fixtures. Equality assertions share the `is_equal`
  reference; `assert_true` and `assert_false` have direct row/truth-table checks, while
  the external assertion reference targets `assert_true_if`.
- Uint coverage follows every public-operation heading in [`uint.md`](uint.md), including
  owned/borrowed construction, ten alias widening/narrowing pairs, checked arithmetic,
  cross-width equality, range/zero checks and division. Goldens use four-bit fixtures;
  wide counts and digests cover the specified 64–253-bit bounds. Groth16 targets construction,
  narrowing, checked multiplication, sum, less-than, division, selection and zero fixtures.
  `random_u64_relations_match_the_integer_reference` also checks selection and range;
  their semantic IDs are listed in Properties alongside the operation-specific generated
  checks for the other conversions and assertions. Compile-time invalid width combinations
  are outside the runtime fixture domain.
- Bytes checks cover every conversion width 0–31 and reject width 32; hash vectors cross
  31-byte packing boundaries. Public byte hashing requires `Bytes<N>`; the raw
  fixed-array helper is crate-private, with the protocol owner-tag path retaining
  its conditional dummy-tag check. Hashes have fixed-length semantics: this is not a
  length-separated commitment to arbitrary byte strings. Groth16 fixtures are pack31,
  hash32 and select32; the assertion fixtures also have snarkjs witness checks.
- Scalar/array `Assert` and `Select` share trait-level fixtures. The inverse relation,
  equality flag and conditional equality have distinct references; array helpers use those
  components. `assert_equal_unless` is crate-private and is reached through the owner-tag
  route plus a variable-skip regression.
- Asset and owner native hashes are compared to the native Zolana implementations. Their
  hash proofs are representative fixtures; their equality/select rows have separate native,
  constraint and tamper checks.
- Circuit `PublicTransfer` is crate-private. Its R1CS behavior is exercised through transaction
  flows; [`transfer.md`](transfer.md) separately checks native hash definitions and ordering.
  Balance tests cover token/data holder combinations; the standalone Groth16 balance fixture
  is a withdrawal. Token initialization/change/burn and data updates are also exercised
  inside transaction fixtures, rather than each receiving a standalone proof.
- Transaction native oracles rebuild the shapes using `FinalizedTransaction`. Refresh, payment, funded data-update and public-settlement interop fixtures
  have passing witness/tamper checks and Groth16 proofs. Burn/sweep paths have native and R1CS fixtures but no
  separately indexed Groth16 proof. Public hashes in the constraint-only asserted fixtures
  are witness claims; the snarkjs proof has no public signals.

The cross-cutting checks are indexed separately: native/R1CS agreement (INV-XC-01),
iden3 exports and parsing (INV-XC-02), setup/proving shape (INV-XC-03), the constraint-only
statement (INV-XC-04), its lack of a public hash to tamper (INV-XC-05), detached
solver cleanup (INV-XC-06), and independent executions of cached circom modules
(INV-XC-07), in [`cross-cutting.md`](cross-cutting.md).

## Checklist totals

These totals count invariant entries, not tests or distinct circuits. They reflect the
current checkboxes and their recorded passing postconditions.

| File | Total | Checked | Partial | Findings |
|---|---:|---:|---:|---:|
| [asset.md](asset.md) | 36 | 35 | 1 | 0 |
| [bool.md](bool.md) | 121 | 121 | 0 | 0 |
| [bytes.md](bytes.md) | 91 | 84 | 7 | 0 |
| [circuit_var.md](circuit_var.md) | 262 | 262 | 0 | 0 |
| [cross-cutting.md](cross-cutting.md) | 7 | 7 | 0 | 0 |
| [gadgets.md](gadgets.md) | 92 | 90 | 2 | 0 |
| [ops.md](ops.md) | 84 | 84 | 0 | 0 |
| [owner.md](owner.md) | 37 | 36 | 1 | 0 |
| [transaction.md](transaction.md) | 23 | 21 | 2 | 0 |
| [transfer.md](transfer.md) | 7 | 7 | 0 | 0 |
| [uint.md](uint.md) | 217 | 211 | 6 | 0 |
| [utxo.md](utxo.md) | 72 | 69 | 3 | 0 |
| **Total** | **1049** | **1027** | **22** | **0** |

Severity: **299 Critical**, **497 High**, **250 Medium**, **3 Low**. The reference audit
matches **1,252 Covered-by references** to passing test output, with no missing file/test or duplicate invariant ID.

The matrix contains **114 operation rows**. Every category has a direct or explicitly
scoped fixture reference, except operation-specific errors marked N/A for infallible APIs.

## Partial coverage and findings

All **22 partial entries** concern bounded Picus determinism checks. A successful test that
permits `Unknown` establishes no determinism result for that run. Some small/normalized
fixtures returned `Safe` in focused runs and `Unknown` under concurrent load; those entries
remain partial. Tamper tests and private-variable perturbation checks support their own
claims but do not prove uniqueness of a witness whose variables move together.

- [asset.md](asset.md): INV-ASSET-16 [partial].
- [bytes.md](bytes.md): INV-BYTES-ALLOC-12 [partial], INV-BYTES-SPLIT-17 [partial], INV-BYTES-PACK-13 [partial], INV-BYTES-ASSERT-15 [partial], INV-BYTES-SELECT-09 [partial], INV-HASH-BYTES-15..16 [partial].
- [gadgets.md](gadgets.md): INV-POSEIDON-19 [partial], INV-HASH-CHAIN-17 [partial].
- [owner.md](owner.md): INV-OWNER-22 [partial].
- [transaction.md](transaction.md): INV-TX-13 [partial], INV-TX-21 [partial].
- [uint.md](uint.md): INV-UINT-PICUS-01..06 [partial].
- [utxo.md](utxo.md): INV-UTXO-23 [partial], INV-LEDGER-15..16 [partial].

No ignored finding reproductions remain. Native proof inputs are deliberately
constants and readable (INV-CV-CONST-06, active characterization); R1CS proof
inputs reject reads at their source location (INV-CV-CONST-05, active regression).
The API documentation states both behaviors. Dummy UTXO commitment parity is
covered by the active INV-UTXO-11 regression and native/proving/interop checks.

Oversized balance and byte-splitting errors retain the caller location
(INV-LEDGER-22 and INV-BYTES-SPLIT-13); their active regressions check caller files
and lines through native and prover paths. The per-type checklists declare no additional
`SPEC_DIVERGENCE` items beyond the documented findings.

**Additional transaction proofs:** INV-TX-18 (payment), INV-TX-19 (funded data update),
and INV-TX-20 (public deposit/withdrawal) passed in the full external lane and are checked.

## Running the checks

From the repository root:

```sh
just test-zolana-program
just test-zolana-program-unit
just test-zolana-program-external
just test-zolana-program-unit bytes::
just test-zolana-program-external harness::picus::timeout_cleanup
```

`just test-zolana-program` checks three crates (`zolana-program`, `zolana-macros`,
`timelock-escrow-program`) with tests/all features, runs the
hermetic unit lane, runs the external lane twice, then runs release tests for the SDK,
macros and arkworks example. The two focused recipes accept an optional test-name filter.

The hermetic unit lane needs no circom, snarkjs or Picus installation. The external lane
runs in release mode with four test threads, adds the test-only `external-tools` feature,
and requires circom, snarkjs (and its Node
runtime), `run-picus`, Racket, cvc5 with finite-field/CoCoA support, and git on PATH.
The recorded tool baseline is circom 2.2.3, snarkjs 0.7.6, Picus 138b151 and cvc5 1.4.1.
`run-picus` must be a working wrapper that locates its Racket installation, not a broken
symlink. Process-table and signal access through `ps`/`kill` is required: Picus starts
solvers in separate process groups, so timeout cleanup discovers and terminates detached
solver descendants before terminating Picus. The focused cleanup regression exercises
that behavior. Compiled Wasmer modules are cached with content-sensitive keys; INV-XC-07
checks concurrent/repeated calculations, changing bytes at the same path, and the
independence of Abort and Ignore assertion handlers.

circomlib is GPL-3.0 and is not committed. The harness fetches pinned commit
`35e54ea21da3e8762557234298dbb553c175ea8d`, or uses a clean checkout at that commit supplied
through `CIRCOMLIB_DIR`:

```sh
CIRCOMLIB_DIR=/path/to/circomlib just test-zolana-program-external
```

Compiled circom artifacts, throwaway Powers-of-Tau files selected by circuit size, and the
pinned circomlib checkout are cached beneath `CARGO_TARGET_TMPDIR/zolana-program-unit`
with file locks. Ceremony artifacts are local test material. Picus limits are per fixture;
`Unsafe` fails a determinism assertion and `Unknown` remains partial where permitted.

## Validation (2026-09-28)

The current full SDK unit suite passes **661 tests with zero failures and zero
ignored tests**.

Validation also includes four-crate checks with all features/tests, two complete
external runs, SDK/macros/example release suites, and subsequent focused checks
for the API and commitment changes. The checked-byte migration passed 75 affected
protocol tests, 12 external byte-hash tests, and the six-fixture compile-fail suite.
Dummy hashing passed all three UTXO snarkjs tests, including a native dummy proof
and refusal of the former incorrect commitment, plus escrow/withdrawal proof and
functional lifecycle tests. No solver processes remained after the complete
external runs.

All **1,248 Covered-by references** resolve to passing tests.

The standalone variable-domain UTXO-hash fixture now has 2167 rows and 2178 variables;
its keys must be generated for those updated matrices. TokenUtxos/DataUtxo transaction
size/digest pins remain unchanged. Public byte hashing requires checked `Bytes<N>`
with a fixed length per protocol domain; cross-length aliases are not a general
byte-string hashing contract.

## Maintaining this index

Add stable IDs using [`PROMPT.md`](PROMPT.md), then implement fixtures and native, R1CS,
property and external checks under the relevant `tests/unit/` directory. Keep external
modules behind `external-tools`; use the shared fixture/equivalence/export harness.
Tick only the postconditions that passing tests assert. Record an unresolved
postcondition as partial or a finding, name every `Covered by` test, and update this matrix
and the totals after auditing those references. Shared or representative proof coverage
must retain its scope label.
