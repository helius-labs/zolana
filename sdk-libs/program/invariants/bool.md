# Bool Invariants

Covers `Bool` of `src/circuit/builtins/types/boolean.rs`: `constant`,
`TryFrom<CircuitVar>`, `TryFrom<&CircuitVar>`, `not`, `and`, `or`, `xor`, `nand`,
`implies`, `all`, `any`, `select`, `assert_true`, `assert_false`, `assert_true_if`, its
`Assert` and `Select` impls, and `From<Bool>` for `CircuitVar` and for `Uint<BITS>`.
Invariants every builtin shares live in `cross-cutting.md`. ID prefixes: `INV-BOOL-CONV`,
`INV-BOOL-GATE`, `INV-BOOL-FOLD`, `INV-BOOL-SEL`, `INV-BOOL-ASSERT`, `INV-BOOL-EQ`; the tests
live in `tests/unit/bool/`.

The fixtures in `tests/unit/bool/fixtures.rs` take every operand as a `Field` private input
and turn it into a `Bool` with `Bool::try_from`, so a non-boolean operand reaches the
conversion; each asserts `CircuitVar::from(<operation>) == out` with a named rule. The
oracles are independent of the SDK: a hardcoded truth table per gate (for (a, b) = (0, 0),
(0, 1), (1, 0), (1, 1)), `Iterator::all`/`any` for the folds, `if c { t } else { f }` for
`select`, and a hardcoded "holds" table per assertion. The expected claim row of a gate is
the multilinear polynomial that agrees with its truth table on {0, 1}^2, which is also
circomlib's arithmetization of its gates. The vectors are the boolean operands, the
non-boolean operands 2, p - 1, (p + 1) / 2 (the inverse of 2), 2^64 and a 254-bit x, the
wrong claims (the negation, 2, p - 1, x), and two deceptive fold vectors whose sum is the one
the fold compares against: `all` over [2, 0, 1] sums to 3, and `any` over [1, p - 1, 0] sums
to 0.

Every exported row below lists its terms as `{wire: coefficient}`. Wire 0 is the constant
one; the inputs follow in field order, then the witnesses a gadget allocates. Where the
statement says "as a set of terms", the exported order of a row's terms is not pinned.

## Conversions (`constant`, `TryFrom<CircuitVar>`, `TryFrom<&CircuitVar>`, `From<Bool>`)

The conversion fixture `Converted<FORM>` asserts `convert(x) == out` for five forms:
`CircuitVar::from(Bool::try_from(x))`, the same with `&x`, and `CircuitVar::from` of
`Uint::<1>::from`, `Uint::<64>::from` and `Uint::<253>::from` of `Bool::try_from(&x)`.

### Semantics

- [x] **INV-BOOL-CONV-01: a Bool constant is exactly 0 or 1 and a constant**
  - Covered by: `tests/unit/bool/native.rs` `a_bool_constant_is_exactly_zero_or_one_and_a_constant`
  - Kind: semantics
  - Statement: for both booleans k, the native value of `CircuitVar::from(Bool::constant(k))` is exactly `Field::from(k)` and its `Debug` form is exactly `CircuitVar::constant(<0 or 1>)`.
  - Location: `src/circuit/builtins/types/boolean.rs:15-17` (`fn constant`), `src/circuit/builtins/types/boolean.rs:102-106` (`impl From<Bool> for CircuitVar`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/native.rs`

- [x] **INV-BOOL-CONV-02: TryFrom accepts exactly the values 0 and 1 and keeps the value**
  - Covered by: `tests/unit/bool/native.rs` `try_from_accepts_exactly_the_constants_zero_and_one_in_both_forms`; `tests/unit/bool/native.rs` `every_boolean_vector_holds_natively_in_every_output_fixture`
  - Kind: semantics
  - Statement: for the constants 0 and 1, `Bool::try_from(var)` and `Bool::try_from(&var)` both return a `Bool` whose value is exactly the input and which is still a constant; for every boolean x, every conversion form of the fixture computes exactly the constant x natively.
  - Location: `src/circuit/builtins/types/boolean.rs:108-125` (`impl TryFrom<CircuitVar>`, `impl TryFrom<&CircuitVar>`), `src/circuit/builtins/field/bits.rs:50-62` (`fn assert_bool`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/native.rs`

- [x] **INV-BOOL-CONV-03: From<Bool> keeps the value in a CircuitVar and in every Uint width**
  - Covered by: `tests/unit/bool/native.rs` `from_bool_keeps_the_value_in_a_circuit_var_and_in_every_uint_width`
  - Kind: semantics
  - Statement: for both booleans k, `CircuitVar::from` of `Bool::constant(k)`, of `Uint::<1>::from(Bool::constant(k))`, of `Uint::<64>::from(...)` and of `Uint::<253>::from(...)` are each exactly the constant k.
  - Location: `src/circuit/builtins/types/boolean.rs:102-106` (`impl From<Bool> for CircuitVar`), `src/circuit/builtins/types/uint.rs:294-298` (`impl From<Bool> for Uint<BITS>`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/native.rs`

### Constraint

- [x] **INV-BOOL-CONV-04: a Bool constant allocates nothing and puts its value on variable 0**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_bool_constant_allocates_nothing_and_puts_its_value_on_variable_zero`
  - Kind: constraint
  - Statement: `CircuitVar::from(Bool::constant(k)).assert_equal(&out, rule)` exports exactly 2 variables and the one row A = {1: -1} for k = false and A = {0: 1, 1: -1} for k = true, with B = {0: 1} and C = {}.
  - Location: `src/circuit/builtins/types/boolean.rs:15-17` (`fn constant`)
  - Severity: Medium
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-CONV-05: every Bool operation on constants adds no constraint and no variable**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_operation_on_constants_adds_no_constraint_and_no_variable`
  - Kind: constraint
  - Statement: a circuit that runs every gate, `select`, `all`, `any`, `TryFrom`, `From<Bool>` for `Uint<64>` and every holding assertion on constants only exports exactly 1 variable (the constant one) and 0 constraints, its assignment is exactly `[1]`, and `check_constraints` returns exactly `Ok(0)`.
  - Location: `src/circuit/builtins/types/boolean.rs:13-152` (`impl Bool`, `impl Assert for Bool`, `impl Select for Bool`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-CONV-06: converting a variable adds exactly the booleanity row and no variable**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_conversion_exports_exactly_the_booleanity_row_then_the_claim_row_in_every_form`
  - Kind: constraint
  - Statement: `CircuitVar::from(Bool::try_from(&x)?).assert_equal(&out, rule)` exports exactly the header of 3 variables, 0 public inputs, 2 private inputs and 2 constraints, row 0 A = {1: 1}, B = {0: -1, 1: 1}, C = {} (x * (x - 1) = 0), and row 1 A = {1: 1, 2: -1}, B = {0: 1}, C = {}: the conversion back into a `CircuitVar` adds nothing.
  - Location: `src/circuit/builtins/field/bits.rs:50-62` (`fn assert_bool`), `src/circuit/builtins/types/boolean.rs:108-125` (`impl TryFrom`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-CONV-07: every conversion form exports byte-identical R1CS**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_conversion_exports_exactly_the_booleanity_row_then_the_claim_row_in_every_form`
  - Kind: constraint
  - Statement: the five conversion forms (owned and borrowed `TryFrom`, and the round trips through `Uint<1>`, `Uint<64>` and `Uint<253>`) export byte-identical `.r1cs` files: `From<Bool>` for `Uint<BITS>` adds no range check.
  - Location: `src/circuit/builtins/types/boolean.rs:118-125` (`impl TryFrom<&CircuitVar>`), `src/circuit/builtins/types/uint.rs:294-298` (`impl From<Bool> for Uint<BITS>`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/r1cs.rs`

### Completeness

- [x] **INV-BOOL-CONV-08: every boolean value satisfies every row of every conversion form**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_boolean_vector_satisfies_every_exported_row_and_every_proving_row`
  - Kind: completeness
  - Statement: for x in {0, 1} and out = x, the exported assignment of every conversion form satisfies every exported row (`first_unsatisfied` is exactly `None`), and `check_constraints` returns exactly `Ok(2)`.
  - Location: `src/circuit/builtins/field/bits.rs:50-62` (`fn assert_bool`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/r1cs.rs`

### Soundness

- [x] **INV-BOOL-CONV-09: a non-boolean value leaves exactly the booleanity row unsatisfied**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_non_boolean_operand_breaks_exactly_its_booleanity_rows_with_every_other_row_satisfied`
  - Kind: soundness
  - Statement: for every non-boolean vector x, the witness `[1, x, x]` leaves exactly row 0 of the conversion fixture's export unsatisfied: the claim row holds, and only the booleanity row refuses x.
  - Location: `src/circuit/builtins/field/bits.rs:50-62` (`fn assert_bool`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-CONV-10: no private variable of a conversion fixture is free**
  - Covered by: `tests/unit/bool/r1cs.rs` `no_private_variable_is_free_and_only_an_equal_sided_inverse_hint_is_tolerated`
  - Kind: soundness
  - Statement: for x in {0, 1} and every conversion form, `check_private_variables` reports exactly 2 constraints, 2 private variables, no free variable and no tolerated variable.
  - Location: `src/testing.rs:70-99` (`fn check_private_variables`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-CONV-11: Picus proves the converted output fixed by the input**
  - Covered by: `tests/unit/bool/picus.rs` `picus_finds_every_conversion_and_constant_operand_output_fixed`
  - Kind: soundness
  - Statement: `run-picus --solver cvc5` reports exactly Safe for the conversion fixture's Picus export with `out` promoted to an output.
  - Location: `src/prover/snarkjs.rs:20-45` (`fn picus_r1cs`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/bool/picus.rs`

### Shape

- [x] **INV-BOOL-CONV-12: setup and proving produce identical conversion matrices**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_boolean_vector_satisfies_every_exported_row_and_every_proving_row`
  - Kind: shape
  - Statement: for x in {0, 1} and every conversion form, `check_constraints` returns exactly `Ok(2)`: the placeholder's setup synthesis and the proof's synthesis have the same shape and the same rows.
  - Location: `src/prover/synthesis.rs:405-429` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/r1cs.rs`

### Error

- [x] **INV-BOOL-CONV-13: natively a non-boolean value fails with exactly NotZeroOrOne at the caller**
  - Covered by: `tests/unit/bool/native.rs` `try_from_accepts_exactly_the_constants_zero_and_one_in_both_forms`; `tests/unit/bool/native.rs` `every_non_boolean_operand_is_refused_natively_with_not_zero_or_one`
  - Kind: error
  - Statement: for every non-boolean vector x, `Bool::try_from(constant(x))` and `Bool::try_from(&constant(x))` return exactly `CircuitError.NotZeroOrOne` with no rule, located in the file that calls `try_from`; the native run of every conversion form fails the same way, located in the fixture's file.
  - Location: `src/circuit/builtins/field/bits.rs:50-58` (`fn assert_bool`, the constant branch)
  - Error: `CircuitErrorKind::NotZeroOrOne`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/bool/native.rs`

- [x] **INV-BOOL-CONV-14: in the proving rows a non-boolean input breaks its booleanity row with the SDK rule**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_non_boolean_input_breaks_its_booleanity_row_in_the_proving_rows_with_the_sdk_rule`; `tests/unit/bool/properties.rs` `a_non_boolean_input_of_every_gate_breaks_its_booleanity_row_in_the_proving_rows` (property)
  - Kind: error
  - Statement: for every input wire w of the conversion forms, `not`, every constant operand form, every two-operand gate (at (1, 0), and at random boolean pairs in the property), `all` of three flags, `select`, `assert_true`, `assert_equal`, `assert_equal_if` and `true.assert_true_if(x)`, each on an honest boolean vector, `check_tampered` with w set to 2 or to p - 1 (and, for every gate, to a random non-boolean value) returns exactly `ProverError.ProofInputsBreakRule` at row w - 1 labelled "a value is neither 0 nor 1".
  - Location: `src/circuit/builtins/field/bits.rs:28-30` (`fn check_is_bool`), `src/circuit/builtins/field/bits.rs:59-61` (`fn assert_bool`, the variable branch)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/bool/r1cs.rs`, `tests/unit/bool/properties.rs`

- [x] **INV-BOOL-CONV-15: a wrong converted claim fails with exactly the fixture rule**
  - Covered by: `tests/unit/bool/native.rs` `every_wrong_claim_breaks_exactly_the_fixture_rule_natively`; `tests/unit/bool/r1cs.rs` `a_claim_off_by_one_breaks_exactly_the_claim_row_with_the_fixture_rule`
  - Kind: error
  - Statement: for x in {0, 1} and every wrong claim, the native run of every conversion form returns exactly `CircuitError.RuleBroken` with "the output is the converted value" located in the fixture's file, and `check_tampered` with `out` moved by +1 or -1 returns exactly `ProverError.ProofInputsBreakRule` at row 1 with that rule.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Error: `CircuitErrorKind::RuleBroken`, `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/bool/native.rs`, `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-CONV-16: the prover refuses a non-boolean operand before synthesis**
  - Covered by: `tests/unit/bool/r1cs.rs` `the_prover_refuses_a_non_boolean_operand_or_a_broken_assertion_before_synthesis`
  - Kind: error
  - Statement: `check_constraints` and `export_assignment` of the `Not` fixture with a = 2 fail with exactly `CircuitError.NotZeroOrOne` and no failed row: the native run inside `ArkworksCircuit::new` refuses the operand before any constraint is synthesized.
  - Location: `src/prover/synthesis.rs:391-396` (`fn new`), `src/circuit/builtins/field/bits.rs:50-58` (`fn assert_bool`)
  - Error: `CircuitErrorKind::NotZeroOrOne`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

### Equivalence

- [x] **INV-BOOL-CONV-17: the booleanity check refuses exactly what circom's `x * (x - 1) === 0` refuses**
  - Covered by: `tests/unit/bool/external.rs` `not_is_relation_equivalent_to_circomlib_not`; `tests/unit/bool/external.rs` `every_two_operand_gate_is_relation_equivalent_to_its_circom_reference`
  - Kind: equivalence
  - Statement: for every non-boolean vector (and every non-boolean pair), the SDK natively, the SDK export against a witness whose every other wire is consistent, circom's witness calculation and circom's R1CS against its own witness all refuse the operand, and all four accept every boolean operand with its honest claim.
  - Location: `src/circuit/builtins/field/bits.rs:50-62` (`fn assert_bool`), `tests/unit/bool/circom/not.circom`, `tests/unit/harness/equivalence.rs` (`fn assert_relation_equivalent`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/bool/external.rs`

### Interop

- [x] **INV-BOOL-CONV-18: snarkjs rejects a non-boolean operand whose other rows hold**
  - Covered by: `tests/unit/bool/external.rs` `snarkjs_accepts_every_honest_gate_witness_and_rejects_a_flipped_or_non_boolean_one`
  - Kind: interop
  - Statement: for every gate and every boolean pair, `snarkjs wtns check` rejects the SDK export with the honest assignment whose a is 2 and whose product and claim are recomputed for a = 2.
  - Location: `src/circuit/builtins/field/bits.rs:59-61` (`fn assert_bool`), `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: Critical
  - Suggested test: external (snarkjs); `tests/unit/bool/external.rs`

## Gates (`not`, `and`, `or`, `xor`, `nand`, `implies`)

`Variables<GATE>` asserts `gate(a, b) == out` for the gates `and`, `or`, `xor`, `nand`,
`implies` and `is_equal` (`is_equal` is the `Assert` impl's, covered in `INV-BOOL-EQ` on the
same fixture); `Not` asserts `a.not() == out`; `WithConstant<GATE, FORM>` computes each gate
with one operand the constant false or true, first or second. The circom references wrap
circomlib's `AND`, `OR`, `XOR`, `NAND` and `NOT` in `tests/unit/bool/circom/` with a
booleanity line per input, since circomlib's gates constrain none; `implies.circom` is our own
`out <== 1 - a + a*b`.

### Semantics

- [x] **INV-BOOL-GATE-01: on constants every gate is exactly its truth table and stays a constant**
  - Covered by: `tests/unit/bool/native.rs` `every_gate_on_constants_is_its_truth_table_and_stays_a_constant`
  - Kind: semantics
  - Statement: for every gate and every pair of Bool constants, the result is a constant whose value is exactly the gate's hardcoded truth-table entry; `not` maps 0 to exactly 1 and 1 to exactly 0, and `not().not()` is exactly the input.
  - Location: `src/circuit/builtins/types/boolean.rs:32-58` (`fn not`, `fn and`, `fn or`, `fn xor`, `fn nand`, `fn implies`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/native.rs`

- [x] **INV-BOOL-GATE-02: natively every gate fixture holds exactly on its truth table**
  - Covered by: `tests/unit/bool/native.rs` `every_boolean_vector_holds_natively_in_every_output_fixture`; `tests/unit/bool/properties.rs` `natively_every_gate_refuses_exactly_the_non_boolean_operands_and_holds_exactly_on_its_truth_table` (property)
  - Kind: semantics
  - Statement: for every gate, every boolean pair and every claim drawn from 0, 1 and random field elements, the native run of `Variables<GATE>` holds exactly when the claim equals the truth-table entry; with the honest claim, the native runs of `Variables<GATE>` and `Not` hold and their computed output is exactly that entry as a constant.
  - Location: `src/circuit/builtins/types/boolean.rs:32-58`
  - Severity: High
  - Suggested test: positive + property; `tests/unit/bool/native.rs`, `tests/unit/bool/properties.rs`

- [x] **INV-BOOL-GATE-03: every constant operand form computes the truth table**
  - Covered by: `tests/unit/bool/native.rs` `every_boolean_vector_holds_natively_in_every_output_fixture`
  - Kind: semantics
  - Statement: for every gate, every constant k in {false, true}, both operand orders and every boolean a, the native output of the gate with a variable a and the constant k is exactly the truth-table entry of (a, k), or of (k, a) when the constant comes first.
  - Location: `src/circuit/builtins/types/boolean.rs:32-58`
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/native.rs`

### Constraint

- [x] **INV-BOOL-GATE-04: not adds no constraint and no variable**
  - Covered by: `tests/unit/bool/r1cs.rs` `not_exports_exactly_the_booleanity_row_and_the_negated_claim_row`; `tests/unit/bool/r1cs.rs` `not_and_every_operation_with_a_constant_operand_add_no_constraint`
  - Kind: constraint
  - Statement: `Not` exports exactly 3 variables, row 0 the booleanity row of a and row 1 A = {0: 1, 1: -1, 2: -1}, B = {0: 1}, C = {}; a circuit that converts a and computes `not` and every gate with a constant operand, asserting nothing, exports exactly 2 variables and the single booleanity row.
  - Location: `src/circuit/builtins/types/boolean.rs:32-34` (`fn not`)
  - Severity: Medium
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-GATE-05: a gate of two variables costs exactly one product row and one witness**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_two_variable_gate_costs_one_product_row_and_inlines_its_truth_table`
  - Kind: constraint
  - Statement: for every two-operand gate, `Variables<GATE>` exports exactly 4 constraints and 5 variables: the booleanity rows of a and b, then row 2 A = {1: 1}, B = {2: 1}, C = {4: 1} (the product ab on witness 4), then the claim row.
  - Location: `src/circuit/builtins/types/boolean.rs:36-58`, `src/circuit/builtins/field/primitive.rs:64-66` (`fn times`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-GATE-06: the claim row of a gate is the multilinear extension of its truth table**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_two_variable_gate_costs_one_product_row_and_inlines_its_truth_table`
  - Kind: constraint
  - Statement: for every two-operand gate with truth table f, row 3 is, as a set of terms, exactly A = {0: f(0,0), 1: f(1,0) - f(0,0), 2: f(0,1) - f(0,0), 3: -1, 4: f(1,1) - f(1,0) - f(0,1) + f(0,0)} with the zero coefficients dropped, B = {0: 1}, C = {}: `and` is ab, `or` a + b - ab, `xor` a + b - 2ab, `nand` 1 - ab and `implies` 1 - a + ab.
  - Location: `src/circuit/builtins/types/boolean.rs:36-58`, `src/prover/synthesis.rs:247-273` (`fn circuit_matrices`, inlining)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-GATE-07: and exports exactly the golden rows and header**
  - Covered by: `tests/unit/bool/r1cs.rs` `and_exports_exactly_the_golden_rows_and_header`
  - Kind: constraint
  - Statement: `Variables<and>` exports exactly the header of 5 variables, 0 public inputs, 4 private inputs and 4 constraints with labels `[0, 1, 2, 3, 4]`, and the rows A = [{1: 1}, {2: 1}, {1: 1}, {4: 1, 3: -1}], B = [{0: -1, 1: 1}, {0: -1, 2: 1}, {2: 1}, {0: 1}], C = [{}, {}, {4: 1}, {}], in exactly that term order: the product witness is itself the claim's left side, so its row is not re-sorted by the inliner.
  - Location: `src/circuit/builtins/types/boolean.rs:36-38` (`fn and`), `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: High
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-GATE-08: a constant operand makes every gate affine in the variable**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_constant_operand_form_inlines_to_the_affine_form_of_its_truth_table`
  - Kind: constraint
  - Statement: for every gate and each of its four constant operand forms with output g(a), the fixture exports exactly 2 constraints and 3 variables: the booleanity row of a, and, as a set of terms, A = {0: g(0), 1: g(1) - g(0), 2: -1} with the zero coefficients dropped, B = {0: 1}, C = {}. No product row and no witness remain, and a cancelled coefficient (as in `a implies true`) leaves no term.
  - Location: `src/circuit/builtins/types/boolean.rs:32-58`, `src/circuit/builtins/field/primitive.rs:64-70` (`fn times`, `fn scaled`)
  - Severity: Medium
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

### Completeness

- [x] **INV-BOOL-GATE-09: every boolean pair satisfies every row of every gate fixture**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_boolean_vector_satisfies_every_exported_row_and_every_proving_row`
  - Kind: completeness
  - Statement: for every gate, every boolean pair and the honest claim, the exported assignment of `Variables<GATE>`, `Not` and every constant operand form satisfies every exported row (`first_unsatisfied` is exactly `None`) and every proving row.
  - Location: `src/circuit/builtins/types/boolean.rs:32-58`
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/r1cs.rs`

### Soundness

- [x] **INV-BOOL-GATE-10: every wrong gate claim leaves the claim row unsatisfied**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_claim_off_by_one_breaks_exactly_the_claim_row_with_the_fixture_rule`; `tests/unit/bool/properties.rs` `every_wrong_claim_of_a_gate_breaks_its_claim_row_in_the_proving_rows` (property)
  - Kind: soundness
  - Statement: for every gate, every boolean pair and every claim other than the truth-table entry (the claim moved by +1 or -1, which covers the negation, 2 and p - 1, and random field elements), the proving rows refuse the claim at the claim row: row 3 for a two-variable gate, row 1 for `not` and for every constant operand form.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/bool/r1cs.rs`, `tests/unit/bool/properties.rs`

- [x] **INV-BOOL-GATE-11: a non-boolean operand is refused by its booleanity row alone**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_non_boolean_operand_breaks_exactly_its_booleanity_rows_with_every_other_row_satisfied`; `tests/unit/bool/properties.rs` `a_non_boolean_operand_breaks_exactly_its_booleanity_rows_in_every_gate` (property)
  - Kind: soundness
  - Statement: for every two-operand gate and every pair with a non-boolean operand (the vectors and random field elements), the witness `[1, a, b, f(a, b), ab]`, with f the gate's polynomial, leaves exactly the booleanity rows of the non-boolean operands unsatisfied (row 0 for a, row 1 for b); for `not`, `[1, x, 1 - x]` leaves exactly row 0. Without the booleanity rows the gate rows would accept, for example, xor(2, 0) = 2.
  - Location: `src/circuit/builtins/field/bits.rs:50-62` (`fn assert_bool`), `src/circuit/builtins/types/boolean.rs:32-58`
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/bool/r1cs.rs`, `tests/unit/bool/properties.rs`

- [x] **INV-BOOL-GATE-12: a tampered product witness breaks the product row**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_tampered_intermediate_witness_breaks_its_own_row`
  - Kind: soundness
  - Statement: for every two-operand gate and every boolean pair, `check_tampered` with the product witness (wire 4) increased by 1 returns exactly `ProverError.ProofInputsBreakRule` at row 2.
  - Location: `src/circuit/builtins/field/primitive.rs:64-66` (`fn times`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-GATE-13: no private variable of a gate fixture is free**
  - Covered by: `tests/unit/bool/r1cs.rs` `no_private_variable_is_free_and_only_an_equal_sided_inverse_hint_is_tolerated`
  - Kind: soundness
  - Statement: for every boolean vector, `check_private_variables` reports no free and no tolerated variable, with exactly (4 constraints, 4 private variables) for every two-variable gate and (2, 2) for `not` and every constant operand form.
  - Location: `src/testing.rs:70-99` (`fn check_private_variables`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-GATE-14: Picus proves every gate output fixed by its operands**
  - Covered by: `tests/unit/bool/picus.rs` `picus_finds_every_gate_output_fixed_by_its_operands_in_the_sdk_and_in_circom`; `tests/unit/bool/picus.rs` `picus_finds_every_conversion_and_constant_operand_output_fixed`
  - Kind: soundness
  - Statement: for every two-operand gate, `not` and every constant operand form, Picus reports exactly Safe for the SDK's Picus export with `out` promoted to an output (the product witness is an output already).
  - Location: `src/prover/snarkjs.rs:20-45` (`fn picus_r1cs`), `tests/unit/harness/equivalence.rs` (`fn picus_verdicts`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/bool/picus.rs`

### Shape

- [x] **INV-BOOL-GATE-15: setup and proving produce identical gate matrices**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_boolean_vector_satisfies_every_exported_row_and_every_proving_row`
  - Kind: shape
  - Statement: for every gate and every boolean pair, `check_constraints` returns exactly `Ok(4)` for `Variables<GATE>` and exactly `Ok(2)` for `Not` and every constant operand form.
  - Location: `src/prover/synthesis.rs:405-429` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/r1cs.rs`

### Error

- [x] **INV-BOOL-GATE-16: natively a wrong gate claim fails with exactly the gate's rule**
  - Covered by: `tests/unit/bool/native.rs` `every_wrong_claim_breaks_exactly_the_fixture_rule_natively`; `tests/unit/bool/properties.rs` `natively_every_gate_refuses_exactly_the_non_boolean_operands_and_holds_exactly_on_its_truth_table` (property)
  - Kind: error
  - Statement: for every gate, every boolean pair and every wrong claim, the native run of `Variables<GATE>`, `Not` and every constant operand form returns exactly `CircuitError.RuleBroken` with the fixture's gate rule, located in the fixture's file.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`, the constant branch)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/bool/native.rs`, `tests/unit/bool/properties.rs`

- [x] **INV-BOOL-GATE-17: a tampered gate claim fails in R1CS with exactly the gate's rule**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_claim_off_by_one_breaks_exactly_the_claim_row_with_the_fixture_rule`; `tests/unit/bool/properties.rs` `every_wrong_claim_of_a_gate_breaks_its_claim_row_in_the_proving_rows` (property)
  - Kind: error
  - Statement: for every gate and every boolean pair, `check_tampered` with `out` moved by +1 or -1 returns exactly `ProverError.ProofInputsBreakRule` at the claim row labelled with the gate's rule.
  - Location: `src/testing.rs:43-68` (`fn check_tampered`), `src/circuit/builtins/ops/assert.rs:46-48` (`labels::check`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/bool/r1cs.rs`, `tests/unit/bool/properties.rs`

- [x] **INV-BOOL-GATE-18: a tampered product is reported at its row with no label**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_tampered_intermediate_witness_breaks_its_own_row`
  - Kind: error
  - Statement: for every two-operand gate, `check_tampered` of the product witness returns exactly `ProverError.ProofInputsBreakRule` at row 2 with no label: the product row is added outside every `labels::check` and `Scope`, so the report names the row only.
  - Location: `src/circuit/builtins/field/primitive.rs:64-66` (`fn times`), `src/circuit/labels.rs:255-270` (`fn report`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-GATE-19: natively a non-boolean gate operand fails with exactly NotZeroOrOne**
  - Covered by: `tests/unit/bool/native.rs` `every_non_boolean_operand_is_refused_natively_with_not_zero_or_one`; `tests/unit/bool/properties.rs` `natively_every_gate_refuses_exactly_the_non_boolean_operands_and_holds_exactly_on_its_truth_table` (property)
  - Kind: error
  - Statement: for every gate and every pair with a non-boolean operand, claiming the gate's polynomial so that the claim alone would not break the rule, the native run of `Variables<GATE>` returns exactly `CircuitError.NotZeroOrOne` located in the fixture's file; so do `Not` and every constant operand form on every non-boolean vector, claiming 0.
  - Location: `src/circuit/builtins/field/bits.rs:50-58` (`fn assert_bool`)
  - Error: `CircuitErrorKind::NotZeroOrOne`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/bool/native.rs`, `tests/unit/bool/properties.rs`

### Equivalence

- [x] **INV-BOOL-GATE-20: and, or, xor and nand are relation-equivalent to circomlib's gates**
  - Covered by: `tests/unit/bool/external.rs` `every_two_operand_gate_is_relation_equivalent_to_its_circom_reference`
  - Kind: equivalence
  - Statement: for every boolean pair with its honest and its negated claim, every wrong claim on (1, 1) and every non-boolean pair, the SDK natively, the SDK export, circom's witness calculation and circom's R1CS each accept exactly when the claim is the truth-table entry of a boolean pair, against `and.circom`, `or.circom`, `xor.circom` and `nand.circom`.
  - Location: `src/circuit/builtins/types/boolean.rs:36-54`, `tests/unit/bool/circom/`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/bool/external.rs`

- [x] **INV-BOOL-GATE-21: implies is relation-equivalent to its own reference**
  - Covered by: `tests/unit/bool/external.rs` `every_two_operand_gate_is_relation_equivalent_to_its_circom_reference`
  - Kind: equivalence
  - Statement: over the same cases as INV-BOOL-GATE-20, `implies` and `implies.circom` accept exactly the same cases.
  - Location: `src/circuit/builtins/types/boolean.rs:56-58` (`fn implies`), `tests/unit/bool/circom/implies.circom`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/bool/external.rs`

- [x] **INV-BOOL-GATE-22: not is relation-equivalent to circomlib NOT**
  - Covered by: `tests/unit/bool/external.rs` `not_is_relation_equivalent_to_circomlib_not`
  - Kind: equivalence
  - Statement: for both booleans with the honest claim and with the claim equal to the input, and for every non-boolean vector claiming 1 - x, `Not` and `not.circom` accept exactly the same cases.
  - Location: `src/circuit/builtins/types/boolean.rs:32-34` (`fn not`), `tests/unit/bool/circom/not.circom`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/bool/external.rs`

- [x] **INV-BOOL-GATE-23: the gate sizes are pinned against circom's**
  - Covered by: `tests/unit/bool/external.rs` `every_two_operand_gate_is_relation_equivalent_to_its_circom_reference`; `tests/unit/bool/external.rs` `not_is_relation_equivalent_to_circomlib_not`
  - Kind: equivalence
  - Statement: every two-operand gate exports exactly 4 constraints and 5 variables against circom's 6 and 7 under `--O0` (which keeps one copy row per component input); `not` exports exactly 2 and 3 against circom's 4 and 5.
  - Location: `tests/unit/harness/equivalence.rs` (`fn sizes`)
  - Severity: Medium
  - Suggested test: external (circom); `tests/unit/bool/external.rs`

- [x] **INV-BOOL-GATE-24: Picus reports every circom gate reference deterministic too**
  - Covered by: `tests/unit/bool/picus.rs` `picus_finds_every_gate_output_fixed_by_its_operands_in_the_sdk_and_in_circom`
  - Kind: equivalence
  - Statement: for every two-operand gate and `not`, Picus reports exactly Safe for the circom reference with `main.out` promoted to an output, the same verdict as for the SDK export (INV-BOOL-GATE-14).
  - Location: `tests/unit/harness/equivalence.rs` (`fn picus_verdicts`), `tests/unit/bool/circom/`
  - Severity: High
  - Suggested test: external (Picus); `tests/unit/bool/picus.rs`

- [x] **INV-BOOL-GATE-25: the Picus export moves exactly the product to the outputs**
  - Covered by: `tests/unit/bool/picus.rs` `the_picus_export_moves_exactly_the_gadget_witnesses_to_the_outputs_and_the_hint_last`
  - Kind: equivalence
  - Statement: the Picus export of `Variables<and>` has exactly 1 public output and the wire labels `[0, 4, 1, 2, 3]` (the product witness first), and the Picus export of `Not` and of the conversion fixture is byte-identical to the snarkjs export.
  - Location: `src/prover/snarkjs.rs:20-45` (`fn picus_r1cs`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/picus.rs`

### Interop

- [x] **INV-BOOL-GATE-26: snarkjs accepts every honest gate witness**
  - Covered by: `tests/unit/bool/external.rs` `snarkjs_accepts_every_honest_gate_witness_and_rejects_a_flipped_or_non_boolean_one`
  - Kind: interop
  - Statement: for every two-operand gate and every boolean pair, `snarkjs wtns check` accepts the SDK export with the SDK's honest assignment.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`), `src/prover/snarkjs.rs:112-124` (`fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/bool/external.rs`

- [x] **INV-BOOL-GATE-27: snarkjs rejects a flipped gate claim**
  - Covered by: `tests/unit/bool/external.rs` `snarkjs_accepts_every_honest_gate_witness_and_rejects_a_flipped_or_non_boolean_one`
  - Kind: interop
  - Statement: for every two-operand gate and every boolean pair, `snarkjs wtns check` rejects the SDK export with the honest assignment whose claim is negated.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Severity: Critical
  - Suggested test: external (snarkjs); `tests/unit/bool/external.rs`

## Folds (`Bool::all`, `Bool::any`)

`Fold<OP, N>` asserts `all(flags) == out` or `any(flags) == out` for N from 0 to 3 flags. For
two or more flags both folds compare the flags' sum with arkworks' `is_eq` (against N for
`all`, against 0 for `any`), which allocates an is-not-equal witness and an inverse hint. The
references are circomlib `MultiAND(3)` for `all` and our own `any.circom`, `1 - IsZero(sum)`
over circomlib `IsZero`, each with a booleanity line per flag.

### Semantics

- [x] **INV-BOOL-FOLD-01: on constants all and any are Iterator::all and Iterator::any**
  - Covered by: `tests/unit/bool/native.rs` `all_and_any_on_constants_are_iterator_all_and_any_with_empty_slices_included`
  - Kind: semantics
  - Statement: for every flag combination of length 0 to 3, `Bool::all` and `Bool::any` over the constants return a constant equal to exactly `Iterator::all` and `Iterator::any` of the flags: `all(&[])` is exactly the constant 1 and `any(&[])` exactly the constant 0.
  - Location: `src/circuit/builtins/types/boolean.rs:60-77` (`fn all`, `fn any`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/native.rs`

- [x] **INV-BOOL-FOLD-02: natively a fold fixture holds exactly on Iterator::all and Iterator::any**
  - Covered by: `tests/unit/bool/native.rs` `every_boolean_vector_holds_natively_in_every_output_fixture`; `tests/unit/bool/properties.rs` `natively_a_fold_holds_exactly_on_iterator_all_and_any_and_refuses_a_non_boolean_flag` (property)
  - Kind: semantics
  - Statement: for every boolean flag combination of length 0 to 3 and every claim drawn from 0, 1 and random field elements, the native run of `Fold<all, N>` and `Fold<any, N>` holds exactly when the claim equals `Iterator::all` (`any`) of the flags.
  - Location: `src/circuit/builtins/types/boolean.rs:60-77`
  - Severity: High
  - Suggested test: positive + property; `tests/unit/bool/native.rs`, `tests/unit/bool/properties.rs`

### Constraint

- [x] **INV-BOOL-FOLD-03: a fold of at most one flag adds no constraint beyond the claim**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_fold_of_at_most_one_flag_adds_no_constraint_beyond_the_claim`
  - Kind: constraint
  - Statement: `Fold<all, 0>` exports exactly the row A = {0: 1, 1: -1} and `Fold<any, 0>` exactly A = {1: -1} (the constants 1 and 0), each with B = {0: 1}, C = {} and 2 variables; `Fold<all, 1>` and `Fold<any, 1>` both export exactly the booleanity row and A = {1: 1, 2: -1}: the single flag itself.
  - Location: `src/circuit/builtins/types/boolean.rs:62-64` (`fn all`), `src/circuit/builtins/types/boolean.rs:71-73` (`fn any`)
  - Severity: Medium
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-FOLD-04: a fold of two flags exports exactly the equality-test rows**
  - Covered by: `tests/unit/bool/r1cs.rs` `all_and_any_of_two_flags_export_exactly_the_equality_test_rows`
  - Kind: constraint
  - Statement: `Fold<all, 2>` exports exactly 6 variables and 5 rows: the booleanity rows of wires 1 and 2, row 2 A = {0: 2, 1: -1, 2: -1}, B = {5: 1}, C = {4: 1} (the difference 2 - sum times the inverse hint is the is-not-equal witness), row 3 the same A with B = {0: 1, 4: -1}, C = {} (the difference is 0 unless the witness is 1), and row 4 A = {0: 1, 3: -1, 4: -1}; `Fold<any, 2>` is the same with the difference -sum (A = {1: -1, 2: -1}) and the claim row A = {3: -1, 4: 1}.
  - Location: `src/circuit/builtins/types/boolean.rs:60-77`, `src/circuit/builtins/field/primitive.rs:88-100` (`fn equals`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-FOLD-05: a fold of n >= 2 flags costs exactly n + 3 constraints and n + 4 variables**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_fold_of_n_flags_costs_n_booleanity_rows_two_equality_rows_and_the_claim`
  - Kind: constraint
  - Statement: for n = 2 and n = 3, both folds export exactly n + 3 constraints (n booleanity rows, 2 equality rows, the claim) and n + 4 variables.
  - Location: `src/circuit/builtins/types/boolean.rs:60-77`
  - Severity: Medium
  - Suggested test: positive; `tests/unit/bool/r1cs.rs`

### Completeness

- [x] **INV-BOOL-FOLD-06: every flag combination satisfies every row of both folds**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_boolean_vector_satisfies_every_exported_row_and_every_proving_row`
  - Kind: completeness
  - Statement: for every boolean flag combination of length 0 to 3 and the honest claim, the exported assignment of both folds satisfies every exported row and every proving row, whether or not the compared sides are equal.
  - Location: `src/circuit/builtins/types/boolean.rs:60-77`
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/r1cs.rs`

### Soundness

- [x] **INV-BOOL-FOLD-07: every wrong fold claim leaves the claim row unsatisfied**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_claim_off_by_one_breaks_exactly_the_claim_row_with_the_fixture_rule`
  - Kind: soundness
  - Statement: for every boolean flag combination of length 0 to 3, the proving rows refuse the claim moved by +1 or by -1 at exactly the last row.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-FOLD-08: flags whose sum deceives the fold are refused by a booleanity row alone**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_non_boolean_operand_breaks_exactly_its_booleanity_rows_with_every_other_row_satisfied`
  - Kind: soundness
  - Statement: `all` over [2, 0, 1] claiming 1 and `any` over [1, p - 1, 0] claiming 0, with the is-not-equal witness 0 and the inverse hint 1 consistent with the sum, leave exactly row 0 and exactly row 1 of their exports unsatisfied: the equality rows and the claim row accept these sums, and only the booleanity rows refuse them.
  - Location: `src/circuit/builtins/types/boolean.rs:98-100` (`fn sum`), `src/circuit/builtins/field/bits.rs:50-62` (`fn assert_bool`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-FOLD-09: a tampered equality witness breaks an equality row**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_tampered_intermediate_witness_breaks_its_own_row`
  - Kind: soundness
  - Statement: with the compared sides unequal (`all` over [1, 0], `any` over [1, 0, 1]), `check_tampered` with the is-not-equal witness or the inverse hint increased by 1 returns exactly `ProverError.ProofInputsBreakRule` at the first equality row labelled "an equality test".
  - Location: `src/circuit/builtins/field/primitive.rs:88-100` (`fn equals`), `src/circuit/builtins/types/boolean.rs:23-26` (`fn of_equality`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-FOLD-10: only the inverse hint of an equal-sided fold is free**
  - Covered by: `tests/unit/bool/r1cs.rs` `no_private_variable_is_free_and_only_an_equal_sided_inverse_hint_is_tolerated`
  - Kind: soundness
  - Statement: for every boolean flag combination, `check_private_variables` reports no free variable; for two or more flags it tolerates exactly the inverse hint (private variable n + 2, role `Multiplier`) when the compared sides are equal (all flags set for `all`, none for `any`), and nothing otherwise.
  - Location: `src/circuit/builtins/field/primitive.rs:88-100` (`fn equals`, `labels::mark`), `src/testing.rs:70-99` (`fn check_private_variables`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-FOLD-11: Picus proves every fold output fixed by its flags**
  - Covered by: `tests/unit/bool/picus.rs` `picus_finds_every_fold_and_select_output_fixed_in_the_sdk_and_in_circom`; `tests/unit/bool/picus.rs` `picus_finds_every_conversion_and_constant_operand_output_fixed`
  - Kind: soundness
  - Statement: Picus reports exactly Safe for the Picus exports of `Fold<all, 3>`, `Fold<any, 3>`, `Fold<all, 0>` and `Fold<any, 1>` with `out` promoted; the is-not-equal witness is checked as an output and the inverse hint is left last, unchecked.
  - Location: `src/prover/snarkjs.rs:20-45` (`fn picus_r1cs`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/bool/picus.rs`

### Shape

- [x] **INV-BOOL-FOLD-12: setup and proving produce identical fold matrices**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_boolean_vector_satisfies_every_exported_row_and_every_proving_row`
  - Kind: shape
  - Statement: for every boolean flag combination of length n from 0 to 3, `check_constraints` of both folds returns exactly `Ok(1)`, `Ok(2)`, `Ok(5)` or `Ok(6)` respectively.
  - Location: `src/prover/synthesis.rs:405-429` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/r1cs.rs`

### Error

- [x] **INV-BOOL-FOLD-13: natively a wrong fold claim fails with exactly the fold's rule**
  - Covered by: `tests/unit/bool/native.rs` `every_wrong_claim_breaks_exactly_the_fixture_rule_natively`; `tests/unit/bool/properties.rs` `natively_a_fold_holds_exactly_on_iterator_all_and_any_and_refuses_a_non_boolean_flag` (property)
  - Kind: error
  - Statement: for every boolean flag combination of length 0 to 3 and every wrong claim, the native run returns exactly `CircuitError.RuleBroken` with the fold's rule, located in the fixture's file.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/bool/native.rs`, `tests/unit/bool/properties.rs`

- [x] **INV-BOOL-FOLD-14: a tampered fold claim fails in R1CS with exactly the fold's rule**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_claim_off_by_one_breaks_exactly_the_claim_row_with_the_fixture_rule`
  - Kind: error
  - Statement: for every boolean flag combination, `check_tampered` with `out` moved by +1 or -1 returns exactly `ProverError.ProofInputsBreakRule` at the last row labelled with the fold's rule.
  - Location: `src/testing.rs:43-68` (`fn check_tampered`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-FOLD-15: natively a non-boolean flag fails with exactly NotZeroOrOne**
  - Covered by: `tests/unit/bool/native.rs` `every_non_boolean_operand_is_refused_natively_with_not_zero_or_one`; `tests/unit/bool/properties.rs` `natively_a_fold_holds_exactly_on_iterator_all_and_any_and_refuses_a_non_boolean_flag` (property)
  - Kind: error
  - Statement: the deceptive flags and every flag list containing a random non-boolean element fail natively with exactly `CircuitError.NotZeroOrOne`, whatever the claim.
  - Location: `src/circuit/builtins/field/bits.rs:50-58` (`fn assert_bool`)
  - Error: `CircuitErrorKind::NotZeroOrOne`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/bool/native.rs`, `tests/unit/bool/properties.rs`

### Equivalence

- [x] **INV-BOOL-FOLD-16: all of three flags is relation-equivalent to circomlib MultiAND**
  - Covered by: `tests/unit/bool/external.rs` `all_of_three_flags_is_relation_equivalent_to_circomlib_multi_and`
  - Kind: equivalence
  - Statement: for the eight flag combinations of length 3 with their honest and negated claims, and the deceptive [2, 0, 1] claiming 1, `Fold<all, 3>` and `multi_and.circom` accept exactly the same cases in all four checks.
  - Location: `src/circuit/builtins/types/boolean.rs:60-68` (`fn all`), `tests/unit/bool/circom/multi_and.circom`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/bool/external.rs`

- [x] **INV-BOOL-FOLD-17: any of three flags is relation-equivalent to a reference over circomlib IsZero**
  - Covered by: `tests/unit/bool/external.rs` `any_of_three_flags_is_relation_equivalent_to_a_reference_over_circomlib_is_zero`
  - Kind: equivalence
  - Statement: for the eight flag combinations of length 3 with their honest and negated claims, and the deceptive [1, p - 1, 0] claiming 0, `Fold<any, 3>` and `any.circom` accept exactly the same cases in all four checks.
  - Location: `src/circuit/builtins/types/boolean.rs:69-77` (`fn any`), `tests/unit/bool/circom/any.circom`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/bool/external.rs`

- [x] **INV-BOOL-FOLD-18: the fold sizes are pinned against circom's**
  - Covered by: `tests/unit/bool/external.rs` `all_of_three_flags_is_relation_equivalent_to_circomlib_multi_and`; `tests/unit/bool/external.rs` `any_of_three_flags_is_relation_equivalent_to_a_reference_over_circomlib_is_zero`
  - Kind: equivalence
  - Statement: both folds of three flags export exactly 6 constraints and 7 variables, against exactly 19 and 20 for `MultiAND(3)` (a tree of two-input ANDs) and exactly 11 and 12 for the `IsZero` reference.
  - Location: `tests/unit/harness/equivalence.rs` (`fn sizes`)
  - Severity: Medium
  - Suggested test: external (circom); `tests/unit/bool/external.rs`

- [x] **INV-BOOL-FOLD-19: Picus reports both fold references deterministic too**
  - Covered by: `tests/unit/bool/picus.rs` `picus_finds_every_fold_and_select_output_fixed_in_the_sdk_and_in_circom`
  - Kind: equivalence
  - Statement: Picus reports exactly Safe for `multi_and.circom` and `any.circom` with `main.out` promoted, the same verdict as for the SDK exports.
  - Location: `tests/unit/harness/equivalence.rs` (`fn picus_verdicts`)
  - Severity: High
  - Suggested test: external (Picus); `tests/unit/bool/picus.rs`

- [x] **INV-BOOL-FOLD-20: the Picus export puts the is-not-equal witness first and the hint last**
  - Covered by: `tests/unit/bool/picus.rs` `the_picus_export_moves_exactly_the_gadget_witnesses_to_the_outputs_and_the_hint_last`
  - Kind: equivalence
  - Statement: the Picus export of `Fold<all, 3>` has exactly 1 public output and the wire labels `[0, 5, 1, 2, 3, 4, 6]`: the is-not-equal witness first, the proof inputs, then the inverse hint.
  - Location: `src/prover/snarkjs.rs:20-45` (`fn picus_r1cs`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/picus.rs`

### Interop

- [x] **INV-BOOL-FOLD-21: snarkjs Groth16 proves and verifies a fold of three flags**
  - Covered by: `tests/unit/bool/external.rs` `snarkjs_proves_and_verifies_select_and_a_fold_of_three_flags`
  - Kind: interop
  - Statement: `snarkjs groth16` setup over the power-4 throwaway ptau, prove with the SDK assignment of `all` over [1, 0, 1] claiming 0, and verify accept the 6-constraint SDK export with exactly the empty public signal list.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`), `src/prover/snarkjs.rs:112-124` (`fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/bool/external.rs`

## Select (`Bool::select`, `Select for Bool`)

`Choose<FORM>` asserts `select(condition, if_true, if_false) == out` in the forms
`condition.select(&t, &f)` and `<Bool as Select>::select(&c, &t, &f)`;
`ChooseConstantCondition<K>` and `ChooseConstantBranches<T, F>` fix the condition or both
branches as constants. The reference is circomlib `Mux1` with `c[0]` the false branch,
`c[1]` the true branch and a booleanity line per input.

### Semantics

- [x] **INV-BOOL-SEL-01: on constants select picks exactly the branch the condition names**
  - Covered by: `tests/unit/bool/native.rs` `select_on_constants_picks_the_branch_the_condition_names_in_both_forms`
  - Kind: semantics
  - Statement: for all eight constant triples and both forms, the result is a constant equal to exactly `if condition { if_true } else { if_false }`.
  - Location: `src/circuit/builtins/types/boolean.rs:79-81` (`fn select`), `src/circuit/builtins/types/boolean.rs:148-152` (`impl Select for Bool`), `src/circuit/builtins/ops/select.rs:7-11` (`impl Select for CircuitVar`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/native.rs`

- [x] **INV-BOOL-SEL-02: natively a select fixture holds exactly on the named branch**
  - Covered by: `tests/unit/bool/native.rs` `every_boolean_vector_holds_natively_in_every_output_fixture`; `tests/unit/bool/properties.rs` `natively_select_refuses_a_non_boolean_operand_and_holds_exactly_on_the_named_branch` (property)
  - Kind: semantics
  - Statement: for every boolean triple and every claim drawn from 0, 1 and random field elements, the native run of both select forms holds exactly when the claim is the named branch.
  - Location: `src/circuit/builtins/types/boolean.rs:79-81`, `src/circuit/builtins/types/boolean.rs:148-152`
  - Severity: High
  - Suggested test: positive + property; `tests/unit/bool/native.rs`, `tests/unit/bool/properties.rs`

### Constraint

- [x] **INV-BOOL-SEL-03: select exports exactly the golden rows**
  - Covered by: `tests/unit/bool/r1cs.rs` `select_exports_exactly_the_golden_rows_in_both_forms`
  - Kind: constraint
  - Statement: `Choose<0>` exports exactly 6 variables and 5 rows: the booleanity rows of the condition, the true branch and the false branch (wires 1, 2, 3), row 3 A = {1: 1}, B = {2: 1, 3: -1}, C = {5: 1} (the product c (t - f) on witness 5), and row 4 A = {3: 1, 4: -1, 5: 1}, B = {0: 1}, C = {}.
  - Location: `src/circuit/builtins/ops/select.rs:7-11` (`impl Select for CircuitVar`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-SEL-04: both select forms export byte-identical R1CS**
  - Covered by: `tests/unit/bool/r1cs.rs` `select_exports_exactly_the_golden_rows_in_both_forms`
  - Kind: constraint
  - Statement: `condition.select(&t, &f)` and `<Bool as Select>::select(&c, &t, &f)` export byte-identical `.r1cs` files.
  - Location: `src/circuit/builtins/types/boolean.rs:79-81`, `src/circuit/builtins/types/boolean.rs:148-152`
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-SEL-05: a constant condition or constant branches make select linear**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_constant_condition_or_constant_branches_make_select_linear`; `tests/unit/bool/r1cs.rs` `not_and_every_operation_with_a_constant_operand_add_no_constraint`
  - Kind: constraint
  - Statement: with the condition the constant true (false), select exports exactly the booleanity rows of both branches and the claim row A = {1: 1, 3: -1} (A = {2: 1, 3: -1}), the other branch's cancelled coefficient leaving no term; with the constant branches (T, F), it exports exactly the booleanity row of the condition and A = {0: F, 1: T - F, 2: -1} with zero coefficients dropped, so (1, 0) is the condition itself and (0, 1) its negation. No product row and no witness remain.
  - Location: `src/circuit/builtins/ops/select.rs:7-11`, `src/circuit/builtins/field/primitive.rs:64-66` (`fn times`)
  - Severity: Medium
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

### Completeness

- [x] **INV-BOOL-SEL-06: every boolean triple satisfies every row of both select forms**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_boolean_vector_satisfies_every_exported_row_and_every_proving_row`
  - Kind: completeness
  - Statement: for every boolean triple and the named branch as the claim, the exported assignment of both forms satisfies every exported row and every proving row; so does one honest vector of the constant-condition and constant-branch fixtures.
  - Location: `src/circuit/builtins/ops/select.rs:7-11`
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/r1cs.rs`

### Soundness

- [x] **INV-BOOL-SEL-07: every wrong select claim leaves the claim row unsatisfied**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_claim_off_by_one_breaks_exactly_the_claim_row_with_the_fixture_rule`
  - Kind: soundness
  - Statement: for every boolean triple and both forms, the proving rows refuse the claim moved by +1 or -1 at exactly row 4.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-SEL-08: a non-boolean select operand is refused by its booleanity row alone**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_non_boolean_operand_breaks_exactly_its_booleanity_rows_with_every_other_row_satisfied`
  - Kind: soundness
  - Statement: for every non-boolean vector x, the witnesses (c, t, f, out, product) = (x, 1, 0, x, x), (1, x, 0, x, x) and (0, 0, x, x, 0) leave exactly row 0, exactly row 1 and exactly row 2 unsatisfied: the product and claim rows accept a non-boolean condition that "selects" x.
  - Location: `src/circuit/builtins/field/bits.rs:50-62` (`fn assert_bool`), `src/circuit/builtins/ops/select.rs:7-11`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-SEL-09: a tampered select product breaks the product row**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_tampered_intermediate_witness_breaks_its_own_row`
  - Kind: soundness
  - Statement: `check_tampered` of `Choose<0>` (1 ? 1 : 0) with the product witness increased by 1 returns exactly `ProverError.ProofInputsBreakRule` at row 3 with no label.
  - Location: `src/circuit/builtins/ops/select.rs:7-11`, `src/circuit/labels.rs:255-270` (`fn report`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-SEL-10: no private variable of a select fixture is free**
  - Covered by: `tests/unit/bool/r1cs.rs` `no_private_variable_is_free_and_only_an_equal_sided_inverse_hint_is_tolerated`
  - Kind: soundness
  - Statement: for every boolean triple and both forms, `check_private_variables` reports exactly 5 constraints, 5 private variables, no free variable and no tolerated variable.
  - Location: `src/testing.rs:70-99` (`fn check_private_variables`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-SEL-11: Picus proves the selected output fixed by the operands**
  - Covered by: `tests/unit/bool/picus.rs` `picus_finds_every_fold_and_select_output_fixed_in_the_sdk_and_in_circom`
  - Kind: soundness
  - Statement: Picus reports exactly Safe for the Picus export of `Choose<0>` with `out` promoted.
  - Location: `src/prover/snarkjs.rs:20-45` (`fn picus_r1cs`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/bool/picus.rs`

### Shape

- [x] **INV-BOOL-SEL-12: setup and proving produce identical select matrices**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_boolean_vector_satisfies_every_exported_row_and_every_proving_row`
  - Kind: shape
  - Statement: for every boolean triple and both forms, `check_constraints` returns exactly `Ok(5)`; for the constant-condition and constant-branch fixtures exactly `Ok(3)` and `Ok(2)`.
  - Location: `src/prover/synthesis.rs:405-429` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/r1cs.rs`

### Error

- [x] **INV-BOOL-SEL-13: natively a wrong select claim fails with exactly the fixture rule**
  - Covered by: `tests/unit/bool/native.rs` `every_wrong_claim_breaks_exactly_the_fixture_rule_natively`; `tests/unit/bool/properties.rs` `natively_select_refuses_a_non_boolean_operand_and_holds_exactly_on_the_named_branch` (property)
  - Kind: error
  - Statement: for every boolean triple, both forms and every wrong claim, the native run returns exactly `CircuitError.RuleBroken` with "the output is the selected branch" located in the fixture's file; the proving rows name the same rule at row 4 (INV-BOOL-SEL-07).
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/bool/native.rs`, `tests/unit/bool/properties.rs`

- [x] **INV-BOOL-SEL-14: natively a non-boolean select operand fails with exactly NotZeroOrOne**
  - Covered by: `tests/unit/bool/native.rs` `every_non_boolean_operand_is_refused_natively_with_not_zero_or_one`; `tests/unit/bool/properties.rs` `natively_select_refuses_a_non_boolean_operand_and_holds_exactly_on_the_named_branch` (property)
  - Kind: error
  - Statement: for every non-boolean condition or false branch (the vectors, and random field elements in any position), the native run of both select forms returns exactly `CircuitError.NotZeroOrOne`.
  - Location: `src/circuit/builtins/field/bits.rs:50-58` (`fn assert_bool`)
  - Error: `CircuitErrorKind::NotZeroOrOne`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/bool/native.rs`, `tests/unit/bool/properties.rs`

### Equivalence

- [x] **INV-BOOL-SEL-15: select is relation-equivalent to circomlib Mux1**
  - Covered by: `tests/unit/bool/external.rs` `select_is_relation_equivalent_to_circomlib_mux1`
  - Kind: equivalence
  - Statement: for every boolean triple with the named branch and with the other branch claimed, and for every non-boolean condition, true branch and false branch whose claim and product are consistent, `Choose<0>` and `select.circom` accept exactly the same cases in all four checks.
  - Location: `src/circuit/builtins/ops/select.rs:7-11`, `tests/unit/bool/circom/select.circom`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/bool/external.rs`

- [x] **INV-BOOL-SEL-16: the select size is pinned against Mux1's**
  - Covered by: `tests/unit/bool/external.rs` `select_is_relation_equivalent_to_circomlib_mux1`
  - Kind: equivalence
  - Statement: `Choose<0>` exports exactly 5 constraints and 6 variables against exactly 12 and 13 for the `Mux1` reference.
  - Location: `tests/unit/harness/equivalence.rs` (`fn sizes`)
  - Severity: Medium
  - Suggested test: external (circom); `tests/unit/bool/external.rs`

- [x] **INV-BOOL-SEL-17: Picus reports the Mux1 reference deterministic too**
  - Covered by: `tests/unit/bool/picus.rs` `picus_finds_every_fold_and_select_output_fixed_in_the_sdk_and_in_circom`
  - Kind: equivalence
  - Statement: Picus reports exactly Safe for `select.circom` with `main.out` promoted, the same verdict as for the SDK export.
  - Location: `tests/unit/harness/equivalence.rs` (`fn picus_verdicts`)
  - Severity: High
  - Suggested test: external (Picus); `tests/unit/bool/picus.rs`

- [x] **INV-BOOL-SEL-18: the select Picus export moves exactly the product to the outputs**
  - Covered by: `tests/unit/bool/picus.rs` `the_picus_export_moves_exactly_the_gadget_witnesses_to_the_outputs_and_the_hint_last`
  - Kind: equivalence
  - Statement: the Picus export of `Choose<0>` has exactly 1 public output and the wire labels `[0, 5, 1, 2, 3, 4]`.
  - Location: `src/prover/snarkjs.rs:20-45` (`fn picus_r1cs`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/picus.rs`

### Interop

- [x] **INV-BOOL-SEL-19: snarkjs Groth16 proves and verifies select**
  - Covered by: `tests/unit/bool/external.rs` `snarkjs_proves_and_verifies_select_and_a_fold_of_three_flags`
  - Kind: interop
  - Statement: `snarkjs groth16` setup over the power-4 throwaway ptau, prove with the SDK assignment of 1 ? 0 : 1 claiming 0, and verify accept the 5-constraint SDK export with exactly the empty public signal list.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`), `src/prover/snarkjs.rs:112-124` (`fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/bool/external.rs`

## Assertions (`assert_true`, `assert_false`, `assert_true_if`)

`AssertedUnary<OP>` runs `a.assert_true(rule)` or `a.assert_false(rule)`;
`AssertedBinary<0>` runs `a.assert_true_if(&b, rule)`, which holds unless b is true and a
false; `AssertTrueIfConstant<FORM>` fixes the flag or the condition as a constant. The
reference `assert_true_if.circom` is our own: booleanity lines and `(a - 1) * b === 0`.

### Semantics

- [x] **INV-BOOL-ASSERT-01: on constants every assertion holds exactly as its table says**
  - Covered by: `tests/unit/bool/native.rs` `every_assertion_on_constants_holds_exactly_as_its_truth_table_says`
  - Kind: semantics
  - Statement: on Bool constants, `assert_true` holds exactly for 1, `assert_false` exactly for 0, and `a.assert_true_if(&b)` exactly unless (a, b) = (0, 1); every other case fails.
  - Location: `src/circuit/builtins/types/boolean.rs:83-96` (`fn assert_true`, `fn assert_false`, `fn assert_true_if`)
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/bool/native.rs`

- [x] **INV-BOOL-ASSERT-02: natively every assertion fixture holds exactly as its table says**
  - Covered by: `tests/unit/bool/native.rs` `every_assertion_fixture_holds_natively_exactly_as_its_truth_table_says`; `tests/unit/bool/properties.rs` `natively_every_assertion_refuses_a_non_boolean_operand_and_holds_exactly_as_its_table_says` (property)
  - Kind: semantics
  - Statement: for every boolean input, the native runs of `AssertedUnary`, `AssertedBinary<assert_true_if>` and the four constant forms of `assert_true_if` hold exactly when their table says, and fail otherwise with exactly `CircuitError.RuleBroken` with the fixture's rule; `false.assert_true_if(x)` holds exactly for x = 0 and `true.assert_true_if(x)` and `x.assert_true_if(false)` for every x.
  - Location: `src/circuit/builtins/types/boolean.rs:83-96`
  - Severity: High
  - Suggested test: positive + negative + property; `tests/unit/bool/native.rs`, `tests/unit/bool/properties.rs`

### Constraint

- [x] **INV-BOOL-ASSERT-03: every assertion exports exactly its golden row**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_assertion_exports_exactly_its_golden_rows`
  - Kind: constraint
  - Statement: after the booleanity rows, `assert_true` exports exactly A = {0: 1, 1: -1}, B = {0: 1}, C = {} (1 - a = 0), `assert_false` exactly A = {1: -1}, B = {0: 1}, C = {}, and `a.assert_true_if(&b)` exactly A = {0: -1, 1: 1}, B = {2: 1}, C = {} ((a - 1) b = 0); none allocates a variable.
  - Location: `src/circuit/builtins/types/boolean.rs:83-96`, `src/circuit/builtins/ops/assert.rs:37-68` (`fn assert_equal`, `fn assert_equal_if`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-ASSERT-04: a constant operand of assert_true_if leaves at most one linear row**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_constant_operand_of_assert_true_if_leaves_at_most_one_linear_row`
  - Kind: constraint
  - Statement: after the booleanity row of x, `x.assert_true_if(false)` and `true.assert_true_if(x)` export no row, `x.assert_true_if(true)` exactly A = {0: 1, 1: -1}, B = {0: 1} (x = 1), and `false.assert_true_if(x)` exactly A = {1: 1}, B = {0: 1} (x = 0).
  - Location: `src/circuit/builtins/ops/assert.rs:51-68` (`fn assert_equal_if`)
  - Severity: Medium
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

### Completeness

- [x] **INV-BOOL-ASSERT-05: every holding assertion satisfies every row**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_holding_assertion_satisfies_every_exported_row_and_every_proving_row`
  - Kind: completeness
  - Statement: for every input on which the assertion holds, the exported assignment of `AssertedUnary`, `AssertedBinary<assert_true_if>` and every constant form satisfies every exported row and every proving row.
  - Location: `src/circuit/builtins/types/boolean.rs:83-96`
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/r1cs.rs`

### Soundness

- [x] **INV-BOOL-ASSERT-06: a failing assertion breaks exactly its assertion row**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_failing_assertion_breaks_exactly_its_assertion_row_with_the_fixture_rule`
  - Kind: soundness
  - Statement: `check_tampered` of `assert_true` with a set to 0, of `assert_false` with a set to 1, and of `a.assert_true_if(&b)` at (1, 1) with a set to 0 returns exactly `ProverError.ProofInputsBreakRule` at the assertion row labelled with the fixture's rule.
  - Location: `src/circuit/builtins/types/boolean.rs:83-96`
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-ASSERT-07: a non-boolean flag or condition is refused by its booleanity row alone**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_non_boolean_operand_breaks_exactly_its_booleanity_rows_with_every_other_row_satisfied`
  - Kind: soundness
  - Statement: for every non-boolean vector x, the witness (a, b) = (x, 0) leaves exactly row 0 of `a.assert_true_if(&b)` unsatisfied and (1, x) exactly row 1: the assertion row accepts both.
  - Location: `src/circuit/builtins/field/bits.rs:50-62` (`fn assert_bool`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-ASSERT-08: Picus proves assert_true and assert_false fix their flag**
  - Covered by: `tests/unit/bool/picus.rs` `picus_finds_exactly_the_operands_an_assertion_fixes`
  - Kind: soundness
  - Statement: Picus reports exactly Safe for `assert_true` and for `assert_false` with a promoted to an output.
  - Location: `src/prover/snarkjs.rs:20-45` (`fn picus_r1cs`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/bool/picus.rs`

- [x] **INV-BOOL-ASSERT-09: Picus finds the flag and the condition of assert_true_if free**
  - Covered by: `tests/unit/bool/picus.rs` `picus_finds_the_flag_of_assert_true_if_free_in_the_sdk_and_in_circom`
  - Kind: soundness
  - Statement: Picus reports exactly Unsafe for `a.assert_true_if(&b)` with a promoted (a is free when b is 0) and with b promoted (b is free when a is 1): the assertion fixes neither operand alone, as its table says.
  - Location: `src/circuit/builtins/types/boolean.rs:93-96` (`fn assert_true_if`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/bool/picus.rs`

- [x] **INV-BOOL-ASSERT-10: no private variable of an assertion fixture is free**
  - Covered by: `tests/unit/bool/r1cs.rs` `no_private_variable_is_free_and_only_an_equal_sided_inverse_hint_is_tolerated`
  - Kind: soundness
  - Statement: for every holding input, `check_private_variables` reports no free and no tolerated variable, with exactly (2 constraints, 1 private variable) for `assert_true` and `assert_false` and (3, 2) for `assert_true_if`.
  - Location: `src/testing.rs:70-99` (`fn check_private_variables`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

### Shape

- [x] **INV-BOOL-ASSERT-11: setup and proving produce identical assertion matrices**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_holding_assertion_satisfies_every_exported_row_and_every_proving_row`
  - Kind: shape
  - Statement: for every holding input, `check_constraints` returns exactly `Ok(2)` for `assert_true` and `assert_false`, `Ok(3)` for `assert_true_if`, and `Ok(1)`, `Ok(2)`, `Ok(2)`, `Ok(1)` for its four constant forms.
  - Location: `src/prover/synthesis.rs:405-429` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/r1cs.rs`

### Error

- [x] **INV-BOOL-ASSERT-12: natively a failing assertion fails with exactly its rule at the caller**
  - Covered by: `tests/unit/bool/native.rs` `every_assertion_on_constants_holds_exactly_as_its_truth_table_says`; `tests/unit/bool/native.rs` `every_assertion_fixture_holds_natively_exactly_as_its_truth_table_says`; `tests/unit/bool/r1cs.rs` `the_prover_refuses_a_non_boolean_operand_or_a_broken_assertion_before_synthesis`
  - Kind: error
  - Statement: every failing case of `assert_true`, `assert_false` and `assert_true_if` returns exactly `CircuitError.RuleBroken` with the rule passed in, located in the file that calls the assertion; `check_constraints` of a failing `assert_true` fixture fails with exactly `CircuitError.RuleBroken` before synthesis.
  - Location: `src/circuit/builtins/types/boolean.rs:83-96`, `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`, the constant branch)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/bool/native.rs`, `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-ASSERT-13: natively a non-boolean assertion operand fails with exactly NotZeroOrOne**
  - Covered by: `tests/unit/bool/native.rs` `every_non_boolean_operand_is_refused_natively_with_not_zero_or_one`; `tests/unit/bool/properties.rs` `natively_every_assertion_refuses_a_non_boolean_operand_and_holds_exactly_as_its_table_says` (property)
  - Kind: error
  - Statement: for every non-boolean vector and every random non-boolean field element in either operand, the native runs of `AssertedUnary`, `AssertedBinary` and every constant form of `assert_true_if` return exactly `CircuitError.NotZeroOrOne` located in the fixture's file, whatever the other operand.
  - Location: `src/circuit/builtins/field/bits.rs:50-58` (`fn assert_bool`)
  - Error: `CircuitErrorKind::NotZeroOrOne`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/bool/native.rs`, `tests/unit/bool/properties.rs`

### Equivalence

- [x] **INV-BOOL-ASSERT-14: assert_true_if is relation-equivalent to its own reference**
  - Covered by: `tests/unit/bool/external.rs` `assert_true_if_is_relation_equivalent_to_its_circom_reference`
  - Kind: equivalence
  - Statement: for every boolean pair and every non-boolean flag (with condition 0) or condition (with flag 1), `a.assert_true_if(&b)` and `assert_true_if.circom` accept exactly the same cases in all four checks, and both export exactly 3 constraints and 3 variables.
  - Location: `src/circuit/builtins/types/boolean.rs:93-96`, `tests/unit/bool/circom/assert_true_if.circom`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/bool/external.rs`

- [x] **INV-BOOL-ASSERT-15: Picus finds the same operands free in the assert_true_if reference**
  - Covered by: `tests/unit/bool/picus.rs` `picus_finds_the_flag_of_assert_true_if_free_in_the_sdk_and_in_circom`
  - Kind: equivalence
  - Statement: Picus reports exactly Unsafe for `assert_true_if.circom` with `main.a` promoted and with `main.b` promoted, the same verdicts as for the SDK export (INV-BOOL-ASSERT-09).
  - Location: `tests/unit/harness/equivalence.rs` (`fn picus_verdicts`)
  - Severity: High
  - Suggested test: external (Picus); `tests/unit/bool/picus.rs`

### Interop

- [x] **INV-BOOL-ASSERT-16: snarkjs accepts exactly the witnesses on which an assertion holds**
  - Covered by: `tests/unit/bool/external.rs` `snarkjs_accepts_exactly_the_witnesses_on_which_an_assertion_holds`
  - Kind: interop
  - Statement: for both booleans a, `snarkjs wtns check` accepts the `assert_true` export with the witness [1, a] exactly when a = 1 and the `assert_false` export exactly when a = 0, rejecting the other; for every boolean pair, it accepts the `a.assert_true_if(&b)` export with [1, a, b] exactly unless (a, b) = (0, 1).
  - Location: `src/circuit/builtins/types/boolean.rs:83-96`, `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: Critical
  - Suggested test: external (snarkjs); `tests/unit/bool/external.rs`

## Assert impl (`is_equal`, `assert_equal`, `assert_equal_if`, `assert_not_equal`)

`is_equal` is the sixth gate of `Variables<GATE>` (its truth table is exact equality);
`AssertedBinary<1>` and `AssertedBinary<2>` run `assert_equal` and the trait's default
`assert_not_equal`; `AssertEqualIf` runs `a.assert_equal_if(&b, &condition)`. The reference
for `is_equal` is circomlib `IsEqual` with a booleanity line per input.

### Semantics

- [x] **INV-BOOL-EQ-01: on constants is_equal is exactly equality and stays a constant**
  - Covered by: `tests/unit/bool/native.rs` `every_gate_on_constants_is_its_truth_table_and_stays_a_constant`
  - Kind: semantics
  - Statement: for every pair of Bool constants, `a.is_equal(&b)` returns `Ok` of a constant equal to exactly 1 when a = b and 0 otherwise.
  - Location: `src/circuit/builtins/types/boolean.rs:127-130` (`fn is_equal`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/native.rs`

- [x] **INV-BOOL-EQ-02: on constants the equality assertions hold exactly as their tables say**
  - Covered by: `tests/unit/bool/native.rs` `every_assertion_on_constants_holds_exactly_as_its_truth_table_says`
  - Kind: semantics
  - Statement: on Bool constants, `assert_equal` holds exactly when a = b, `assert_not_equal` exactly when a != b, and `assert_equal_if` exactly unless the condition is 1 and a != b.
  - Location: `src/circuit/builtins/types/boolean.rs:132-146` (`fn assert_equal`, `fn assert_equal_if`), `src/circuit/builtins/ops/assert.rs:25-28` (`fn assert_not_equal`, the default)
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/bool/native.rs`

- [x] **INV-BOOL-EQ-03: natively every equality fixture holds exactly as its table says**
  - Covered by: `tests/unit/bool/native.rs` `every_assertion_fixture_holds_natively_exactly_as_its_truth_table_says`; `tests/unit/bool/native.rs` `every_boolean_vector_holds_natively_in_every_output_fixture`; `tests/unit/bool/properties.rs` `natively_every_assertion_refuses_a_non_boolean_operand_and_holds_exactly_as_its_table_says` (property)
  - Kind: semantics
  - Statement: for every boolean pair (and triple for `assert_equal_if`), the native runs of `AssertedBinary<assert_equal>`, `AssertedBinary<assert_not_equal>`, `AssertEqualIf` and `Variables<is_equal>` with its honest claim hold exactly when their table says, and the assertions fail otherwise with exactly `CircuitError.RuleBroken` with the fixture's rule.
  - Location: `src/circuit/builtins/types/boolean.rs:127-146`
  - Severity: High
  - Suggested test: positive + negative + property; `tests/unit/bool/native.rs`, `tests/unit/bool/properties.rs`

### Constraint

- [x] **INV-BOOL-EQ-04: is_equal costs exactly one product row and claims 1 - a - b + 2ab**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_two_variable_gate_costs_one_product_row_and_inlines_its_truth_table`
  - Kind: constraint
  - Statement: `Variables<is_equal>` exports exactly 4 constraints and 5 variables, the product row A = {1: 1}, B = {2: 1}, C = {4: 1}, and the claim row, as a set of terms, A = {0: 1, 1: -1, 2: -1, 3: -1, 4: 2}: unlike `CircuitVar::is_equal`, it allocates no inverse hint.
  - Location: `src/circuit/builtins/types/boolean.rs:127-130` (`fn is_equal`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-EQ-05: assert_equal exports exactly one linear row**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_assertion_exports_exactly_its_golden_rows`
  - Kind: constraint
  - Statement: after the booleanity rows, `a.assert_equal(&b)` exports exactly A = {1: 1, 2: -1}, B = {0: 1}, C = {} and allocates no variable.
  - Location: `src/circuit/builtins/types/boolean.rs:132-135` (`fn assert_equal`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-EQ-06: assert_not_equal exports a product row and a linear row, no inverse hint**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_assertion_exports_exactly_its_golden_rows`
  - Kind: constraint
  - Statement: after the booleanity rows, `a.assert_not_equal(&b)` exports exactly the product row A = {1: 1}, B = {2: 1}, C = {3: 1} and A = {0: -1, 1: 1, 2: 1, 3: -2}, B = {0: 1}, C = {} (is_equal = 0), 4 variables in all: the trait's default goes through `is_equal` and `assert_false`, not the inverse hint of `CircuitVar::assert_not_equal`.
  - Location: `src/circuit/builtins/ops/assert.rs:25-28` (`fn assert_not_equal`, the default), `src/circuit/builtins/types/boolean.rs:127-130`
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-EQ-07: assert_equal_if exports exactly one product row**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_assertion_exports_exactly_its_golden_rows`
  - Kind: constraint
  - Statement: after the booleanity rows of a, b and the condition, `a.assert_equal_if(&b, &c)` exports exactly A = {1: 1, 2: -1}, B = {3: 1}, C = {} ((a - b) c = 0) and allocates no variable.
  - Location: `src/circuit/builtins/types/boolean.rs:137-146` (`fn assert_equal_if`), `src/circuit/builtins/ops/assert.rs:51-68`
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/bool/r1cs.rs`

### Completeness

- [x] **INV-BOOL-EQ-08: every holding equality case satisfies every row**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_holding_assertion_satisfies_every_exported_row_and_every_proving_row`; `tests/unit/bool/r1cs.rs` `every_boolean_vector_satisfies_every_exported_row_and_every_proving_row`
  - Kind: completeness
  - Statement: for every boolean input on which it holds, the exported assignment of `assert_equal`, `assert_not_equal`, `assert_equal_if` and of `is_equal` with the honest claim satisfies every exported row and every proving row.
  - Location: `src/circuit/builtins/types/boolean.rs:127-146`
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/r1cs.rs`

### Soundness

- [x] **INV-BOOL-EQ-09: a failing equality assertion breaks exactly its assertion row**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_failing_assertion_breaks_exactly_its_assertion_row_with_the_fixture_rule`
  - Kind: soundness
  - Statement: `check_tampered` of `assert_equal` at (1, 1) with b set to 0 returns exactly `ProverError.ProofInputsBreakRule` at row 2 with its rule, of `assert_equal_if` at (1, 0, 0) with the condition set to 1 at row 3 with its rule; the witnesses (1, 1, product 1) and (0, 0, product 0) of `assert_not_equal` leave exactly row 3 unsatisfied.
  - Location: `src/circuit/builtins/types/boolean.rs:127-146`, `src/circuit/builtins/ops/assert.rs:25-28`
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-EQ-10: a non-boolean equality operand is refused by its booleanity row alone**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_non_boolean_operand_breaks_exactly_its_booleanity_rows_with_every_other_row_satisfied`
  - Kind: soundness
  - Statement: for every non-boolean vector x, the witness (x, 0, 0) of `assert_equal_if` leaves exactly row 0 unsatisfied and (1, 1, x) exactly row 2: the assertion row accepts a non-boolean condition when a = b.
  - Location: `src/circuit/builtins/field/bits.rs:50-62` (`fn assert_bool`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-EQ-11: Picus finds exactly the operands an equality assertion fixes**
  - Covered by: `tests/unit/bool/picus.rs` `picus_finds_exactly_the_operands_an_assertion_fixes`; `tests/unit/bool/picus.rs` `picus_finds_every_gate_output_fixed_by_its_operands_in_the_sdk_and_in_circom`
  - Kind: soundness
  - Statement: with b promoted to an output, Picus reports exactly Safe for `assert_equal` (b = a) and `assert_not_equal` (b = 1 - a) and exactly Unsafe for `assert_equal_if` (b is free when the condition is 0); with `out` promoted, exactly Safe for `is_equal`.
  - Location: `src/prover/snarkjs.rs:20-45` (`fn picus_r1cs`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/bool/picus.rs`

- [x] **INV-BOOL-EQ-12: no private variable of an equality fixture is free**
  - Covered by: `tests/unit/bool/r1cs.rs` `no_private_variable_is_free_and_only_an_equal_sided_inverse_hint_is_tolerated`
  - Kind: soundness
  - Statement: for every holding input, `check_private_variables` reports no free and no tolerated variable, with exactly (3 constraints, 2 private variables) for `assert_equal`, (4, 3) for `assert_not_equal` and (4, 3) for `assert_equal_if`.
  - Location: `src/testing.rs:70-99` (`fn check_private_variables`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-EQ-20: a tampered assert_not_equal product breaks the product row with no label**
  - Covered by: `tests/unit/bool/r1cs.rs` `a_tampered_intermediate_witness_breaks_its_own_row`
  - Kind: soundness
  - Statement: `check_tampered` of `AssertedBinary<assert_not_equal>` at (1, 0) with the product witness (wire 3) increased by 1 returns exactly `ProverError.ProofInputsBreakRule` at row 2 with no label.
  - Location: `src/circuit/builtins/ops/assert.rs:25-28` (`fn assert_not_equal`, the default), `src/circuit/builtins/types/boolean.rs:127-130` (`fn is_equal`), `src/circuit/labels.rs:255-270` (`fn report`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/bool/r1cs.rs`

### Shape

- [x] **INV-BOOL-EQ-13: setup and proving produce identical equality matrices**
  - Covered by: `tests/unit/bool/r1cs.rs` `every_holding_assertion_satisfies_every_exported_row_and_every_proving_row`
  - Kind: shape
  - Statement: for every holding input, `check_constraints` returns exactly `Ok(3)` for `assert_equal`, `Ok(4)` for `assert_not_equal` and `Ok(4)` for `assert_equal_if`.
  - Location: `src/prover/synthesis.rs:405-429` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/r1cs.rs`

### Error

- [x] **INV-BOOL-EQ-14: natively a failing equality assertion fails with exactly its rule**
  - Covered by: `tests/unit/bool/native.rs` `every_assertion_on_constants_holds_exactly_as_its_truth_table_says`; `tests/unit/bool/native.rs` `every_assertion_fixture_holds_natively_exactly_as_its_truth_table_says`; `tests/unit/bool/r1cs.rs` `the_prover_refuses_a_non_boolean_operand_or_a_broken_assertion_before_synthesis`
  - Kind: error
  - Statement: every failing case of `assert_equal`, `assert_not_equal` and `assert_equal_if` returns exactly `CircuitError.RuleBroken` with the rule passed in, located in the calling file; `export_assignment` of a failing `assert_not_equal` fixture fails with exactly `CircuitError.RuleBroken`.
  - Location: `src/circuit/builtins/ops/assert.rs:37-68`
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/bool/native.rs`, `tests/unit/bool/r1cs.rs`

- [x] **INV-BOOL-EQ-15: natively a non-boolean equality operand fails with exactly NotZeroOrOne**
  - Covered by: `tests/unit/bool/native.rs` `every_non_boolean_operand_is_refused_natively_with_not_zero_or_one`; `tests/unit/bool/properties.rs` `natively_every_assertion_refuses_a_non_boolean_operand_and_holds_exactly_as_its_table_says` (property)
  - Kind: error
  - Statement: for every non-boolean pair, and every triple with a random non-boolean element in any position, the native runs of `AssertedBinary<assert_equal>`, `AssertedBinary<assert_not_equal>`, `AssertEqualIf` and `Variables<is_equal>` return exactly `CircuitError.NotZeroOrOne` located in the fixture's file, even when the condition of `AssertEqualIf` is 0.
  - Location: `src/circuit/builtins/field/bits.rs:50-58` (`fn assert_bool`)
  - Error: `CircuitErrorKind::NotZeroOrOne`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/bool/native.rs`, `tests/unit/bool/properties.rs`

### Equivalence

- [x] **INV-BOOL-EQ-16: is_equal is relation-equivalent to circomlib IsEqual**
  - Covered by: `tests/unit/bool/external.rs` `every_two_operand_gate_is_relation_equivalent_to_its_circom_reference`
  - Kind: equivalence
  - Statement: over the cases of INV-BOOL-GATE-20, `Variables<is_equal>` and `is_equal.circom` accept exactly the same cases in all four checks; the SDK exports exactly 4 constraints and 5 variables against exactly 9 and 10.
  - Location: `src/circuit/builtins/types/boolean.rs:127-130`, `tests/unit/bool/circom/is_equal.circom`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/bool/external.rs`

- [x] **INV-BOOL-EQ-17: Picus reports the IsEqual reference deterministic too**
  - Covered by: `tests/unit/bool/picus.rs` `picus_finds_every_gate_output_fixed_by_its_operands_in_the_sdk_and_in_circom`
  - Kind: equivalence
  - Statement: Picus reports exactly Safe for `is_equal.circom` with `main.out` promoted, the same verdict as for the SDK export.
  - Location: `tests/unit/harness/equivalence.rs` (`fn picus_verdicts`)
  - Severity: High
  - Suggested test: external (Picus); `tests/unit/bool/picus.rs`

- [x] **INV-BOOL-EQ-18: without a gadget witness the Picus export of an equality assertion is the snarkjs export**
  - Covered by: `tests/unit/bool/picus.rs` `the_picus_export_moves_exactly_the_gadget_witnesses_to_the_outputs_and_the_hint_last`
  - Kind: equivalence
  - Statement: the Picus exports of `AssertedBinary<assert_equal>` and `AssertEqualIf` are byte-identical to their snarkjs exports.
  - Location: `src/prover/snarkjs.rs:20-45` (`fn picus_r1cs`)
  - Severity: High
  - Suggested test: positive; `tests/unit/bool/picus.rs`

### Interop

- [x] **INV-BOOL-EQ-19: snarkjs accepts every honest is_equal witness and rejects a flipped one**
  - Covered by: `tests/unit/bool/external.rs` `snarkjs_accepts_every_honest_gate_witness_and_rejects_a_flipped_or_non_boolean_one`
  - Kind: interop
  - Statement: for every boolean pair, `snarkjs wtns check` accepts the `Variables<is_equal>` export with the honest assignment and rejects it with the claim negated or with a = 2 and the other wires recomputed.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`), `src/prover/snarkjs.rs:112-124` (`fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/bool/external.rs`

## Summary

- Total invariants: 121 (conversions 18, gates 27, folds 21, select 19, assertions 16, Assert impl 20)
- Critical: 41; High: 52; Medium: 28
- Covered: 121; Partial: 0; Findings: 0
- SPEC_DIVERGENCE items: none. `../spec.md` states that `Bool::try_from(&var)` checks a
  0 or 1 value, that `CircuitVar::from` turns a `Bool` back into a value, and that `From`
  widens a `Bool` into a `Uint`; INV-BOOL-CONV-02, -03, -06 and -07 pin exactly that.
- INSUFFICIENT_INFO items: none. `../spec.md` does not describe the gates, the folds,
  `select` or the assertions; their invariants are derived from `src/` alone, against
  independent truth tables.
