# CircuitVar Invariants

Covers the `CircuitVar` operators and constants of `src/circuit/builtins/field/var.rs`,
the methods of `src/circuit/builtins/field/arithmetic.rs` and the bit methods of
`src/circuit/builtins/field/bits.rs`, one section per operation, each extracted by
running [`PROMPT.md`](PROMPT.md). The tests live in `tests/unit/circuit_var/<op>/`; the
constants (`INV-CV-CONST`) are covered from `tests/unit/circuit_var/neg/constants.rs`,
since negation is `zero().minus(..)`. Invariants every builtin shares live in
`cross-cutting.md`.

## Addition (`+`, `+=`)

The operand forms are the nine impls `field_operators!` generates for `Add` and
`AddAssign`: with a variable operand `a + b`, `a + &b`, `&a + b`, `&a + &b`, `a += b` and
`a += &b`, and with a `Field` constant operand `a + k`, `&a + k` and `a += k`. The fixtures
in `tests/unit/circuit_var/add/fixtures.rs` assert `<form> == sum` with the rule "the sum is
left plus right": `Variables<FORM>` takes `left`, `right` and `sum` as private inputs, and
`WithConstant<FORM>` takes `right` as a constant whose placeholder is 0. The valid vectors
are 0 + 0, 0 + x, 1 + (p - 1), (p - 1) + (p - 1), (p - 1) / 2 + (p + 1) / 2,
(2^64 - 1) + 1, 2^253 + 2^253 and x + (-x); the invalid ones are 1 + 2 = 4, the boundary
claims 1 + (p - 1) = p - 1, (2^64 - 1) + 1 = 2^64 - 1, (2^64 - 1) + 1 = 2^64 + 1,
2^253 + 2^253 = (2^254 - p) + 1, 5 + 7 = 5 and 3 + 4 = 0 (all canonical), and the
non-canonical claim (p - 1) + 1 = p.

### Semantics

- [x] **INV-CV-ADD-01: the native sum is field addition modulo p**
  - Covered by: `tests/unit/circuit_var/add/native.rs` `the_native_sum_is_field_addition_modulo_p_in_every_form`; `tests/unit/circuit_var/add/native.rs` `constant_addition_is_commutative_and_associative_with_identity_and_inverse`; `tests/unit/circuit_var/add/properties.rs` `every_form_gives_the_same_native_sum` (property)
  - Kind: semantics
  - Statement: for every pair of field elements a and b, the native value of `constant(a) + constant(b)` is exactly `Field::from(a) + Field::from(b)`, the representative of a + b modulo p below p: 1 + (p - 1) is exactly 0, (p - 1) + (p - 1) is exactly p - 2 and 2^253 + 2^253 is exactly 2^254 - p.
  - Location: `src/circuit/builtins/field/var.rs:207-281` (`macro field_operators`), `src/circuit/builtins/field/var.rs:41-47` (`impl Add for Field`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/add/native.rs`, `tests/unit/circuit_var/add/properties.rs`

- [x] **INV-CV-ADD-02: constant plus constant stays a constant**
  - Covered by: `tests/unit/circuit_var/add/native.rs` `the_native_sum_is_field_addition_modulo_p_in_every_form`
  - Kind: semantics
  - Statement: for every pair of constants and every operand form, the sum is a constant: `value` returns exactly the sum and its `Debug` form is exactly `CircuitVar::constant(<sum>)`.
  - Location: `src/circuit/builtins/field/var.rs:95-109` (`fn constant`, `fn value`), `src/circuit/builtins/field/primitive.rs:56-58` (`fn plus`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/add/native.rs`

- [x] **INV-CV-ADD-03: addition never fails**
  - Covered by: `tests/unit/circuit_var/add/native.rs` `every_valid_vector_holds_natively_in_every_form`; `tests/unit/circuit_var/add/r1cs.rs` `the_proving_rows_accept_the_honest_sum_and_name_the_rule_for_another`
  - Kind: semantics
  - Statement: for every valid vector and every operand form, computing the sum returns a value without an error or a panic, in the native run and in the R1CS synthesis: both runs of the fixture complete.
  - Location: `src/circuit/builtins/field/var.rs:207-281` (`macro field_operators`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/add/native.rs`, `tests/unit/circuit_var/add/r1cs.rs`

- [x] **INV-CV-ADD-04: every operand form gives the same value**
  - Covered by: `tests/unit/circuit_var/add/native.rs` `the_native_sum_is_field_addition_modulo_p_in_every_form`; `tests/unit/circuit_var/add/properties.rs` `every_form_gives_the_same_native_sum` (property)
  - Kind: semantics
  - Statement: for every pair a and b, the native values of the nine operand forms are all exactly equal, with b a variable operand in the first six and the constant k = b in the last three.
  - Location: `src/circuit/builtins/field/var.rs:207-281` (`macro field_operators`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/add/native.rs`, `tests/unit/circuit_var/add/properties.rs`

### Constraint

- [x] **INV-CV-ADD-05: adding adds no constraint**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `adding_allocates_no_variable_and_adds_no_constraint`
  - Kind: constraint
  - Statement: for every operand form, the constraint count after computing a + b is exactly the count before: a circuit that computes all nine forms and asserts nothing exports exactly 0 constraints, and `check_constraints` returns exactly 0.
  - Location: `src/circuit/builtins/field/primitive.rs:56-58` (`fn plus`), `src/circuit/builtins/field/var.rs:207-281` (`macro field_operators`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/add/r1cs.rs`

- [x] **INV-CV-ADD-06: adding allocates no variable**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `adding_allocates_no_variable_and_adds_no_constraint`; `tests/unit/circuit_var/add/r1cs.rs` `the_assignment_is_the_constant_one_then_the_variable_inputs`
  - Kind: constraint
  - Statement: for every operand form, the variable count after computing a + b is exactly the count before: the circuit that computes all nine forms exports exactly the 3 variables of the constant one and its two inputs, and every fixture's exported assignment is exactly `[1, left, right, sum]` (`[1, left, sum]` with a constant operand).
  - Location: `src/circuit/builtins/field/primitive.rs:56-58` (`fn plus`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/add/r1cs.rs`

- [x] **INV-CV-ADD-07: the using row has coefficient exactly 1 for each operand**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `a_plus_b_exports_exactly_the_golden_row_and_header`
  - Kind: constraint
  - Statement: the R1CS of `(&left + &right).assert_equal(&sum, rule)` is exactly one row with A = {1: 1, 2: 1, 3: -1}, B = {0: 1} and C = {}: the sum's linear combination inlined into the assertion's `(left - right) * 1 = 0`. This is the shape derived by hand from `conditional_enforce_equal(sum, TRUE)`; arkworks 0.6 (gr1cs) inlines it with no extra row or variable.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`), `src/circuit/builtins/field/primitive.rs:56-58` (`fn plus`), `src/circuit/builtins/field/primitive.rs:107-109` (`fn enforce_equal`), `src/prover/synthesis.rs:242-268` (`fn circuit_matrices`, `cs.finalize()` inlines)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/add/r1cs.rs`

- [x] **INV-CV-ADD-08: a + a gives coefficient exactly 2**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `a_plus_a_has_coefficient_exactly_two`
  - Kind: constraint
  - Statement: `(&a + &a).assert_equal(&sum, rule)` exports exactly A = {1: 2, 2: -1}, B = {0: 1} and C = {}: the two occurrences of a merge into one entry of coefficient exactly 2.
  - Location: `src/circuit/builtins/field/primitive.rs:56-58` (`fn plus`), `src/prover/synthesis.rs:242-268` (`fn circuit_matrices`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/add/r1cs.rs`

- [x] **INV-CV-ADD-09: (a + b) - b inlines to exactly a**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `a_plus_b_minus_b_inlines_to_exactly_a`
  - Kind: constraint
  - Statement: `((&a + &b) - &b).assert_equal(&sum, rule)` exports exactly A = {1: 1, 3: -1}, B = {0: 1} and C = {}: b's cancelled coefficient leaves no entry.
  - Location: `src/circuit/builtins/field/primitive.rs:56-62` (`fn plus`, `fn minus`), `src/prover/synthesis.rs:242-268` (`fn circuit_matrices`)
  - Severity: Medium
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/add/r1cs.rs`

- [x] **INV-CV-ADD-10: a + Field(k) puts exactly k on variable 0**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `a_plus_a_constant_puts_exactly_the_constant_on_variable_zero`; `tests/unit/circuit_var/add/r1cs.rs` `the_proving_rows_accept_the_honest_sum_and_name_the_rule_for_another`
  - Kind: constraint
  - Statement: for every constant k, `(&a + Field(k)).assert_equal(&sum, rule)` has exactly k on variable 0 of A and allocates no variable for k: k = 5 exports exactly A = {0: 5, 1: 1, 2: -1}, k = 0 exports exactly A = {1: 1, 2: -1}, and for the right operand k of every valid vector the proving row accepts exactly left + k.
  - Location: `src/circuit/builtins/field/var.rs:241-255` (`impl Add<Field>` in `macro field_operators`), `src/circuit/builtins/field/var.rs:269-273` (`impl AddAssign<Field>`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/add/r1cs.rs`

- [x] **INV-CV-ADD-11: every form of one operand kind exports byte-identical R1CS**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `every_form_of_one_operand_kind_exports_byte_identical_r1cs`
  - Kind: constraint
  - Statement: the six variable operand forms export byte-identical `.r1cs` files, and the three constant operand forms export byte-identical `.r1cs` files.
  - Location: `src/circuit/builtins/field/var.rs:207-281` (`macro field_operators`), `src/prover/snarkjs.rs:10-55` (`fn r1cs`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/add/r1cs.rs`

- [x] **INV-CV-ADD-12: the exported header counts are exact**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `a_plus_b_exports_exactly_the_golden_row_and_header`
  - Kind: constraint
  - Statement: the add fixture's exported header is exactly: field size 32, the BN254 scalar prime, 4 variables, 0 public outputs, 0 public inputs, 3 private inputs, 4 labels and 1 constraint, with the identity label map `[0, 1, 2, 3]`.
  - Location: `src/prover/snarkjs.rs:10-55` (`fn r1cs`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/add/r1cs.rs`

### Completeness

- [x] **INV-CV-ADD-13: every valid vector satisfies every row**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `every_valid_vector_satisfies_the_row_and_a_tampered_sum_breaks_it`; `tests/unit/circuit_var/add/r1cs.rs` `the_proving_rows_accept_the_honest_sum_and_name_the_rule_for_another`; `tests/unit/circuit_var/add/properties.rs` `check_constraints_counts_one_constraint_for_every_valid_triple` (property)
  - Kind: completeness
  - Statement: for every valid vector, the exported assignment of every variable operand form satisfies every row of its exported R1CS, and the honest assignment of every operand form satisfies every proving row.
  - Location: `src/prover/synthesis.rs:169-197` (`fn check`), `src/prover/snarkjs.rs:57-69` (`fn wtns`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/add/r1cs.rs`, `tests/unit/circuit_var/add/properties.rs`

- [x] **INV-CV-ADD-30: a constant fixed in the circuit exports a row every honest witness satisfies**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `a_constant_fixed_in_the_circuit_exports_a_row_every_honest_witness_satisfies`
  - Kind: completeness
  - Statement: for the left operand a of every valid vector, the exported assignment of `PlusFive { a, sum: a + 5 }` satisfies every row of `PlusFive`'s exported R1CS (`first_unsatisfied` is exactly `None`), and the same assignment with the sum increased by 1 leaves exactly row 0 unsatisfied. Unlike the `WithConstant` forms (INV-CV-ADD-17), the constant is part of the circuit, so the placeholder's export is the proof's.
  - Location: `src/circuit/builtins/field/var.rs:241-255` (`impl Add<Field>` in `macro field_operators`), `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/circuit_var/add/r1cs.rs`

### Soundness

- [x] **INV-CV-ADD-14: every wrong sum leaves some row unsatisfied**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `every_valid_vector_satisfies_the_row_and_a_tampered_sum_breaks_it`; `tests/unit/circuit_var/add/r1cs.rs` `every_invalid_vector_breaks_the_row`; `tests/unit/circuit_var/add/properties.rs` `a_wrong_sum_is_refused_natively_and_in_r1cs` (property)
  - Kind: soundness
  - Statement: for every left and right and every sum other than left + right, the assignment `[1, left, right, sum]` leaves exactly row 0 of the exported R1CS unsatisfied, and the proving rows of every operand form refuse that sum.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`), `src/circuit/builtins/field/primitive.rs:107-109` (`fn enforce_equal`)
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/circuit_var/add/r1cs.rs`, `tests/unit/circuit_var/add/properties.rs`

- [x] **INV-CV-ADD-15: no private variable of the fixture is free**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `no_private_variable_is_free_in_any_form`
  - Kind: soundness
  - Statement: for every valid vector and every operand form, `check_private_variables` reports exactly 1 constraint, exactly the fixture's private variables (3, or 2 with a constant operand), no free variable and no tolerated variable. `check_private_variables` perturbs one private variable at a time with random values: it finds a variable no constraint binds, but it does not prove the witness unique. Variables that can move together are not detected; that needs a determinism checker such as Picus. For addition, INV-CV-ADD-32 closes that gap with Picus.
  - Location: `src/prover/synthesis.rs:106-167` (`fn unconstrained_private_variables`), `src/testing.rs:70-99` (`fn check_private_variables`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/circuit_var/add/r1cs.rs`

- [x] **INV-CV-ADD-32: Picus proves every add fixture's sum fixed by its operands**
  - Covered by: `tests/unit/circuit_var/add/picus.rs` `picus_finds_every_form_safe_and_the_sum_fixed_by_its_operands`; `tests/unit/circuit_var/add/picus.rs` `picus_finds_the_sum_of_a_plus_a_and_a_plus_five_fixed`
  - Kind: soundness
  - Statement: for every operand form, `run-picus --solver cvc5` reports exactly Safe for the `export_picus_r1cs` file, and exactly Safe once the sum is moved from the private inputs to the outputs: no two witnesses with the same left and right (or a, for `Double` and `PlusFive`) differ in the sum. This proves the witness unique given the operands, which the single-variable perturbation of INV-CV-ADD-15 does not.
  - Location: `src/prover/snarkjs.rs:20-45` (`fn picus_r1cs`), `src/client/zk_circuit.rs:19-25` (`fn export_picus_r1cs`), `tests/unit/harness/picus.rs` (`fn verdict`, `fn promote`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/circuit_var/add/picus.rs`

- [x] **INV-CV-ADD-33: Picus reports an operand no constraint fixes as unsafe**
  - Covered by: `tests/unit/circuit_var/add/picus.rs` `picus_finds_b_free_once_a_plus_b_minus_b_inlines_to_a`; `tests/unit/circuit_var/add/picus.rs` `picus_finds_an_operand_free_when_no_sum_is_asserted`
  - Kind: soundness
  - Statement: Picus distinguishes a free variable from a fixed one on the add fixtures: in `AddThenSubtract`, whose row inlines to a - sum = 0, a and the sum are each exactly Safe once moved to the outputs and b is exactly Unsafe; in the deliberately unasserted fixture, the export with no outputs is exactly Safe and `right` moved to the outputs is exactly Unsafe.
  - Location: `src/prover/snarkjs.rs:20-45` (`fn picus_r1cs`), `tests/unit/harness/picus.rs` (`fn verdict`, `fn promote`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/circuit_var/add/picus.rs`

### Shape

- [x] **INV-CV-ADD-16: setup and proving produce identical matrices**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `every_valid_vector_checks_one_constraint_in_every_variable_form`; `tests/unit/circuit_var/add/properties.rs` `check_constraints_counts_one_constraint_for_every_valid_triple` (property)
  - Kind: shape
  - Statement: for every valid vector and every variable operand form, `check_constraints` returns exactly `Ok(1)`: the placeholder's setup synthesis and the proof's synthesis have the same shape and the same rows.
  - Location: `src/prover/synthesis.rs:400-424` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/add/r1cs.rs`, `tests/unit/circuit_var/add/properties.rs`

- [x] **INV-CV-ADD-17: a constant operand is part of the circuit**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `a_constant_other_than_the_placeholders_builds_a_different_row`
  - Kind: shape
  - Statement: for every valid vector and every constant operand form, `check_constraints` returns exactly `Ok(1)` when the constant equals the placeholder's (0), and otherwise exactly `ProverError.ConstraintsDiffer` at row 0 labelled with the fixture's rule.
  - Location: `src/prover/synthesis.rs:400-424` (`fn check_constraints`), `src/prover/synthesis.rs:83-87` (`fn first_differing_row`)
  - Error: `ProverErrorKind::ConstraintsDiffer`
  - Severity: High
  - Suggested test: negative; `tests/unit/circuit_var/add/r1cs.rs`

### Error

- [x] **INV-CV-ADD-18: a wrong sum fails natively with exactly the fixture's rule**
  - Covered by: `tests/unit/circuit_var/add/native.rs` `every_invalid_vector_breaks_exactly_the_fixture_rule_natively`; `tests/unit/circuit_var/add/properties.rs` `natively_every_form_holds_exactly_when_the_sum_is_left_plus_right` (property); `tests/unit/circuit_var/add/properties.rs` `a_wrong_sum_is_refused_natively_and_in_r1cs` (property)
  - Kind: error
  - Statement: for every left and right and every sum other than left + right, the native run of every operand form returns exactly `CircuitError.RuleBroken` with the rule "the sum is left plus right", located in the fixture's file.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`, the constant branch)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/circuit_var/add/native.rs`, `tests/unit/circuit_var/add/properties.rs`

- [x] **INV-CV-ADD-19: a tampered sum fails in R1CS with exactly the fixture's rule**
  - Covered by: `tests/unit/circuit_var/add/r1cs.rs` `the_proving_rows_accept_the_honest_sum_and_name_the_rule_for_another`; `tests/unit/circuit_var/add/properties.rs` `a_wrong_sum_is_refused_natively_and_in_r1cs` (property)
  - Kind: error
  - Statement: for every valid vector and every operand form, `check_tampered` with the sum changed to another value returns exactly `ProverError.ProofInputsBreakRule` at row 0 labelled with the fixture's rule.
  - Location: `src/testing.rs:43-68` (`fn check_tampered`), `src/prover/synthesis.rs:169-197` (`fn check`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/circuit_var/add/r1cs.rs`, `tests/unit/circuit_var/add/properties.rs`

- [x] **INV-CV-ADD-20: a sum of p is refused before it reaches the circuit**
  - Covered by: `tests/unit/circuit_var/add/native.rs` `a_sum_of_p_is_refused_before_it_reaches_the_circuit`
  - Kind: error
  - Statement: the non-canonical claim (p - 1) + 1 = p never reaches a fixture: p has no canonical `Field`, and `conversion::field` and the `[u8; 32]` proof input refuse its bytes with exactly `CircuitError.BytesTooLarge`, although p is congruent to the true sum 0.
  - Location: `src/conversion/var.rs:13-20` (`fn field`), `src/conversion/var.rs:148-158` (`impl ProofInput for [u8; 32]`)
  - Error: `CircuitErrorKind::BytesTooLarge`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/circuit_var/add/native.rs`

### Equivalence

- [x] **INV-CV-ADD-21: the normalized rows equal circom's**
  - Covered by: `tests/unit/circuit_var/add/external.rs` `circom_rows_normalize_to_the_sdk_rows_under_an_equal_header`
  - Kind: equivalence
  - Statement: the SDK export and `add.circom` (`sum === left + right`, compiled with `--O0`) normalize to exactly the same multiset of constraints, the single linear constraint {1: 1, 2: 1, 3: -1}. circom writes it as `0 * 0 = C` with C = left + right - sum, and the SDK as `A * 1 = 0`.
  - Location: `src/prover/snarkjs.rs:10-55` (`fn r1cs`), `tests/unit/circuit_var/add/add.circom`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/add/external.rs`

- [x] **INV-CV-ADD-22: the SDK header equals circom's**
  - Covered by: `tests/unit/circuit_var/add/external.rs` `circom_rows_normalize_to_the_sdk_rows_under_an_equal_header`
  - Kind: equivalence
  - Statement: the SDK export's header and label map are exactly circom's, so the variables map by index: left, right and sum are variables 1, 2 and 3 in both.
  - Location: `src/prover/snarkjs.rs:10-55` (`fn r1cs`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/add/external.rs`

- [x] **INV-CV-ADD-23: the circom witness equals the SDK witness**
  - Covered by: `tests/unit/circuit_var/add/external.rs` `circom_witnesses_equal_the_sdk_witnesses`
  - Kind: equivalence
  - Statement: for every valid vector, the witness `ark_circom::WitnessCalculator` computes from circom's wasm is exactly the SDK's exported assignment.
  - Location: `src/prover/synthesis.rs:270-273` (`fn assignment_of`), `src/prover/snarkjs.rs:57-69` (`fn wtns`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/add/external.rs`

- [x] **INV-CV-ADD-24: circom witness calculation fails for every invalid vector**
  - Covered by: `tests/unit/circuit_var/add/external.rs` `circom_witness_calculation_fails_for_every_invalid_vector`
  - Kind: equivalence
  - Statement: for every invalid vector, including the sum p passed unreduced, circom's witness calculation aborts with exactly "Assert Failed" from `sum === left + right`. ark-circom's own runtime ignores circom's `exceptionHandler`, so the harness installs one that aborts as circom's runtime does; snarkjs's `wtns calculate` reduces p to 0 first and accepts that claim.
  - Location: `tests/unit/circuit_var/add/add.circom`, `tests/unit/harness/circom.rs` (`fn calculator`)
  - Severity: Medium
  - Suggested test: external (circom); `tests/unit/circuit_var/add/external.rs`

- [x] **INV-CV-ADD-25: each R1CS accepts the other's witness**
  - Covered by: `tests/unit/circuit_var/add/external.rs` `each_r1cs_accepts_the_others_witness`
  - Kind: equivalence
  - Statement: for every valid vector, the circom R1CS accepts the SDK witness and the SDK R1CS accepts the circom witness: `first_unsatisfied` is exactly `None` both ways.
  - Location: `src/prover/snarkjs.rs:10-69` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/add/external.rs`

- [x] **INV-CV-ADD-31: with no gadget witness the Picus export is the snarkjs export**
  - Covered by: `tests/unit/circuit_var/add/picus.rs` `with_no_gadget_witness_the_picus_export_is_the_snarkjs_export`
  - Kind: equivalence
  - Statement: for every operand form and for `Unasserted`, `Double`, `AddThenSubtract` and `PlusFive`, `export_picus_r1cs` is byte-identical to `export_r1cs`: none of them allocates a gadget witness, so the Picus wire order (outputs, then public inputs, then private inputs, then inverse hints) is the variable order and the header has 0 outputs.
  - Location: `src/prover/snarkjs.rs:20-110` (`fn picus_r1cs`, `fn r1cs_in_wire_order`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/add/picus.rs`

### Interop

- [x] **INV-CV-ADD-26: snarkjs wtns check accepts the SDK pair**
  - Covered by: `tests/unit/circuit_var/add/external.rs` `snarkjs_accepts_the_sdk_pair_and_rejects_a_tampered_witness`
  - Kind: interop
  - Statement: for every valid vector, `snarkjs wtns check` accepts the SDK R1CS with the SDK assignment.
  - Location: `src/prover/snarkjs.rs:10-69` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/add/external.rs`

- [x] **INV-CV-ADD-27: snarkjs wtns check rejects a tampered witness**
  - Covered by: `tests/unit/circuit_var/add/external.rs` `snarkjs_accepts_the_sdk_pair_and_rejects_a_tampered_witness`
  - Kind: interop
  - Statement: for every valid vector, `snarkjs wtns check` rejects the SDK R1CS with the SDK assignment whose sum is increased by exactly 1.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`), `src/prover/snarkjs.rs:10-55` (`fn r1cs`)
  - Severity: Critical
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/add/external.rs`

- [x] **INV-CV-ADD-28: snarkjs wtns check accepts both cross pairs**
  - Covered by: `tests/unit/circuit_var/add/external.rs` `snarkjs_accepts_both_cross_pairs`
  - Kind: interop
  - Statement: for every valid vector, `snarkjs wtns check` accepts the circom R1CS with the SDK assignment, and the SDK R1CS with the circom witness.
  - Location: `src/prover/snarkjs.rs:10-69` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs, circom); `tests/unit/circuit_var/add/external.rs`

- [x] **INV-CV-ADD-29: snarkjs Groth16 proves and verifies**
  - Covered by: `tests/unit/circuit_var/add/external.rs` `snarkjs_proves_and_verifies_the_sdk_circuit`
  - Kind: interop
  - Statement: `snarkjs groth16 setup` over a throwaway power-4 ptau, `groth16 prove` with the SDK assignment of 2^253 + 2^253 and `groth16 verify` accept the SDK R1CS, with exactly the empty public signal list.
  - Location: `src/prover/snarkjs.rs:10-69` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/add/external.rs`

## Subtraction (`-`, `-=`)

The operand forms are the nine impls `field_operators!` generates for `Sub` and
`SubAssign`: `a - b`, `a - &b`, `&a - b`, `&a - &b`, `a -= b` and `a -= &b` with a variable
operand, and `a - k`, `&a - k` and `a -= k` with a `Field` constant. The fixtures in
`tests/unit/circuit_var/sub/fixtures.rs` assert `<form> == difference` with the rule "the
difference is left minus right": `Variables<FORM>` takes `left`, `right` and `difference`
as private inputs (variables 1, 2 and 3), and `WithConstant<FORM>` takes `right` as a
constant whose placeholder is 0. `SelfMinusSelf` asserts `a - a == difference`, `MinusFive`
asserts `a - 5 == difference`, and `Unasserted` computes all nine forms (the constant is 7)
and asserts nothing. The valid vectors are 0 - 0, x - 0, 0 - 1 = p - 1, 1 - (p - 1) = 2,
(p - 1) - (p - 1) = 0, (p + 1) / 2 - (p - 1) / 2 = 1, 2^64 - 1, 0 - 2^253 = p - 2^253 and
x - (-x) = 2x; the invalid ones are 5 - 3 = 3, 0 - 1 = 1, 2 - 1 = p - 1, 2^64 - 1 = 2^64,
1 - (p - 1) = 0, x - (-x) = 0 and (p - 1) - (p - 1) = p - 1 (all canonical), and the
non-canonical claim 1 - 1 = p.

### Semantics

- [x] **INV-CV-SUB-01: the native difference is field subtraction modulo p**
  - Covered by: `tests/unit/circuit_var/sub/native.rs` `the_native_difference_is_field_subtraction_modulo_p_in_every_form`; `tests/unit/circuit_var/sub/properties.rs` `every_form_gives_the_same_native_difference` (property)
  - Kind: semantics
  - Statement: for every valid vector and every operand form, the native value of the difference is exactly `Field::from(left) - Field::from(right)`, the vector's difference: 0 - 1 is exactly p - 1, 1 - (p - 1) is exactly 2 and 0 - 2^253 is exactly p - 2^253; for every random pair it is exactly `left - right`.
  - Location: `src/circuit/builtins/field/var.rs:207-281` (`macro field_operators`), `src/circuit/builtins/field/var.rs:49-55` (`impl Sub for Field`), `src/circuit/builtins/field/primitive.rs:60-62` (`fn minus`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/sub/native.rs`, `tests/unit/circuit_var/sub/properties.rs`

- [x] **INV-CV-SUB-02: constant minus constant stays a constant**
  - Covered by: `tests/unit/circuit_var/sub/native.rs` `the_native_difference_is_field_subtraction_modulo_p_in_every_form`
  - Kind: semantics
  - Statement: for every valid vector and every operand form, the native difference's `Debug` form is exactly `CircuitVar::constant(<difference>)` and `value` returns exactly the difference.
  - Location: `src/circuit/builtins/field/var.rs:86-109` (`impl Debug for CircuitVar`, `fn value`), `src/circuit/builtins/field/primitive.rs:60-62` (`fn minus`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/sub/native.rs`

- [x] **INV-CV-SUB-03: subtraction never fails**
  - Covered by: `tests/unit/circuit_var/sub/native.rs` `every_valid_vector_holds_natively_in_every_form`; `tests/unit/circuit_var/sub/r1cs.rs` `the_proving_rows_accept_the_honest_difference_and_name_the_rule_for_another`
  - Kind: semantics
  - Statement: for every valid vector and every operand form, the native run returns exactly `Ok(())` and the proving synthesis completes, so `check_tampered` with the honest difference returns exactly `Ok(())`.
  - Location: `src/circuit/builtins/field/var.rs:207-281` (`macro field_operators`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/sub/native.rs`, `tests/unit/circuit_var/sub/r1cs.rs`

- [x] **INV-CV-SUB-04: every operand form gives the same value**
  - Covered by: `tests/unit/circuit_var/sub/native.rs` `the_native_difference_is_field_subtraction_modulo_p_in_every_form`; `tests/unit/circuit_var/sub/properties.rs` `every_form_gives_the_same_native_difference` (property)
  - Kind: semantics
  - Statement: for every pair of field elements, the native values of the nine operand forms are all exactly equal, with the constant k = right in the last three.
  - Location: `src/circuit/builtins/field/var.rs:207-281` (`macro field_operators`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/sub/native.rs`, `tests/unit/circuit_var/sub/properties.rs`

- [x] **INV-CV-SUB-05: constant subtraction is addition of the negation**
  - Covered by: `tests/unit/circuit_var/sub/native.rs` `constant_subtraction_adds_the_negation_undoes_addition_and_anticommutes`
  - Kind: semantics
  - Statement: for every pair a and b of the 18 operands of the valid vectors, as constants, the native values satisfy exactly a - b = a + (-b), (a - b) + b = a and b - a = -(a - b), and for every operand a - a is exactly 0 and a - `zero()` is exactly a.
  - Location: `src/circuit/builtins/field/var.rs:207-297` (`macro field_operators`, `impl Neg for CircuitVar`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/sub/native.rs`

### Constraint

- [x] **INV-CV-SUB-06: subtracting adds no constraint**
  - Covered by: `tests/unit/circuit_var/sub/r1cs.rs` `subtracting_allocates_no_variable_and_adds_no_constraint`
  - Kind: constraint
  - Statement: `Unasserted`, which computes all nine forms and asserts nothing, exports exactly 0 constraints, and `check_constraints` returns exactly `Ok(0)`.
  - Location: `src/circuit/builtins/field/primitive.rs:60-62` (`fn minus`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/sub/r1cs.rs`

- [x] **INV-CV-SUB-07: subtracting allocates no variable**
  - Covered by: `tests/unit/circuit_var/sub/r1cs.rs` `subtracting_allocates_no_variable_and_adds_no_constraint`; `tests/unit/circuit_var/sub/r1cs.rs` `the_assignment_is_the_constant_one_then_the_variable_inputs`
  - Kind: constraint
  - Statement: `Unasserted` exports exactly the 3 variables of the constant one and its two inputs, with the assignment exactly `[1, 1, 2]`, and for every valid vector every fixture's exported assignment is exactly `[1, left, right, difference]` (`[1, left, difference]` with a constant operand).
  - Location: `src/circuit/builtins/field/primitive.rs:60-62` (`fn minus`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/sub/r1cs.rs`

- [x] **INV-CV-SUB-08: the using row has coefficient exactly -1 for the subtrahend**
  - Covered by: `tests/unit/circuit_var/sub/r1cs.rs` `a_minus_b_exports_exactly_the_golden_row_and_header`
  - Kind: constraint
  - Statement: the R1CS of `(&left - &right).assert_equal(&difference, rule)` is exactly one row A = {1: 1, 2: -1, 3: -1}, B = {0: 1}, C = {}: the difference inlined into the assertion's `(left - right - difference) * 1 = 0`.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`), `src/circuit/builtins/field/primitive.rs:60-62` (`fn minus`), `src/prover/synthesis.rs:247-273` (`fn circuit_matrices`, `cs.finalize()` inlines)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/sub/r1cs.rs`

- [x] **INV-CV-SUB-09: a - a cancels to no entry for a**
  - Covered by: `tests/unit/circuit_var/sub/r1cs.rs` `a_minus_a_cancels_to_no_entry_for_a`
  - Kind: constraint
  - Statement: `SelfMinusSelf` exports exactly A = {2: -1}, B = {0: 1}, C = {}: a's cancelled coefficient leaves no entry, so the row reads `difference = 0`.
  - Location: `src/circuit/builtins/field/primitive.rs:60-62` (`fn minus`), `src/prover/synthesis.rs:247-273` (`fn circuit_matrices`)
  - Severity: Medium
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/sub/r1cs.rs`

- [x] **INV-CV-SUB-10: a - Field(k) puts exactly -k on variable 0**
  - Covered by: `tests/unit/circuit_var/sub/r1cs.rs` `a_minus_a_constant_puts_exactly_minus_the_constant_on_variable_zero`; `tests/unit/circuit_var/sub/r1cs.rs` `the_proving_rows_accept_the_honest_difference_and_name_the_rule_for_another`
  - Kind: constraint
  - Statement: `MinusFive` exports exactly A = {0: -5, 1: 1, 2: -1}, B = {0: 1}, C = {}; `WithConstant<1>` exported from its placeholder k = 0 exports exactly A = {1: 1, 2: -1}; and for the right operand k of every valid vector the proving row of every constant form accepts exactly left - k.
  - Location: `src/circuit/builtins/field/var.rs:241-255` (`impl Sub<Field>` in `macro field_operators`), `src/circuit/builtins/field/var.rs:269-273` (`impl SubAssign<Field>`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/sub/r1cs.rs`

- [x] **INV-CV-SUB-11: every form of one operand kind exports byte-identical R1CS**
  - Covered by: `tests/unit/circuit_var/sub/r1cs.rs` `every_form_of_one_operand_kind_exports_byte_identical_r1cs`
  - Kind: constraint
  - Statement: the six variable operand forms export byte-identical `.r1cs` files, and the three constant operand forms export byte-identical `.r1cs` files.
  - Location: `src/circuit/builtins/field/var.rs:207-281` (`macro field_operators`), `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/sub/r1cs.rs`

- [x] **INV-CV-SUB-12: the exported header counts are exact**
  - Covered by: `tests/unit/circuit_var/sub/r1cs.rs` `a_minus_b_exports_exactly_the_golden_row_and_header`
  - Kind: constraint
  - Statement: the sub fixture's exported header is exactly: field size 32, the BN254 scalar prime, 4 variables, 0 public outputs, 0 public inputs, 3 private inputs, 4 labels and 1 constraint, with the identity label map `[0, 1, 2, 3]`.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`), `src/prover/snarkjs.rs:49-110` (`fn r1cs_in_wire_order`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/sub/r1cs.rs`

### Completeness

- [x] **INV-CV-SUB-13: every valid vector satisfies every row**
  - Covered by: `tests/unit/circuit_var/sub/r1cs.rs` `every_valid_vector_satisfies_the_row_and_a_tampered_difference_breaks_it`; `tests/unit/circuit_var/sub/r1cs.rs` `the_proving_rows_accept_the_honest_difference_and_name_the_rule_for_another`; `tests/unit/circuit_var/sub/properties.rs` `check_constraints_counts_one_constraint_for_every_valid_triple` (property)
  - Kind: completeness
  - Statement: for every valid vector, the exported assignment of every variable operand form satisfies every row of its exported R1CS (`first_unsatisfied` is exactly `None`), and the honest assignment of every operand form satisfies every proving row; for every random pair, `check_constraints` of every variable form with the honest difference returns exactly `Ok(1)`.
  - Location: `src/prover/synthesis.rs:174-202` (`fn check`), `src/prover/snarkjs.rs:112-124` (`fn wtns`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/sub/r1cs.rs`, `tests/unit/circuit_var/sub/properties.rs`

- [x] **INV-CV-SUB-14: a constant fixed in the circuit exports a row every honest witness satisfies**
  - Covered by: `tests/unit/circuit_var/sub/r1cs.rs` `a_constant_fixed_in_the_circuit_exports_a_row_every_honest_witness_satisfies`
  - Kind: completeness
  - Statement: for the left operand a of every valid vector, the exported assignment of `MinusFive { a, difference: a - 5 }` satisfies every row of `MinusFive`'s exported R1CS, and the same assignment with the difference increased by 1 leaves exactly row 0 unsatisfied.
  - Location: `src/circuit/builtins/field/var.rs:241-255` (`impl Sub<Field>` in `macro field_operators`), `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/circuit_var/sub/r1cs.rs`

### Soundness

- [x] **INV-CV-SUB-15: every wrong difference leaves row 0 unsatisfied**
  - Covered by: `tests/unit/circuit_var/sub/r1cs.rs` `every_valid_vector_satisfies_the_row_and_a_tampered_difference_breaks_it`; `tests/unit/circuit_var/sub/r1cs.rs` `every_invalid_vector_breaks_the_row`; `tests/unit/circuit_var/sub/properties.rs` `a_wrong_difference_is_refused_natively_and_in_r1cs` (property)
  - Kind: soundness
  - Statement: for every valid vector and every variable form, the honest assignment with the difference increased by 1 leaves exactly row 0 unsatisfied; for every invalid vector and for every random wrong difference, the assignment `[1, left, right, difference]` leaves exactly row 0 of the exported R1CS unsatisfied.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`), `src/circuit/builtins/field/primitive.rs:107-109` (`fn enforce_equal`)
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/circuit_var/sub/r1cs.rs`, `tests/unit/circuit_var/sub/properties.rs`

- [x] **INV-CV-SUB-16: no private variable of the fixture is free**
  - Covered by: `tests/unit/circuit_var/sub/r1cs.rs` `no_private_variable_is_free_in_any_form`
  - Kind: soundness
  - Statement: for every valid vector and every operand form, `check_private_variables` reports exactly 1 constraint, exactly the fixture's private variables (3, or 2 with a constant operand), no free variable and no tolerated variable. The perturbation finds an unbound variable but does not prove the witness unique; INV-CV-SUB-17 does, with Picus.
  - Location: `src/prover/synthesis.rs:111-172` (`fn unconstrained_private_variables`), `src/testing.rs:70-99` (`fn check_private_variables`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/circuit_var/sub/r1cs.rs`

- [x] **INV-CV-SUB-17: Picus proves every sub fixture's difference fixed by its operands**
  - Covered by: `tests/unit/circuit_var/sub/picus.rs` `picus_finds_every_form_safe_and_the_difference_fixed_by_its_operands`; `tests/unit/circuit_var/sub/picus.rs` `picus_finds_a_free_once_a_minus_a_cancels`
  - Kind: soundness
  - Statement: for every operand form, `run-picus --solver cvc5` reports exactly Safe for the `export_picus_r1cs` file and exactly Safe once the difference is moved to the outputs, and it reports exactly Safe for `MinusFive` with its difference moved to the outputs: no two witnesses with the same operands differ in the difference. Every call runs under a 120 s limit.
  - Location: `src/prover/snarkjs.rs:19-45` (`fn picus_r1cs`), `tests/unit/harness/picus.rs` (`fn verdict_within`, `fn promote`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/circuit_var/sub/picus.rs`

- [x] **INV-CV-SUB-18: Picus reports an operand no constraint fixes as unsafe**
  - Covered by: `tests/unit/circuit_var/sub/picus.rs` `picus_finds_a_free_once_a_minus_a_cancels`; `tests/unit/circuit_var/sub/picus.rs` `picus_finds_an_operand_free_when_no_difference_is_asserted`
  - Kind: soundness
  - Statement: in `SelfMinusSelf`, whose row reads `difference = 0`, a moved to the outputs is exactly Unsafe and the difference moved to the outputs is exactly Safe; in `Unasserted`, the export with no outputs is exactly Safe and `right` moved to the outputs is exactly Unsafe.
  - Location: `src/prover/snarkjs.rs:19-45` (`fn picus_r1cs`), `tests/unit/harness/picus.rs` (`fn verdict_within`, `fn promote`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/circuit_var/sub/picus.rs`

### Shape

- [x] **INV-CV-SUB-19: setup and proving produce identical matrices**
  - Covered by: `tests/unit/circuit_var/sub/r1cs.rs` `every_valid_vector_checks_one_constraint_in_every_variable_form`; `tests/unit/circuit_var/sub/properties.rs` `check_constraints_counts_one_constraint_for_every_valid_triple` (property)
  - Kind: shape
  - Statement: for every valid vector, every random pair and every variable operand form, `check_constraints` returns exactly `Ok(1)`: the placeholder's setup synthesis and the proof's synthesis have the same shape and the same rows.
  - Location: `src/prover/synthesis.rs:405-429` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/sub/r1cs.rs`, `tests/unit/circuit_var/sub/properties.rs`

- [x] **INV-CV-SUB-20: a constant operand is part of the circuit**
  - Covered by: `tests/unit/circuit_var/sub/r1cs.rs` `a_constant_other_than_the_placeholders_builds_a_different_row`
  - Kind: shape
  - Statement: for every valid vector and every constant operand form, `check_constraints` returns exactly `Ok(1)` when the constant equals the placeholder's (0), and otherwise exactly `ProverError.ConstraintsDiffer` at row 0 labelled with the fixture's rule.
  - Location: `src/prover/synthesis.rs:405-429` (`fn check_constraints`), `src/prover/synthesis.rs:83-87` (`fn first_differing_row`)
  - Error: `ProverErrorKind::ConstraintsDiffer`
  - Severity: High
  - Suggested test: negative; `tests/unit/circuit_var/sub/r1cs.rs`

### Error

- [x] **INV-CV-SUB-21: a wrong difference fails natively with exactly the fixture's rule**
  - Covered by: `tests/unit/circuit_var/sub/native.rs` `every_invalid_vector_breaks_exactly_the_fixture_rule_natively`; `tests/unit/circuit_var/sub/properties.rs` `natively_every_form_holds_exactly_when_the_difference_is_left_minus_right` (property); `tests/unit/circuit_var/sub/properties.rs` `a_wrong_difference_is_refused_natively_and_in_r1cs` (property)
  - Kind: error
  - Statement: for every invalid vector, every random wrong difference and every operand form, the native run returns exactly `CircuitError.RuleBroken` with the rule "the difference is left minus right", located in the fixture's file; with the honest difference it returns exactly `Ok(())`.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`, the constant branch)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/circuit_var/sub/native.rs`, `tests/unit/circuit_var/sub/properties.rs`

- [x] **INV-CV-SUB-22: a tampered difference fails in R1CS with exactly the fixture's rule**
  - Covered by: `tests/unit/circuit_var/sub/r1cs.rs` `the_proving_rows_accept_the_honest_difference_and_name_the_rule_for_another`; `tests/unit/circuit_var/sub/properties.rs` `a_wrong_difference_is_refused_natively_and_in_r1cs` (property)
  - Kind: error
  - Statement: for every valid vector and every operand form, `check_tampered` with the difference increased by 1 returns exactly `ProverError.ProofInputsBreakRule` at row 0 labelled with the fixture's rule; for every random wrong difference the broken rule is exactly the fixture's.
  - Location: `src/testing.rs:43-68` (`fn check_tampered`), `src/prover/synthesis.rs:174-202` (`fn check`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/circuit_var/sub/r1cs.rs`, `tests/unit/circuit_var/sub/properties.rs`

- [x] **INV-CV-SUB-23: a difference of p is refused before it reaches the circuit**
  - Covered by: `tests/unit/circuit_var/sub/native.rs` `a_difference_of_p_is_refused_before_it_reaches_the_circuit`
  - Kind: error
  - Statement: the non-canonical claim 1 - 1 = p never reaches a fixture: p has no canonical `Field`, and `conversion::field` and the `[u8; 32]` proof input refuse its bytes with exactly `CircuitError.BytesTooLarge`, although p is congruent to the true difference 0.
  - Location: `src/conversion/var.rs:13-20` (`fn field`), `src/conversion/var.rs:148-158` (`impl ProofInput for [u8; 32]`)
  - Error: `CircuitErrorKind::BytesTooLarge`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/circuit_var/sub/native.rs`

### Equivalence

- [x] **INV-CV-SUB-24: the normalized rows equal circom's**
  - Covered by: `tests/unit/circuit_var/sub/external.rs` `circom_rows_normalize_to_the_sdk_rows_under_an_equal_header`
  - Kind: equivalence
  - Statement: the SDK export and `sub.circom` (`difference === left - right`, compiled with `--O0`) normalize to exactly the same multiset of constraints, the single linear constraint {1: 1, 2: -1, 3: -1}.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`), `tests/unit/circuit_var/sub/sub.circom`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/sub/external.rs`

- [x] **INV-CV-SUB-25: the SDK header equals circom's**
  - Covered by: `tests/unit/circuit_var/sub/external.rs` `circom_rows_normalize_to_the_sdk_rows_under_an_equal_header`
  - Kind: equivalence
  - Statement: the SDK export's header and label map are exactly circom's, so left, right and difference are variables 1, 2 and 3 in both.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/sub/external.rs`

- [x] **INV-CV-SUB-26: the circom witness equals the SDK witness**
  - Covered by: `tests/unit/circuit_var/sub/external.rs` `circom_witnesses_equal_the_sdk_witnesses`
  - Kind: equivalence
  - Statement: for every valid vector, the witness `ark_circom::WitnessCalculator` computes from circom's wasm is exactly the SDK's exported assignment.
  - Location: `src/prover/synthesis.rs:275-278` (`fn assignment_of`), `src/prover/snarkjs.rs:112-124` (`fn wtns`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/sub/external.rs`

- [x] **INV-CV-SUB-27: circom witness calculation fails for every invalid vector**
  - Covered by: `tests/unit/circuit_var/sub/external.rs` `circom_witness_calculation_fails_for_every_invalid_vector`
  - Kind: equivalence
  - Statement: for every invalid vector, and for the difference p passed unreduced, circom's witness calculation aborts with exactly "Assert Failed" from `difference === left - right`.
  - Location: `tests/unit/circuit_var/sub/sub.circom`, `tests/unit/harness/circom.rs` (`fn calculator`)
  - Severity: Medium
  - Suggested test: external (circom); `tests/unit/circuit_var/sub/external.rs`

- [x] **INV-CV-SUB-28: each R1CS accepts the other's witness**
  - Covered by: `tests/unit/circuit_var/sub/external.rs` `each_r1cs_accepts_the_others_witness`
  - Kind: equivalence
  - Statement: for every valid vector, the circom R1CS accepts the SDK witness and the SDK R1CS accepts the circom witness: `first_unsatisfied` is exactly `None` both ways.
  - Location: `src/prover/snarkjs.rs:12-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/sub/external.rs`

- [x] **INV-CV-SUB-29: with no gadget witness the Picus export is the snarkjs export**
  - Covered by: `tests/unit/circuit_var/sub/picus.rs` `with_no_gadget_witness_the_picus_export_is_the_snarkjs_export`
  - Kind: equivalence
  - Statement: for every operand form and for `Unasserted`, `SelfMinusSelf` and `MinusFive`, `export_picus_r1cs` is byte-identical to `export_r1cs`: none of them allocates a gadget witness.
  - Location: `src/prover/snarkjs.rs:19-110` (`fn picus_r1cs`, `fn r1cs_in_wire_order`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/sub/picus.rs`

### Interop

- [x] **INV-CV-SUB-30: snarkjs wtns check accepts the SDK pair**
  - Covered by: `tests/unit/circuit_var/sub/external.rs` `snarkjs_accepts_the_sdk_pair_and_rejects_a_tampered_witness`
  - Kind: interop
  - Statement: for every valid vector, `snarkjs wtns check` accepts the SDK R1CS with the SDK assignment.
  - Location: `src/prover/snarkjs.rs:12-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/sub/external.rs`

- [x] **INV-CV-SUB-31: snarkjs wtns check rejects a tampered witness**
  - Covered by: `tests/unit/circuit_var/sub/external.rs` `snarkjs_accepts_the_sdk_pair_and_rejects_a_tampered_witness`
  - Kind: interop
  - Statement: for every valid vector, `snarkjs wtns check` rejects the SDK R1CS with the SDK assignment whose difference is increased by exactly 1.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`), `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: Critical
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/sub/external.rs`

- [x] **INV-CV-SUB-32: snarkjs wtns check accepts both cross pairs**
  - Covered by: `tests/unit/circuit_var/sub/external.rs` `snarkjs_accepts_both_cross_pairs`
  - Kind: interop
  - Statement: for every valid vector, `snarkjs wtns check` accepts the circom R1CS with the SDK assignment, and the SDK R1CS with the circom witness.
  - Location: `src/prover/snarkjs.rs:12-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs, circom); `tests/unit/circuit_var/sub/external.rs`

- [x] **INV-CV-SUB-33: snarkjs Groth16 proves and verifies**
  - Covered by: `tests/unit/circuit_var/sub/external.rs` `snarkjs_proves_and_verifies_the_sdk_circuit`
  - Kind: interop
  - Statement: `snarkjs groth16 setup` over a throwaway ptau, `groth16 prove` with the SDK assignment of 0 - 2^253 and `groth16 verify` accept the SDK R1CS, with exactly the empty public signal list.
  - Location: `src/prover/snarkjs.rs:12-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/sub/external.rs`

## Multiplication (`*`, `*=`)

The operand forms are the nine impls `field_operators!` generates for `Mul` and
`MulAssign`: `a * b`, `a * &b`, `&a * b`, `&a * &b`, `a *= b` and `a *= &b` with a variable
operand, and `a * k`, `&a * k` and `a *= k` with a `Field` constant. The fixtures in
`tests/unit/circuit_var/mul/fixtures.rs` assert `<form> == product` with the rule "the
product is left times right": `Variables<FORM>` takes `left`, `right` and the claimed
`product` as private inputs (variables 1, 2 and 3), and the product of two variables is a
witness w, variable 4; `WithConstant<FORM>` takes `right` as a constant whose placeholder is
0. `Square` asserts `a * a`, `SumTimes` `(a + b) * c`, `TimesFive` `a * 5` and `TimesZero`
`a * 0`; `UnassertedVariables` computes the six variable forms and `UnassertedConstants`
the three constant forms with k = 7, asserting nothing. The valid vectors are 0 * 0, 0 * x,
1 * x, (p - 1) * (p - 1) = 1, x * (p - 1) = -x, 2 * (p + 1) / 2 = 1, 2^64 * 2^64 = 2^128,
2^128 * 2^128 = 2^256 mod p and x * x; the invalid ones are 2 * 3 = 5, 2 * 3 = 7, 0 * 0 = 1,
x * 0 = x, (p - 1) * (p - 1) = p - 1, 2 * (p + 1) / 2 = 0 and 2^128 * 2^128 = 0, and the
non-canonical claim 1 * 0 = p.

### Semantics

- [x] **INV-CV-MUL-01: the native product is field multiplication modulo p**
  - Covered by: `tests/unit/circuit_var/mul/native.rs` `the_native_product_is_field_multiplication_modulo_p_in_every_form`; `tests/unit/circuit_var/mul/properties.rs` `every_form_gives_the_same_native_product` (property)
  - Kind: semantics
  - Statement: for every valid vector and every operand form, the native value of the product is exactly `Field::from(left) * Field::from(right)`, the vector's product: (p - 1) * (p - 1) is exactly 1, 2 * (p + 1) / 2 is exactly 1 and 2^128 * 2^128 is exactly 2^256 mod p; for every random pair it is exactly `left * right`.
  - Location: `src/circuit/builtins/field/var.rs:207-281` (`macro field_operators`), `src/circuit/builtins/field/var.rs:57-63` (`impl Mul for Field`), `src/circuit/builtins/field/primitive.rs:64-66` (`fn times`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/mul/native.rs`, `tests/unit/circuit_var/mul/properties.rs`

- [x] **INV-CV-MUL-02: constant times constant stays a constant**
  - Covered by: `tests/unit/circuit_var/mul/native.rs` `the_native_product_is_field_multiplication_modulo_p_in_every_form`
  - Kind: semantics
  - Statement: for every valid vector and every operand form, the native product's `Debug` form is exactly `CircuitVar::constant(<product>)` and `value` returns exactly the product.
  - Location: `src/circuit/builtins/field/var.rs:86-109` (`impl Debug for CircuitVar`, `fn value`), `src/circuit/builtins/field/primitive.rs:64-66` (`fn times`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/mul/native.rs`

- [x] **INV-CV-MUL-03: multiplication never fails**
  - Covered by: `tests/unit/circuit_var/mul/native.rs` `every_valid_vector_holds_natively_in_every_form`; `tests/unit/circuit_var/mul/r1cs.rs` `the_proving_rows_name_the_rule_for_a_wrong_claim_and_no_rule_for_a_wrong_witness`
  - Kind: semantics
  - Statement: for every valid vector and every operand form, the native run returns exactly `Ok(())` and the proving synthesis completes, so `check_tampered` with the honest product returns exactly `Ok(())`.
  - Location: `src/circuit/builtins/field/var.rs:207-281` (`macro field_operators`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/mul/native.rs`, `tests/unit/circuit_var/mul/r1cs.rs`

- [x] **INV-CV-MUL-04: every operand form gives the same value**
  - Covered by: `tests/unit/circuit_var/mul/native.rs` `the_native_product_is_field_multiplication_modulo_p_in_every_form`; `tests/unit/circuit_var/mul/properties.rs` `every_form_gives_the_same_native_product` (property)
  - Kind: semantics
  - Statement: for every pair of field elements, the native values of the nine operand forms are all exactly equal, with the constant k = right in the last three.
  - Location: `src/circuit/builtins/field/var.rs:207-281` (`macro field_operators`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/mul/native.rs`, `tests/unit/circuit_var/mul/properties.rs`

- [x] **INV-CV-MUL-05: constant multiplication is a commutative ring product**
  - Covered by: `tests/unit/circuit_var/mul/native.rs` `constant_multiplication_is_a_commutative_ring_product_over_addition`
  - Kind: semantics
  - Statement: for every pair and every triple of the 18 operands of the valid vectors, as constants, the native values satisfy exactly a * b = b * a, (a * b) * c = a * (b * c) and a * (b + c) = a * b + a * c, and for every operand a * 1 is exactly a, a * `zero()` is exactly 0 and a * (p - 1) is exactly -a.
  - Location: `src/circuit/builtins/field/var.rs:207-281` (`macro field_operators`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/mul/native.rs`

### Constraint

- [x] **INV-CV-MUL-06: a product of two variables adds exactly one constraint and one variable**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `a_product_of_two_variables_adds_exactly_one_constraint_and_one_variable`
  - Kind: constraint
  - Statement: `UnassertedVariables` over left = 3 and right = 4 exports exactly 9 variables and 6 constraints, the i-th row exactly A = {1: 1}, B = {2: 1}, C = {3 + i: 1}; its assignment is exactly `[1, 3, 4]` followed by six times 12, and `check_constraints` returns exactly `Ok(6)`.
  - Location: `src/circuit/builtins/field/primitive.rs:64-66` (`fn times`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/mul/r1cs.rs`

- [x] **INV-CV-MUL-07: a product by a constant adds no constraint and no variable**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `a_product_by_a_constant_adds_no_constraint_and_no_variable`
  - Kind: constraint
  - Statement: `UnassertedConstants` over left = 3 exports exactly 2 variables and 0 constraints, its assignment is exactly `[1, 3]`, and `check_constraints` returns exactly `Ok(0)`.
  - Location: `src/circuit/builtins/field/var.rs:241-255` (`impl Mul<Field>` in `macro field_operators`), `src/circuit/builtins/field/primitive.rs:64-66` (`fn times`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/mul/r1cs.rs`

- [x] **INV-CV-MUL-08: the product row and the using row are exact**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `a_times_b_exports_exactly_the_golden_rows_and_header`
  - Kind: constraint
  - Statement: the R1CS of `(&left * &right).assert_equal(&product, rule)` is exactly two rows: row 0 A = {1: 1}, B = {2: 1}, C = {4: 1} (`left * right = w`) and row 1 A = {4: 1, 3: -1}, B = {0: 1}, C = {} (`(w - product) * 1 = 0`).
  - Location: `src/circuit/builtins/field/primitive.rs:64-66` (`fn times`), `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/mul/r1cs.rs`

- [x] **INV-CV-MUL-09: the exported header counts are exact**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `a_times_b_exports_exactly_the_golden_rows_and_header`
  - Kind: constraint
  - Statement: the mul fixture's exported header is exactly: field size 32, the BN254 scalar prime, 5 variables, 0 public outputs, 0 public inputs, 4 private inputs (the product witness counts as one), 5 labels and 2 constraints, with the identity label map `[0, 1, 2, 3, 4]`.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`), `src/prover/snarkjs.rs:49-110` (`fn r1cs_in_wire_order`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/mul/r1cs.rs`

- [x] **INV-CV-MUL-10: a * a multiplies the variable by itself**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `a_times_a_multiplies_the_variable_by_itself`
  - Kind: constraint
  - Statement: `Square` exports exactly row 0 A = {1: 1}, B = {1: 1}, C = {3: 1} and row 1 A = {3: 1, 2: -1}, B = {0: 1}, C = {}.
  - Location: `src/circuit/builtins/field/primitive.rs:64-66` (`fn times`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/mul/r1cs.rs`

- [x] **INV-CV-MUL-11: (a + b) * c inlines the sum into the product row**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `a_sum_times_c_inlines_the_sum_into_the_product_row`
  - Kind: constraint
  - Statement: `SumTimes` exports exactly row 0 A = {1: 1, 2: 1}, B = {3: 1}, C = {5: 1} and row 1 A = {5: 1, 4: -1}, B = {0: 1}, C = {}: the sum costs no row of its own.
  - Location: `src/circuit/builtins/field/primitive.rs:56-66` (`fn plus`, `fn times`), `src/prover/synthesis.rs:247-273` (`fn circuit_matrices`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/mul/r1cs.rs`

- [x] **INV-CV-MUL-12: a * Field(k) scales the variable by exactly k**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `a_times_a_constant_scales_the_variable_by_exactly_the_constant`
  - Kind: constraint
  - Statement: `TimesFive` exports exactly the one row A = {1: 5, 2: -1}, B = {0: 1}, C = {}, and `TimesZero` and `WithConstant<1>` exported from its placeholder k = 0 both export exactly A = {2: -1}, B = {0: 1}, C = {}: a drops out of the row.
  - Location: `src/circuit/builtins/field/var.rs:241-255` (`impl Mul<Field>` in `macro field_operators`), `src/circuit/builtins/field/var.rs:269-273` (`impl MulAssign<Field>`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/mul/r1cs.rs`

- [x] **INV-CV-MUL-13: every form of one operand kind exports byte-identical R1CS**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `every_form_of_one_operand_kind_exports_byte_identical_r1cs`
  - Kind: constraint
  - Statement: the six variable operand forms export byte-identical `.r1cs` files, and the three constant operand forms export byte-identical `.r1cs` files.
  - Location: `src/circuit/builtins/field/var.rs:207-281` (`macro field_operators`), `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/mul/r1cs.rs`

- [x] **INV-CV-MUL-14: the product witness follows the proof inputs**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `the_assignment_is_the_operands_the_claim_then_the_product_witness`
  - Kind: constraint
  - Statement: for every valid vector, every variable form's exported assignment is exactly `[1, left, right, product, left * right]` and every constant form's exactly `[1, left, product]`.
  - Location: `src/circuit/builtins/field/primitive.rs:64-66` (`fn times`), `src/prover/synthesis.rs:275-278` (`fn assignment_of`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/mul/r1cs.rs`

### Completeness

- [x] **INV-CV-MUL-15: every valid vector satisfies every row**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row`; `tests/unit/circuit_var/mul/r1cs.rs` `the_proving_rows_name_the_rule_for_a_wrong_claim_and_no_rule_for_a_wrong_witness`; `tests/unit/circuit_var/mul/properties.rs` `check_constraints_counts_two_constraints_for_every_valid_triple` (property)
  - Kind: completeness
  - Statement: for every valid vector, the exported assignment of every variable form satisfies both rows of its exported R1CS, and the honest assignment of every operand form satisfies every proving row; for every random pair, `check_constraints` of every variable form with the honest product returns exactly `Ok(2)`.
  - Location: `src/prover/synthesis.rs:174-202` (`fn check`), `src/prover/snarkjs.rs:112-124` (`fn wtns`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/mul/r1cs.rs`, `tests/unit/circuit_var/mul/properties.rs`

- [x] **INV-CV-MUL-16: a constant fixed in the circuit exports a row every honest witness satisfies**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `a_constant_fixed_in_the_circuit_exports_a_row_every_honest_witness_satisfies`
  - Kind: completeness
  - Statement: for the left operand a of every valid vector, the exported assignment of `TimesFive { a, product: 5a }` satisfies every row of `TimesFive`'s exported R1CS, and the same assignment with the product increased by 1 leaves exactly row 0 unsatisfied.
  - Location: `src/circuit/builtins/field/var.rs:241-255` (`impl Mul<Field>` in `macro field_operators`)
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/circuit_var/mul/r1cs.rs`

### Soundness

- [x] **INV-CV-MUL-17: every wrong claim leaves some row unsatisfied**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row`; `tests/unit/circuit_var/mul/r1cs.rs` `every_invalid_vector_breaks_a_row_whichever_product_witness_it_takes`; `tests/unit/circuit_var/mul/properties.rs` `a_wrong_product_is_refused_natively_and_in_r1cs` (property)
  - Kind: soundness
  - Statement: for every valid vector and every variable form, the honest assignment with the claim increased by 1 leaves exactly row 1 first unsatisfied; for every invalid vector, the assignment with w = left * right leaves exactly row 1 first unsatisfied and the one with w = the claim exactly row 0; for every random wrong claim and every random w, some row of the exported R1CS is unsatisfied.
  - Location: `src/circuit/builtins/field/primitive.rs:64-66` (`fn times`), `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/circuit_var/mul/r1cs.rs`, `tests/unit/circuit_var/mul/properties.rs`

- [x] **INV-CV-MUL-18: a wrong product witness breaks the product row**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row`
  - Kind: soundness
  - Statement: for every valid vector and every variable form, the honest assignment with w increased by 1 leaves exactly row 0 first unsatisfied.
  - Location: `src/circuit/builtins/field/primitive.rs:64-66` (`fn times`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/circuit_var/mul/r1cs.rs`

- [x] **INV-CV-MUL-19: the perturbation check finds exactly the operands a zero partner frees**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `no_private_variable_is_free_unless_its_partner_operand_is_zero`
  - Kind: soundness
  - Statement: for every valid vector with both operands nonzero, `check_private_variables` reports exactly 2 constraints, 4 private variables and no free or tolerated variable for every variable form, and exactly 1 constraint and 2 private variables for every constant form; for every valid vector it reports as free exactly private variable 0 (left) when right is 0 and private variable 1 (right) when left is 0, and for a constant form exactly private variable 0 when k is 0, with no tolerated variable: a zero factor leaves its partner unbound, as the relation allows.
  - Location: `src/prover/synthesis.rs:111-172` (`fn unconstrained_private_variables`), `src/testing.rs:70-99` (`fn check_private_variables`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/circuit_var/mul/r1cs.rs`

- [x] **INV-CV-MUL-20: Picus proves every product fixed by its operands**
  - Covered by: `tests/unit/circuit_var/mul/picus.rs` `picus_finds_every_form_safe_and_the_product_fixed_by_its_operands`; `tests/unit/circuit_var/mul/picus.rs` `picus_finds_the_square_and_the_product_of_a_sum_fixed`
  - Kind: soundness
  - Statement: for every operand form, Picus reports exactly Safe for the `export_picus_r1cs` file (whose output is w in the variable forms) and exactly Safe once the claimed product is moved to the outputs; the product of `Square` and of `SumTimes` moved to the outputs is exactly Safe. Every call runs under a 120 s limit.
  - Location: `src/prover/snarkjs.rs:19-45` (`fn picus_r1cs`), `tests/unit/harness/picus.rs` (`fn verdict_within`, `fn promote`, `fn picus_wire`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/circuit_var/mul/picus.rs`

- [x] **INV-CV-MUL-21: Picus reports an operand no constraint fixes as unsafe**
  - Covered by: `tests/unit/circuit_var/mul/picus.rs` `picus_finds_a_free_once_times_zero_drops_it`; `tests/unit/circuit_var/mul/picus.rs` `picus_finds_an_operand_free_when_no_product_is_asserted`
  - Kind: soundness
  - Statement: in `TimesZero`, a moved to the outputs is exactly Unsafe and the product moved to the outputs exactly Safe; `UnassertedVariables`, whose outputs are its six product witnesses, is exactly Safe while `right` moved to the outputs is exactly Unsafe, and `left` of `UnassertedConstants` moved to the outputs is exactly Unsafe.
  - Location: `src/prover/snarkjs.rs:19-45` (`fn picus_r1cs`), `tests/unit/harness/picus.rs` (`fn verdict_within`, `fn promote`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/circuit_var/mul/picus.rs`

### Shape

- [x] **INV-CV-MUL-22: setup and proving produce identical matrices**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `every_valid_vector_checks_two_constraints_in_every_variable_form`; `tests/unit/circuit_var/mul/properties.rs` `check_constraints_counts_two_constraints_for_every_valid_triple` (property)
  - Kind: shape
  - Statement: for every valid vector, every random pair and every variable operand form, `check_constraints` returns exactly `Ok(2)`.
  - Location: `src/prover/synthesis.rs:405-429` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/mul/r1cs.rs`, `tests/unit/circuit_var/mul/properties.rs`

- [x] **INV-CV-MUL-23: a constant operand is part of the circuit**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `a_constant_other_than_the_placeholders_builds_a_different_row`
  - Kind: shape
  - Statement: for every valid vector and every constant operand form, `check_constraints` returns exactly `Ok(1)` when the constant equals the placeholder's (0), and otherwise exactly `ProverError.ConstraintsDiffer` at row 0 labelled with the fixture's rule.
  - Location: `src/prover/synthesis.rs:405-429` (`fn check_constraints`), `src/prover/synthesis.rs:83-87` (`fn first_differing_row`)
  - Error: `ProverErrorKind::ConstraintsDiffer`
  - Severity: High
  - Suggested test: negative; `tests/unit/circuit_var/mul/r1cs.rs`

### Error

- [x] **INV-CV-MUL-24: a wrong product fails natively with exactly the fixture's rule**
  - Covered by: `tests/unit/circuit_var/mul/native.rs` `every_invalid_vector_breaks_exactly_the_fixture_rule_natively`; `tests/unit/circuit_var/mul/properties.rs` `natively_every_form_holds_exactly_when_the_product_is_left_times_right` (property); `tests/unit/circuit_var/mul/properties.rs` `a_wrong_product_is_refused_natively_and_in_r1cs` (property)
  - Kind: error
  - Statement: for every invalid vector, every random wrong product and every operand form, the native run returns exactly `CircuitError.RuleBroken` with the rule "the product is left times right", located in the fixture's file; with the honest product it returns exactly `Ok(())`.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`, the constant branch)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/circuit_var/mul/native.rs`, `tests/unit/circuit_var/mul/properties.rs`

- [x] **INV-CV-MUL-25: a tampered claim fails in R1CS with exactly the fixture's rule**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `the_proving_rows_name_the_rule_for_a_wrong_claim_and_no_rule_for_a_wrong_witness`; `tests/unit/circuit_var/mul/properties.rs` `a_wrong_product_is_refused_natively_and_in_r1cs` (property)
  - Kind: error
  - Statement: for every valid vector, `check_tampered` with the claimed product increased by 1 returns exactly `ProverError.ProofInputsBreakRule` at row 1 labelled with the fixture's rule for every variable form, and at row 0 for every constant form; for every random wrong claim the broken rule is exactly the fixture's in every form.
  - Location: `src/testing.rs:43-68` (`fn check_tampered`), `src/prover/synthesis.rs:174-202` (`fn check`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/circuit_var/mul/r1cs.rs`, `tests/unit/circuit_var/mul/properties.rs`

- [x] **INV-CV-MUL-26: a tampered product witness breaks an unlabelled row**
  - Covered by: `tests/unit/circuit_var/mul/r1cs.rs` `the_proving_rows_name_the_rule_for_a_wrong_claim_and_no_rule_for_a_wrong_witness`
  - Kind: error
  - Statement: for every valid vector and every variable form, `check_tampered` with w increased by 1 returns exactly `ProverError.ProofInputsBreakRule` at row 0 with no label: the product row is built outside the assertion's check, so it names no rule.
  - Location: `src/circuit/builtins/field/primitive.rs:64-66` (`fn times`), `src/circuit/labels.rs:255-270` (`fn report`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/circuit_var/mul/r1cs.rs`

- [x] **INV-CV-MUL-27: a product of p is refused before it reaches the circuit**
  - Covered by: `tests/unit/circuit_var/mul/native.rs` `a_product_of_p_is_refused_before_it_reaches_the_circuit`
  - Kind: error
  - Statement: the non-canonical claim 1 * 0 = p never reaches a fixture: p has no canonical `Field`, and `conversion::field` and the `[u8; 32]` proof input refuse its bytes with exactly `CircuitError.BytesTooLarge`, although p is congruent to the true product 0.
  - Location: `src/conversion/var.rs:13-20` (`fn field`), `src/conversion/var.rs:148-158` (`impl ProofInput for [u8; 32]`)
  - Error: `CircuitErrorKind::BytesTooLarge`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/circuit_var/mul/native.rs`

### Equivalence

- [x] **INV-CV-MUL-28: the normalized rows equal circom's over the same wires**
  - Covered by: `tests/unit/circuit_var/mul/external.rs` `circom_rows_normalize_to_the_sdk_rows_over_the_same_wires`
  - Kind: equivalence
  - Statement: the SDK export and `mul.circom` (`computed <== left * right; product === computed`) normalize to exactly the same multiset: the linear constraint {3: 1, 4: -1} and the product left * right = w over w = variable 4 in both, with equal label maps.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`), `tests/unit/circuit_var/mul/mul.circom`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/mul/external.rs`

- [x] **INV-CV-MUL-29: the headers differ only in the private input count**
  - Covered by: `tests/unit/circuit_var/mul/external.rs` `circom_rows_normalize_to_the_sdk_rows_over_the_same_wires`
  - Kind: equivalence
  - Statement: the SDK header is exactly 5 variables, 0 public inputs, 4 private inputs and 2 constraints, and circom's exactly 5 variables, 0 public inputs, 3 private inputs and 2 constraints: circom counts its intermediate signal `computed` apart from the private inputs, while the SDK counts the product witness among them.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: Medium
  - Suggested test: external (circom); `tests/unit/circuit_var/mul/external.rs`

- [x] **INV-CV-MUL-30: the circom witness equals the SDK witness**
  - Covered by: `tests/unit/circuit_var/mul/external.rs` `circom_witnesses_equal_the_sdk_witnesses`
  - Kind: equivalence
  - Statement: for every valid vector, the witness circom's wasm computes is exactly the SDK's exported assignment, product witness included.
  - Location: `src/prover/synthesis.rs:275-278` (`fn assignment_of`), `src/prover/snarkjs.rs:112-124` (`fn wtns`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/mul/external.rs`

- [x] **INV-CV-MUL-31: circom witness calculation fails for every invalid vector**
  - Covered by: `tests/unit/circuit_var/mul/external.rs` `circom_witness_calculation_fails_for_every_invalid_vector`
  - Kind: equivalence
  - Statement: for every invalid vector, and for the product p passed unreduced, circom's witness calculation aborts with exactly "Assert Failed".
  - Location: `tests/unit/circuit_var/mul/mul.circom`, `tests/unit/harness/circom.rs` (`fn calculator`)
  - Severity: Medium
  - Suggested test: external (circom); `tests/unit/circuit_var/mul/external.rs`

- [x] **INV-CV-MUL-32: each R1CS accepts the other's witness**
  - Covered by: `tests/unit/circuit_var/mul/external.rs` `each_r1cs_accepts_the_others_witness`
  - Kind: equivalence
  - Statement: for every valid vector, the circom R1CS accepts the SDK witness and the SDK R1CS accepts the circom witness: `first_unsatisfied` is exactly `None` both ways.
  - Location: `src/prover/snarkjs.rs:12-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/mul/external.rs`

- [x] **INV-CV-MUL-33: the Picus export makes the product witness its only output**
  - Covered by: `tests/unit/circuit_var/mul/picus.rs` `the_picus_export_makes_the_product_witness_its_only_output`
  - Kind: equivalence
  - Statement: `Variables<3>`'s `export_picus_r1cs` header is exactly 5 variables, 1 public output, 0 public inputs, 3 private inputs and 2 constraints, with the wire labels exactly `[0, 4, 1, 2, 3]`; every variable form's Picus export is byte-identical to it, and every constant form's and `UnassertedConstants`' Picus export is byte-identical to its `export_r1cs`.
  - Location: `src/prover/snarkjs.rs:19-45` (`fn picus_r1cs`)
  - Severity: High
  - Suggested test: external (Picus); `tests/unit/circuit_var/mul/picus.rs`

### Interop

- [x] **INV-CV-MUL-34: snarkjs wtns check accepts the SDK pair**
  - Covered by: `tests/unit/circuit_var/mul/external.rs` `snarkjs_accepts_the_sdk_pair_and_rejects_each_tampered_wire`
  - Kind: interop
  - Statement: for every valid vector, `snarkjs wtns check` accepts the SDK R1CS with the SDK assignment.
  - Location: `src/prover/snarkjs.rs:12-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/mul/external.rs`

- [x] **INV-CV-MUL-35: snarkjs wtns check rejects a tampered claim or product witness**
  - Covered by: `tests/unit/circuit_var/mul/external.rs` `snarkjs_accepts_the_sdk_pair_and_rejects_each_tampered_wire`
  - Kind: interop
  - Statement: for every valid vector, `snarkjs wtns check` rejects the SDK R1CS with the SDK assignment whose claimed product is increased by exactly 1, and with the one whose w is increased by exactly 1.
  - Location: `src/circuit/builtins/field/primitive.rs:64-66` (`fn times`), `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: Critical
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/mul/external.rs`

- [x] **INV-CV-MUL-36: snarkjs wtns check accepts both cross pairs**
  - Covered by: `tests/unit/circuit_var/mul/external.rs` `snarkjs_accepts_both_cross_pairs`
  - Kind: interop
  - Statement: for every valid vector, `snarkjs wtns check` accepts the circom R1CS with the SDK assignment, and the SDK R1CS with the circom witness.
  - Location: `src/prover/snarkjs.rs:12-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs, circom); `tests/unit/circuit_var/mul/external.rs`

- [x] **INV-CV-MUL-37: snarkjs Groth16 proves and verifies**
  - Covered by: `tests/unit/circuit_var/mul/external.rs` `snarkjs_proves_and_verifies_the_sdk_circuit`
  - Kind: interop
  - Statement: `snarkjs groth16 setup` over a throwaway ptau, `groth16 prove` with the SDK assignment of 2^128 * 2^128 and `groth16 verify` accept the SDK R1CS, with exactly the empty public signal list.
  - Location: `src/prover/snarkjs.rs:12-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/mul/external.rs`

## Negation (unary `-`)

The operand forms are `impl Neg for CircuitVar` (`-a`) and `impl Neg for &CircuitVar`
(`-&a`), both `zero().minus(..)`. The fixtures in `tests/unit/circuit_var/neg/fixtures.rs`
assert `<form> == negation` with the rule "the negation is minus the value":
`Negated<FORM>` takes `value` and `negation` as private inputs (variables 1 and 2).
`DoubleNegation` asserts `-(-a)`, `PlusNegation` asserts `a + -a`, and `Unasserted`
computes both forms and asserts nothing. The valid vectors are -0 = 0, -1 = p - 1,
-(p - 1) = 1, -((p - 1) / 2) = (p + 1) / 2, -2^64 = p - 2^64, -2^253 = p - 2^253 and
-x = p - x; the invalid ones are -1 = 1, -0 = p - 1, -x = x, -((p - 1) / 2) = (p - 1) / 2,
-2^64 = 2^64 and -(p - 1) = 0, and the non-canonical claim -0 = p.

### Semantics

- [x] **INV-CV-NEG-01: the native negation is the additive inverse modulo p**
  - Covered by: `tests/unit/circuit_var/neg/native.rs` `the_native_negation_is_the_additive_inverse_modulo_p_in_every_form`; `tests/unit/circuit_var/neg/properties.rs` `every_form_gives_the_same_native_negation` (property)
  - Kind: semantics
  - Statement: for every valid vector and both forms, the native value of the negation is exactly `-Field::from(value)`, the vector's negation: -0 is exactly 0 and -1 is exactly p - 1; for every random value it is exactly `-value`.
  - Location: `src/circuit/builtins/field/var.rs:283-297` (`impl Neg for &CircuitVar`, `impl Neg for CircuitVar`), `src/circuit/builtins/field/var.rs:65-71` (`impl Neg for Field`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/neg/native.rs`, `tests/unit/circuit_var/neg/properties.rs`

- [x] **INV-CV-NEG-02: the negation of a constant stays a constant**
  - Covered by: `tests/unit/circuit_var/neg/native.rs` `the_native_negation_is_the_additive_inverse_modulo_p_in_every_form`
  - Kind: semantics
  - Statement: for every valid vector and both forms, the native negation's `Debug` form is exactly `CircuitVar::constant(<negation>)` and `value` returns exactly the negation.
  - Location: `src/circuit/builtins/field/var.rs:86-109` (`impl Debug for CircuitVar`, `fn value`), `src/circuit/builtins/field/var.rs:283-297` (`impl Neg`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/neg/native.rs`

- [x] **INV-CV-NEG-03: negation never fails**
  - Covered by: `tests/unit/circuit_var/neg/native.rs` `every_valid_vector_holds_natively_in_every_form`; `tests/unit/circuit_var/neg/r1cs.rs` `the_proving_rows_accept_the_honest_negation_and_name_the_rule_for_another`
  - Kind: semantics
  - Statement: for every valid vector and both forms, the native run returns exactly `Ok(())` and `check_tampered` with the honest negation returns exactly `Ok(())`.
  - Location: `src/circuit/builtins/field/var.rs:283-297` (`impl Neg`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/neg/native.rs`, `tests/unit/circuit_var/neg/r1cs.rs`

- [x] **INV-CV-NEG-04: both forms give the same value**
  - Covered by: `tests/unit/circuit_var/neg/native.rs` `the_native_negation_is_the_additive_inverse_modulo_p_in_every_form`; `tests/unit/circuit_var/neg/properties.rs` `every_form_gives_the_same_native_negation` (property)
  - Kind: semantics
  - Statement: for every field element, the native values of `-a` and `-&a` are exactly equal.
  - Location: `src/circuit/builtins/field/var.rs:283-297` (`impl Neg`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/neg/native.rs`, `tests/unit/circuit_var/neg/properties.rs`

- [x] **INV-CV-NEG-05: constant negation is an involution that cancels**
  - Covered by: `tests/unit/circuit_var/neg/native.rs` `constant_negation_is_an_involution_that_cancels_and_subtracts_from_zero`
  - Kind: semantics
  - Statement: for the value a of every valid vector, as a constant, the native values satisfy exactly -(-a) = a, a + -a = 0 and -a = `zero()` - a.
  - Location: `src/circuit/builtins/field/var.rs:283-297` (`impl Neg`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/neg/native.rs`

### Constraint

- [x] **INV-CV-NEG-06: negating adds no constraint**
  - Covered by: `tests/unit/circuit_var/neg/r1cs.rs` `negating_allocates_no_variable_and_adds_no_constraint`
  - Kind: constraint
  - Statement: `Unasserted`, which computes both forms and asserts nothing, exports exactly 0 constraints, and `check_constraints` returns exactly `Ok(0)`.
  - Location: `src/circuit/builtins/field/var.rs:283-297` (`impl Neg`), `src/circuit/builtins/field/primitive.rs:60-62` (`fn minus`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/neg/r1cs.rs`

- [x] **INV-CV-NEG-07: negating allocates no variable**
  - Covered by: `tests/unit/circuit_var/neg/r1cs.rs` `negating_allocates_no_variable_and_adds_no_constraint`; `tests/unit/circuit_var/neg/r1cs.rs` `the_assignment_is_the_constant_one_then_the_inputs`
  - Kind: constraint
  - Statement: `Unasserted` exports exactly 2 variables with the assignment exactly `[1, 3]`, and for every valid vector both forms' exported assignment is exactly `[1, value, negation]`.
  - Location: `src/circuit/builtins/field/var.rs:283-297` (`impl Neg`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/neg/r1cs.rs`

- [x] **INV-CV-NEG-08: the using row has coefficient exactly -1 for the value**
  - Covered by: `tests/unit/circuit_var/neg/r1cs.rs` `minus_a_exports_exactly_the_golden_row_and_header`
  - Kind: constraint
  - Statement: the R1CS of `(-&value).assert_equal(&negation, rule)` is exactly one row A = {1: -1, 2: -1}, B = {0: 1}, C = {}.
  - Location: `src/circuit/builtins/field/var.rs:283-289` (`impl Neg for &CircuitVar`), `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/neg/r1cs.rs`

- [x] **INV-CV-NEG-09: the exported header counts are exact**
  - Covered by: `tests/unit/circuit_var/neg/r1cs.rs` `minus_a_exports_exactly_the_golden_row_and_header`
  - Kind: constraint
  - Statement: the neg fixture's exported header is exactly: field size 32, the BN254 scalar prime, 3 variables, 0 public outputs, 0 public inputs, 2 private inputs, 3 labels and 1 constraint, with the identity label map `[0, 1, 2]`.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/neg/r1cs.rs`

- [x] **INV-CV-NEG-10: a double negation inlines to exactly the value**
  - Covered by: `tests/unit/circuit_var/neg/r1cs.rs` `a_double_negation_inlines_to_exactly_the_value`
  - Kind: constraint
  - Statement: `DoubleNegation` exports exactly A = {1: 1, 2: -1}, B = {0: 1}, C = {}.
  - Location: `src/circuit/builtins/field/var.rs:283-297` (`impl Neg`), `src/prover/synthesis.rs:247-273` (`fn circuit_matrices`)
  - Severity: Medium
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/neg/r1cs.rs`

- [x] **INV-CV-NEG-11: a + -a cancels to no entry for a**
  - Covered by: `tests/unit/circuit_var/neg/r1cs.rs` `a_plus_minus_a_cancels_to_no_entry_for_a`
  - Kind: constraint
  - Statement: `PlusNegation` exports exactly A = {2: -1}, B = {0: 1}, C = {}, so the row reads `negation = 0`.
  - Location: `src/circuit/builtins/field/var.rs:283-297` (`impl Neg`), `src/prover/synthesis.rs:247-273` (`fn circuit_matrices`)
  - Severity: Medium
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/neg/r1cs.rs`

- [x] **INV-CV-NEG-12: both forms export byte-identical R1CS**
  - Covered by: `tests/unit/circuit_var/neg/r1cs.rs` `both_forms_export_byte_identical_r1cs`
  - Kind: constraint
  - Statement: `Negated<0>` (`-a`) and `Negated<1>` (`-&a`) export byte-identical `.r1cs` files.
  - Location: `src/circuit/builtins/field/var.rs:283-297` (`impl Neg`), `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/neg/r1cs.rs`

### Completeness

- [x] **INV-CV-NEG-13: every valid vector satisfies every row**
  - Covered by: `tests/unit/circuit_var/neg/r1cs.rs` `every_valid_vector_satisfies_the_row_and_a_tampered_negation_breaks_it`; `tests/unit/circuit_var/neg/r1cs.rs` `the_proving_rows_accept_the_honest_negation_and_name_the_rule_for_another`; `tests/unit/circuit_var/neg/properties.rs` `a_wrong_negation_is_refused_natively_and_in_r1cs_and_the_honest_one_checks` (property)
  - Kind: completeness
  - Statement: for every valid vector and both forms, the exported assignment satisfies the exported row and the honest assignment satisfies every proving row; for every random value, `check_constraints` of both forms with the honest negation returns exactly `Ok(1)`.
  - Location: `src/prover/synthesis.rs:174-202` (`fn check`), `src/prover/snarkjs.rs:112-124` (`fn wtns`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/neg/r1cs.rs`, `tests/unit/circuit_var/neg/properties.rs`

### Soundness

- [x] **INV-CV-NEG-14: every wrong negation leaves row 0 unsatisfied**
  - Covered by: `tests/unit/circuit_var/neg/r1cs.rs` `every_valid_vector_satisfies_the_row_and_a_tampered_negation_breaks_it`; `tests/unit/circuit_var/neg/r1cs.rs` `every_invalid_vector_breaks_the_row`; `tests/unit/circuit_var/neg/properties.rs` `a_wrong_negation_is_refused_natively_and_in_r1cs_and_the_honest_one_checks` (property)
  - Kind: soundness
  - Statement: for every valid vector and both forms, the honest assignment with the negation increased by 1 leaves exactly row 0 unsatisfied; for every invalid vector and every random wrong negation, `[1, value, negation]` leaves exactly row 0 of the exported R1CS unsatisfied.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`), `src/circuit/builtins/field/primitive.rs:107-109` (`fn enforce_equal`)
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/circuit_var/neg/r1cs.rs`, `tests/unit/circuit_var/neg/properties.rs`

- [x] **INV-CV-NEG-15: no private variable of the fixture is free**
  - Covered by: `tests/unit/circuit_var/neg/r1cs.rs` `no_private_variable_is_free_in_any_form`
  - Kind: soundness
  - Statement: for every valid vector and both forms, `check_private_variables` reports exactly 1 constraint, 2 private variables, no free variable and no tolerated variable.
  - Location: `src/prover/synthesis.rs:111-172` (`fn unconstrained_private_variables`), `src/testing.rs:70-99` (`fn check_private_variables`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/circuit_var/neg/r1cs.rs`

- [x] **INV-CV-NEG-16: Picus proves the negation and the value each fixed by the other**
  - Covered by: `tests/unit/circuit_var/neg/picus.rs` `picus_finds_the_negation_and_the_value_each_fixed_by_the_other`
  - Kind: soundness
  - Statement: for both forms and for `DoubleNegation`, Picus reports exactly Safe for the `export_picus_r1cs` file, exactly Safe with the negation moved to the outputs and exactly Safe with the value moved to the outputs, each call under a 120 s limit.
  - Location: `src/prover/snarkjs.rs:19-45` (`fn picus_r1cs`), `tests/unit/harness/picus.rs` (`fn verdict_within`, `fn promote`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/circuit_var/neg/picus.rs`

- [x] **INV-CV-NEG-17: Picus reports the value free once a + -a cancels**
  - Covered by: `tests/unit/circuit_var/neg/picus.rs` `picus_finds_the_value_free_once_a_plus_minus_a_cancels`
  - Kind: soundness
  - Statement: in `PlusNegation`, the value moved to the outputs is exactly Unsafe and the negation moved to the outputs exactly Safe.
  - Location: `src/prover/snarkjs.rs:19-45` (`fn picus_r1cs`), `tests/unit/harness/picus.rs` (`fn verdict_within`, `fn promote`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/circuit_var/neg/picus.rs`

### Shape

- [x] **INV-CV-NEG-18: setup and proving produce identical matrices**
  - Covered by: `tests/unit/circuit_var/neg/r1cs.rs` `every_valid_vector_checks_one_constraint_in_every_form`; `tests/unit/circuit_var/neg/properties.rs` `a_wrong_negation_is_refused_natively_and_in_r1cs_and_the_honest_one_checks` (property)
  - Kind: shape
  - Statement: for every valid vector, every random value and both forms, `check_constraints` returns exactly `Ok(1)`.
  - Location: `src/prover/synthesis.rs:405-429` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/neg/r1cs.rs`, `tests/unit/circuit_var/neg/properties.rs`

### Error

- [x] **INV-CV-NEG-19: a wrong negation fails natively with exactly the fixture's rule**
  - Covered by: `tests/unit/circuit_var/neg/native.rs` `every_invalid_vector_breaks_exactly_the_fixture_rule_natively`; `tests/unit/circuit_var/neg/properties.rs` `natively_every_form_holds_exactly_when_the_claim_is_minus_the_value` (property); `tests/unit/circuit_var/neg/properties.rs` `a_wrong_negation_is_refused_natively_and_in_r1cs_and_the_honest_one_checks` (property)
  - Kind: error
  - Statement: for every invalid vector, every random wrong negation and both forms, the native run returns exactly `CircuitError.RuleBroken` with the rule "the negation is minus the value", located in the fixture's file; with the honest negation it returns exactly `Ok(())`.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`, the constant branch)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/circuit_var/neg/native.rs`, `tests/unit/circuit_var/neg/properties.rs`

- [x] **INV-CV-NEG-20: a tampered negation fails in R1CS with exactly the fixture's rule**
  - Covered by: `tests/unit/circuit_var/neg/r1cs.rs` `the_proving_rows_accept_the_honest_negation_and_name_the_rule_for_another`; `tests/unit/circuit_var/neg/properties.rs` `a_wrong_negation_is_refused_natively_and_in_r1cs_and_the_honest_one_checks` (property)
  - Kind: error
  - Statement: for every valid vector and both forms, `check_tampered` with the negation increased by 1 returns exactly `ProverError.ProofInputsBreakRule` at row 0 labelled with the fixture's rule; for every random wrong negation the broken rule is exactly the fixture's.
  - Location: `src/testing.rs:43-68` (`fn check_tampered`), `src/prover/synthesis.rs:174-202` (`fn check`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/circuit_var/neg/r1cs.rs`, `tests/unit/circuit_var/neg/properties.rs`

- [x] **INV-CV-NEG-21: a negation of p is refused before it reaches the circuit**
  - Covered by: `tests/unit/circuit_var/neg/native.rs` `a_negation_of_p_is_refused_before_it_reaches_the_circuit`
  - Kind: error
  - Statement: the non-canonical claim -0 = p never reaches a fixture: `conversion::field` and the `[u8; 32]` proof input refuse its bytes with exactly `CircuitError.BytesTooLarge`, although p is congruent to the true negation 0.
  - Location: `src/conversion/var.rs:13-20` (`fn field`), `src/conversion/var.rs:148-158` (`impl ProofInput for [u8; 32]`)
  - Error: `CircuitErrorKind::BytesTooLarge`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/circuit_var/neg/native.rs`

### Equivalence

- [x] **INV-CV-NEG-22: the normalized rows equal circom's**
  - Covered by: `tests/unit/circuit_var/neg/external.rs` `circom_rows_normalize_to_the_sdk_rows_under_an_equal_header`
  - Kind: equivalence
  - Statement: the SDK export and `neg.circom` (`negation === -value`) normalize to exactly the same multiset, the single linear constraint {1: 1, 2: 1}.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`), `tests/unit/circuit_var/neg/neg.circom`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/neg/external.rs`

- [x] **INV-CV-NEG-23: the SDK header equals circom's**
  - Covered by: `tests/unit/circuit_var/neg/external.rs` `circom_rows_normalize_to_the_sdk_rows_under_an_equal_header`
  - Kind: equivalence
  - Statement: the SDK export's header and label map are exactly circom's, so value and negation are variables 1 and 2 in both.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/neg/external.rs`

- [x] **INV-CV-NEG-24: the circom witness equals the SDK witness**
  - Covered by: `tests/unit/circuit_var/neg/external.rs` `circom_witnesses_equal_the_sdk_witnesses`
  - Kind: equivalence
  - Statement: for every valid vector, the witness circom's wasm computes is exactly the SDK's exported assignment.
  - Location: `src/prover/synthesis.rs:275-278` (`fn assignment_of`), `src/prover/snarkjs.rs:112-124` (`fn wtns`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/neg/external.rs`

- [x] **INV-CV-NEG-25: circom witness calculation fails for every invalid vector**
  - Covered by: `tests/unit/circuit_var/neg/external.rs` `circom_witness_calculation_fails_for_every_invalid_vector`
  - Kind: equivalence
  - Statement: for every invalid vector, and for the negation p passed unreduced, circom's witness calculation aborts with exactly "Assert Failed".
  - Location: `tests/unit/circuit_var/neg/neg.circom`, `tests/unit/harness/circom.rs` (`fn calculator`)
  - Severity: Medium
  - Suggested test: external (circom); `tests/unit/circuit_var/neg/external.rs`

- [x] **INV-CV-NEG-26: each R1CS accepts the other's witness**
  - Covered by: `tests/unit/circuit_var/neg/external.rs` `each_r1cs_accepts_the_others_witness`
  - Kind: equivalence
  - Statement: for every valid vector, the circom R1CS accepts the SDK witness and the SDK R1CS accepts the circom witness.
  - Location: `src/prover/snarkjs.rs:12-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/neg/external.rs`

- [x] **INV-CV-NEG-27: with no gadget witness the Picus export is the snarkjs export**
  - Covered by: `tests/unit/circuit_var/neg/picus.rs` `with_no_gadget_witness_the_picus_export_is_the_snarkjs_export`
  - Kind: equivalence
  - Statement: for both forms and for `Unasserted`, `DoubleNegation` and `PlusNegation`, `export_picus_r1cs` is byte-identical to `export_r1cs`.
  - Location: `src/prover/snarkjs.rs:19-110` (`fn picus_r1cs`, `fn r1cs_in_wire_order`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/neg/picus.rs`

### Interop

- [x] **INV-CV-NEG-28: snarkjs wtns check accepts the SDK pair**
  - Covered by: `tests/unit/circuit_var/neg/external.rs` `snarkjs_accepts_the_sdk_pair_and_rejects_a_tampered_witness`
  - Kind: interop
  - Statement: for every valid vector, `snarkjs wtns check` accepts the SDK R1CS with the SDK assignment.
  - Location: `src/prover/snarkjs.rs:12-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/neg/external.rs`

- [x] **INV-CV-NEG-29: snarkjs wtns check rejects a tampered witness**
  - Covered by: `tests/unit/circuit_var/neg/external.rs` `snarkjs_accepts_the_sdk_pair_and_rejects_a_tampered_witness`
  - Kind: interop
  - Statement: for every valid vector, `snarkjs wtns check` rejects the SDK R1CS with the SDK assignment whose negation is increased by exactly 1.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`), `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: Critical
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/neg/external.rs`

- [x] **INV-CV-NEG-30: snarkjs wtns check accepts both cross pairs**
  - Covered by: `tests/unit/circuit_var/neg/external.rs` `snarkjs_accepts_both_cross_pairs`
  - Kind: interop
  - Statement: for every valid vector, `snarkjs wtns check` accepts the circom R1CS with the SDK assignment, and the SDK R1CS with the circom witness.
  - Location: `src/prover/snarkjs.rs:12-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs, circom); `tests/unit/circuit_var/neg/external.rs`

- [x] **INV-CV-NEG-31: snarkjs Groth16 proves and verifies**
  - Covered by: `tests/unit/circuit_var/neg/external.rs` `snarkjs_proves_and_verifies_the_sdk_circuit`
  - Kind: interop
  - Statement: `snarkjs groth16 setup` over a throwaway ptau, `groth16 prove` with the SDK assignment of -x and `groth16 verify` accept the SDK R1CS, with exactly the empty public signal list.
  - Location: `src/prover/snarkjs.rs:12-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/neg/external.rs`

## Inverse (`inverse`)

`CircuitVar::inverse` returns the constant inverse of a constant, `DivisionByZero` for the
constant 0 or for a variable whose assigned value is 0, and otherwise arkworks'
`FpVar::inverse`: a witness w with the row `x * w = 1`. The fixtures in
`tests/unit/circuit_var/inverse/fixtures.rs` assert `x.inverse()? == inverse` with the rule
"the claim is the inverse of x": `Inverse` takes `x` and the claimed `inverse` as private
inputs (variables 1 and 2), and w is variable 3. `Unasserted` only inverts x,
`InverseOfFour` asserts `constant(4).inverse()? == inverse` and `InverseOfZero`
`constant(0).inverse()? == inverse`. The valid vectors are 1 / 1 = 1, 1 / (p - 1) = p - 1,
1 / 2 = (p + 1) / 2, 1 / ((p + 1) / 2) = 2, 1 / 3, 1 / 2^64 and 1 / x; the invalid ones
are 1 / 2 = 2, 1 / 2 = (p - 1) / 2, 1 / 1 = 0, 1 / x = x and 1 / (p - 1) = 1; the zero
vectors claim 1 / 0 = 0, 1 and p - 1. The circom reference `inverse.circom` computes
`inv <-- 1 / x; inv * x === 1; inverse === inv`.

### Semantics

- [x] **INV-CV-INV-01: the native inverse of a nonzero constant is its field inverse**
  - Covered by: `tests/unit/circuit_var/inverse/native.rs` `the_native_inverse_of_a_constant_is_its_field_inverse_and_stays_a_constant`
  - Kind: semantics
  - Statement: for the x of every valid vector, `constant(x).inverse()` is exactly the vector's inverse, x times it is exactly 1, and its `Debug` form is exactly `CircuitVar::constant(<inverse>)`.
  - Location: `src/circuit/builtins/field/arithmetic.rs:7-19` (`fn inverse`, the constant branch)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/inverse/native.rs`

- [x] **INV-CV-INV-02: inverting a nonzero x never fails**
  - Covered by: `tests/unit/circuit_var/inverse/native.rs` `every_valid_vector_holds_natively`; `tests/unit/circuit_var/inverse/r1cs.rs` `a_zero_x_is_refused_with_division_by_zero_in_the_r1cs_synthesis_and_by_the_prover`
  - Kind: semantics
  - Statement: for every valid vector, the native run of `Inverse` returns exactly `Ok(())`, and so does the proving synthesis alone on a fresh constraint system.
  - Location: `src/circuit/builtins/field/arithmetic.rs:7-19` (`fn inverse`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/inverse/native.rs`, `tests/unit/circuit_var/inverse/r1cs.rs`

- [x] **INV-CV-INV-03: constant inversion is an involution that distributes over products**
  - Covered by: `tests/unit/circuit_var/inverse/native.rs` `constant_inversion_is_an_involution_that_distributes_over_products`
  - Kind: semantics
  - Statement: for every x and every pair a and b of the valid vectors' x, as constants, the native inverse of the inverse of a is exactly a, and the inverse of a * b is exactly the inverse of a times the inverse of b.
  - Location: `src/circuit/builtins/field/arithmetic.rs:7-19` (`fn inverse`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/inverse/native.rs`

### Constraint

- [x] **INV-CV-INV-04: the inverse row and the using row are exact**
  - Covered by: `tests/unit/circuit_var/inverse/r1cs.rs` `inverse_exports_exactly_the_golden_rows_and_header`
  - Kind: constraint
  - Statement: `Inverse` exports exactly two rows: row 0 A = {1: 1}, B = {3: 1}, C = {0: 1} (`x * w = 1`) and row 1 A = {3: 1, 2: -1}, B = {0: 1}, C = {} (`(w - inverse) * 1 = 0`).
  - Location: `src/circuit/builtins/field/primitive.rs:80-82` (`fn inverted`), `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/inverse/r1cs.rs`

- [x] **INV-CV-INV-05: the exported header counts are exact**
  - Covered by: `tests/unit/circuit_var/inverse/r1cs.rs` `inverse_exports_exactly_the_golden_rows_and_header`
  - Kind: constraint
  - Statement: `Inverse`'s exported header is exactly 4 variables, 0 public outputs, 0 public inputs, 3 private inputs and 2 constraints over the BN254 scalar prime, with the identity label map `[0, 1, 2, 3]`.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/inverse/r1cs.rs`

- [x] **INV-CV-INV-06: inverting a variable adds exactly one constraint and one witness**
  - Covered by: `tests/unit/circuit_var/inverse/r1cs.rs` `inverting_a_variable_adds_exactly_one_constraint_and_one_witness`
  - Kind: constraint
  - Statement: `Unasserted` over x = 2 exports exactly 3 variables and the one row A = {1: 1}, B = {2: 1}, C = {0: 1}; its assignment is exactly `[1, 2, (p + 1) / 2]` and `check_constraints` returns exactly `Ok(1)`.
  - Location: `src/circuit/builtins/field/primitive.rs:80-82` (`fn inverted`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/inverse/r1cs.rs`

- [x] **INV-CV-INV-07: inverting a constant allocates nothing and puts the inverse on variable 0**
  - Covered by: `tests/unit/circuit_var/inverse/r1cs.rs` `inverting_a_constant_puts_the_inverse_on_variable_zero_and_allocates_nothing`
  - Kind: constraint
  - Statement: `InverseOfFour` exports exactly 2 variables and the one row A = {0: 1/4, 1: -1}, B = {0: 1}, C = {}, and `check_constraints` with the claim 1/4 returns exactly `Ok(1)`.
  - Location: `src/circuit/builtins/field/arithmetic.rs:7-19` (`fn inverse`, the constant branch)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/inverse/r1cs.rs`

- [x] **INV-CV-INV-08: the inverse witness follows the proof inputs**
  - Covered by: `tests/unit/circuit_var/inverse/r1cs.rs` `the_assignment_is_x_the_claim_then_the_inverse_witness`
  - Kind: constraint
  - Statement: for every valid vector, `Inverse`'s exported assignment is exactly `[1, x, inverse, inverse]`: w holds exactly 1 / x.
  - Location: `src/circuit/builtins/field/primitive.rs:80-82` (`fn inverted`), `src/prover/synthesis.rs:275-278` (`fn assignment_of`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/inverse/r1cs.rs`

- [x] **INV-CV-INV-09: the inverse witness and its row carry no label**
  - Covered by: `tests/unit/circuit_var/inverse/r1cs.rs` `the_inverse_witness_and_its_row_carry_no_label`
  - Kind: constraint
  - Statement: `constraint_labels` of `Inverse` over x = 2 is exactly three labels: an `Allocation(Constrained)` "a field proof input" for private variable 0, one for private variable 1, and the `Check` labelled with the fixture's rule, in the fixture's file, over exactly row 1. Private variable 2 (w) has no allocation label, so it has no `Multiplier` role: unlike the inverse hint of an equality test, it is a gadget witness, which the Picus export makes an output (INV-CV-INV-27).
  - Location: `src/circuit/builtins/field/primitive.rs:80-82` (`fn inverted`), `src/circuit/labels.rs:75-99` (`fn check`, `fn allocate`), `src/testing.rs:32-41` (`fn constraint_labels`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/inverse/r1cs.rs`

### Completeness

- [x] **INV-CV-INV-10: every valid vector satisfies every row**
  - Covered by: `tests/unit/circuit_var/inverse/r1cs.rs` `every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row`; `tests/unit/circuit_var/inverse/r1cs.rs` `the_proving_rows_name_the_rule_for_a_wrong_claim_and_no_rule_for_a_wrong_witness`; `tests/unit/circuit_var/inverse/properties.rs` `every_honest_inverse_checks_two_constraints_and_a_wrong_claim_names_the_rule` (property)
  - Kind: completeness
  - Statement: for every valid vector, the exported assignment satisfies both exported rows and the honest assignment satisfies every proving row; for every random nonzero x, `check_constraints` with the honest claim returns exactly `Ok(2)`.
  - Location: `src/prover/synthesis.rs:174-202` (`fn check`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/inverse/r1cs.rs`, `tests/unit/circuit_var/inverse/properties.rs`

### Soundness

- [x] **INV-CV-INV-11: every wrong claim leaves some row unsatisfied**
  - Covered by: `tests/unit/circuit_var/inverse/r1cs.rs` `every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row`; `tests/unit/circuit_var/inverse/r1cs.rs` `every_wrong_inverse_breaks_a_row_whichever_witness_it_takes`
  - Kind: soundness
  - Statement: for every valid vector, the honest assignment with the claim increased by 1 leaves exactly row 1 first unsatisfied; for every invalid vector, the assignment with w = 1 / x leaves exactly row 1 first unsatisfied and the one with w = the claim exactly row 0.
  - Location: `src/circuit/builtins/field/primitive.rs:80-82` (`fn inverted`), `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/circuit_var/inverse/r1cs.rs`

- [x] **INV-CV-INV-12: a wrong inverse witness breaks the inverse row**
  - Covered by: `tests/unit/circuit_var/inverse/r1cs.rs` `every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row`; `tests/unit/circuit_var/inverse/properties.rs` `a_wrong_inverse_witness_breaks_the_inverse_row` (property)
  - Kind: soundness
  - Statement: for every valid vector, the honest assignment with w increased by 1 leaves exactly row 0 first unsatisfied; for every random nonzero x and every random w other than 1 / x, `[1, x, w, w]` leaves exactly row 0 first unsatisfied.
  - Location: `src/circuit/builtins/field/primitive.rs:80-82` (`fn inverted`)
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/circuit_var/inverse/r1cs.rs`, `tests/unit/circuit_var/inverse/properties.rs`

- [x] **INV-CV-INV-13: a zero x is unprovable**
  - Covered by: `tests/unit/circuit_var/inverse/r1cs.rs` `a_zero_x_breaks_the_inverse_row_whatever_the_witness`; `tests/unit/circuit_var/inverse/r1cs.rs` `every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row`; `tests/unit/circuit_var/inverse/properties.rs` `a_zero_x_is_refused_natively_and_by_every_witness` (property)
  - Kind: soundness
  - Statement: for every zero vector and every w in {0, 1, 2, p - 1}, for every random claim and random w, and for every valid vector's honest assignment with x overwritten by 0, the assignment with x = 0 leaves exactly row 0 first unsatisfied: no witness satisfies `0 * w = 1`.
  - Location: `src/circuit/builtins/field/primitive.rs:80-82` (`fn inverted`)
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/circuit_var/inverse/r1cs.rs`, `tests/unit/circuit_var/inverse/properties.rs`

- [x] **INV-CV-INV-14: no private variable of the fixture is free**
  - Covered by: `tests/unit/circuit_var/inverse/r1cs.rs` `no_private_variable_is_free_for_any_valid_vector`
  - Kind: soundness
  - Statement: for every valid vector, `check_private_variables` of `Inverse` reports exactly 2 constraints, 3 private variables, no free variable and no tolerated variable.
  - Location: `src/prover/synthesis.rs:111-172` (`fn unconstrained_private_variables`), `src/testing.rs:70-99` (`fn check_private_variables`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/circuit_var/inverse/r1cs.rs`

- [x] **INV-CV-INV-15: Picus proves the SDK and the circom inverse deterministic**
  - Covered by: `tests/unit/circuit_var/inverse/picus.rs` `picus_finds_the_sdk_and_the_circom_inverse_deterministic`
  - Kind: soundness
  - Statement: Picus reports exactly Safe for `Inverse`'s `export_picus_r1cs` with the claim moved to the outputs next to w, and exactly Safe for `inverse.circom` with its `inverse` input moved to the outputs, each under a 120 s limit.
  - Location: `src/prover/snarkjs.rs:19-45` (`fn picus_r1cs`), `tests/unit/harness/equivalence.rs` (`fn picus_verdicts`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/circuit_var/inverse/picus.rs`

- [x] **INV-CV-INV-16: Picus proves w fixed by x and x fixed by the claim**
  - Covered by: `tests/unit/circuit_var/inverse/picus.rs` `picus_finds_the_inverse_witness_fixed_by_x_and_x_fixed_by_the_claim`
  - Kind: soundness
  - Statement: Picus reports exactly Safe for `Unasserted`'s and `Inverse`'s Picus exports, whose only output is w, and exactly Safe for `Inverse` with x also moved to the outputs.
  - Location: `src/prover/snarkjs.rs:19-45` (`fn picus_r1cs`), `tests/unit/harness/picus.rs` (`fn verdict_within`, `fn promote`, `fn picus_wire`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/circuit_var/inverse/picus.rs`

### Shape

- [x] **INV-CV-INV-17: setup inverts the placeholder's zero without refusing it**
  - Covered by: `tests/unit/circuit_var/inverse/r1cs.rs` `every_valid_vector_checks_two_constraints_although_the_placeholder_x_is_zero`
  - Kind: shape
  - Statement: for every valid vector, `check_constraints` of `Inverse` returns exactly `Ok(2)`, although the placeholder's x is 0: the setup synthesis has no assigned value, so it skips the zero check and builds the same rows as the proof.
  - Location: `src/circuit/builtins/field/arithmetic.rs:15-18` (`fn inverse`, the assigned-value check), `src/prover/synthesis.rs:405-429` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/inverse/r1cs.rs`

### Error

- [x] **INV-CV-INV-18: a wrong claim fails natively with exactly the fixture's rule**
  - Covered by: `tests/unit/circuit_var/inverse/native.rs` `every_wrong_inverse_of_a_nonzero_x_breaks_exactly_the_fixture_rule_natively`; `tests/unit/circuit_var/inverse/properties.rs` `natively_the_inverse_holds_exactly_when_the_claim_times_x_is_one` (property)
  - Kind: error
  - Statement: for every invalid vector and for every random nonzero x and claim, the native run returns exactly `Ok(())` when x times the claim is 1 and otherwise exactly `CircuitError.RuleBroken` with the rule "the claim is the inverse of x", located in the fixture's file.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`, the constant branch)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/circuit_var/inverse/native.rs`, `tests/unit/circuit_var/inverse/properties.rs`

- [x] **INV-CV-INV-19: a zero x fails natively with DivisionByZero whatever the claim**
  - Covered by: `tests/unit/circuit_var/inverse/native.rs` `a_zero_x_fails_natively_with_division_by_zero_whatever_the_claim`; `tests/unit/circuit_var/inverse/properties.rs` `a_zero_x_is_refused_natively_and_by_every_witness` (property)
  - Kind: error
  - Statement: for every zero vector and every random claim, the native run of `Inverse` returns exactly `CircuitError.DivisionByZero`, with no rule, located in the fixture's file.
  - Location: `src/circuit/builtins/field/arithmetic.rs:7-19` (`fn inverse`, the constant branch)
  - Error: `CircuitErrorKind::DivisionByZero`
  - Severity: High
  - Suggested test: negative + property; `tests/unit/circuit_var/inverse/native.rs`, `tests/unit/circuit_var/inverse/properties.rs`

- [x] **INV-CV-INV-20: a zero x fails in R1CS with DivisionByZero**
  - Covered by: `tests/unit/circuit_var/inverse/r1cs.rs` `a_zero_x_is_refused_with_division_by_zero_in_the_r1cs_synthesis_and_by_the_prover`
  - Kind: error
  - Statement: for every zero vector, the proving synthesis alone on a fresh constraint system, `check_constraints` and `export_assignment` each return exactly `CircuitError.DivisionByZero`, with no rule, located in the fixture's file: the prover refuses to assign w before any row is checked.
  - Location: `src/circuit/builtins/field/arithmetic.rs:15-17` (`fn inverse`, the assigned-value check)
  - Error: `CircuitErrorKind::DivisionByZero`
  - Severity: High
  - Suggested test: negative; `tests/unit/circuit_var/inverse/r1cs.rs`

- [x] **INV-CV-INV-21: the constant zero has no inverse at the line that asks**
  - Covered by: `tests/unit/circuit_var/inverse/native.rs` `the_constant_zero_has_no_inverse_at_the_line_that_asks`
  - Kind: error
  - Statement: `zero().inverse()` returns exactly `CircuitError.DivisionByZero` located in the calling file, the native run of `InverseOfZero` returns exactly `DivisionByZero` located in the fixture's file, and the native run of `InverseOfFour` with the claim 1/4 returns exactly `Ok(())`.
  - Location: `src/circuit/builtins/field/arithmetic.rs:7-13` (`fn inverse`, the constant branch)
  - Error: `CircuitErrorKind::DivisionByZero`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/circuit_var/inverse/native.rs`

- [x] **INV-CV-INV-22: a constant zero is refused when the circuit is built**
  - Covered by: `tests/unit/circuit_var/inverse/r1cs.rs` `a_constant_zero_divisor_is_refused_when_the_circuit_is_built`
  - Kind: error
  - Statement: `InverseOfZero::export_r1cs` and `InverseOfZero::export_picus_r1cs` each return exactly `CircuitError.DivisionByZero` located in the fixture's file.
  - Location: `src/circuit/builtins/field/arithmetic.rs:7-13` (`fn inverse`, the constant branch), `src/client/zk_circuit.rs:14-25` (`fn export_r1cs`, `fn export_picus_r1cs`)
  - Error: `CircuitErrorKind::DivisionByZero`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/circuit_var/inverse/r1cs.rs`

- [x] **INV-CV-INV-23: a tampered claim fails in R1CS with exactly the fixture's rule**
  - Covered by: `tests/unit/circuit_var/inverse/r1cs.rs` `the_proving_rows_name_the_rule_for_a_wrong_claim_and_no_rule_for_a_wrong_witness`; `tests/unit/circuit_var/inverse/properties.rs` `every_honest_inverse_checks_two_constraints_and_a_wrong_claim_names_the_rule` (property)
  - Kind: error
  - Statement: for every valid vector and every random nonzero x and offset, `check_tampered` with the claim moved off 1 / x returns exactly `ProverError.ProofInputsBreakRule` at row 1 labelled with the fixture's rule.
  - Location: `src/testing.rs:43-68` (`fn check_tampered`), `src/prover/synthesis.rs:174-202` (`fn check`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/circuit_var/inverse/r1cs.rs`, `tests/unit/circuit_var/inverse/properties.rs`

- [x] **INV-CV-INV-24: a tampered w or a zeroed x breaks the unlabelled inverse row**
  - Covered by: `tests/unit/circuit_var/inverse/r1cs.rs` `the_proving_rows_name_the_rule_for_a_wrong_claim_and_no_rule_for_a_wrong_witness`
  - Kind: error
  - Statement: for every valid vector, `check_tampered` with w increased by 1, and with x set to 0, each returns exactly `ProverError.ProofInputsBreakRule` at row 0 with no label.
  - Location: `src/circuit/builtins/field/primitive.rs:80-82` (`fn inverted`), `src/circuit/labels.rs:255-270` (`fn report`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/circuit_var/inverse/r1cs.rs`

### Equivalence

- [x] **INV-CV-INV-25: circom accepts exactly the cases the SDK accepts**
  - Covered by: `tests/unit/circuit_var/inverse/external.rs` `circom_accepts_exactly_the_cases_the_sdk_accepts`
  - Kind: equivalence
  - Statement: for every valid, invalid and zero vector, the SDK native run, the SDK R1CS, circom's witness calculation and circom's R1CS (checked against the witness calculated with failed asserts ignored) all accept exactly when the vector is valid; the SDK R1CS is checked against the honest assignment with the claim overwritten for an invalid vector and against `[1, 0, claim, 0]` for a zero vector.
  - Location: `src/circuit/builtins/field/arithmetic.rs:7-19` (`fn inverse`), `tests/unit/circuit_var/inverse/inverse.circom`, `tests/unit/harness/equivalence.rs` (`fn assert_relation_equivalent`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/inverse/external.rs`

- [x] **INV-CV-INV-26: the rows normalize equal and both sizes are pinned**
  - Covered by: `tests/unit/circuit_var/inverse/external.rs` `the_rows_normalize_equal_and_both_sizes_are_pinned`
  - Kind: equivalence
  - Statement: circom's `inv` is wire 3, the SDK's w's variable, both circuits have exactly 2 constraints over 4 variables, and both normalize to exactly the linear {2: 1, 3: -1} and the product x * w = 1.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`), `tests/unit/circuit_var/inverse/inverse.circom`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/inverse/external.rs`

- [x] **INV-CV-INV-27: the Picus export makes the inverse witness its only output**
  - Covered by: `tests/unit/circuit_var/inverse/picus.rs` `the_picus_export_makes_the_inverse_witness_its_only_output`
  - Kind: equivalence
  - Statement: `Inverse`'s `export_picus_r1cs` header is exactly 4 variables, 1 public output, 2 private inputs and 2 constraints with the wire labels `[0, 3, 1, 2]`, and `Unasserted`'s exactly 3 variables, 1 public output, 1 private input and 1 constraint with `[0, 2, 1]`.
  - Location: `src/prover/snarkjs.rs:19-45` (`fn picus_r1cs`)
  - Severity: High
  - Suggested test: external (Picus); `tests/unit/circuit_var/inverse/picus.rs`

- [x] **INV-CV-INV-28: the circom witness equals the SDK witness**
  - Covered by: `tests/unit/circuit_var/inverse/external.rs` `circom_witnesses_equal_the_sdk_assignments`
  - Kind: equivalence
  - Statement: for every valid vector, the witness circom's wasm computes is exactly the SDK's exported assignment, w included.
  - Location: `src/prover/synthesis.rs:275-278` (`fn assignment_of`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/inverse/external.rs`

### Interop

- [x] **INV-CV-INV-29: snarkjs wtns check accepts the SDK pair and rejects each tampered wire**
  - Covered by: `tests/unit/circuit_var/inverse/external.rs` `snarkjs_accepts_the_sdk_pair_and_rejects_each_tampered_wire`
  - Kind: interop
  - Statement: for every valid vector, `snarkjs wtns check` accepts the SDK R1CS with the SDK assignment and rejects it with the claim, or w, increased by exactly 1.
  - Location: `src/prover/snarkjs.rs:12-124` (`fn r1cs`, `fn wtns`)
  - Severity: Critical
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/inverse/external.rs`

- [x] **INV-CV-INV-30: snarkjs wtns check rejects a zero x**
  - Covered by: `tests/unit/circuit_var/inverse/external.rs` `snarkjs_rejects_a_zero_x_with_every_inverse_witness`
  - Kind: interop
  - Statement: for every zero vector, `snarkjs wtns check` rejects the SDK R1CS with `[1, 0, claim, claim]`.
  - Location: `src/circuit/builtins/field/primitive.rs:80-82` (`fn inverted`), `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: Critical
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/inverse/external.rs`

- [x] **INV-CV-INV-31: snarkjs Groth16 proves and verifies**
  - Covered by: `tests/unit/circuit_var/inverse/external.rs` `snarkjs_proves_and_verifies_the_sdk_circuit`
  - Kind: interop
  - Statement: `snarkjs groth16 setup` over a throwaway ptau, `groth16 prove` with the SDK assignment of 1 / x and `groth16 verify` accept the SDK R1CS, with exactly the empty public signal list.
  - Location: `src/prover/snarkjs.rs:12-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/inverse/external.rs`

## Division (`div`)

`CircuitVar::div` is `self.times(&divisor.inverse()?)`: the divisor's inverse
(INV-CV-INV), then a product. The fixtures in `tests/unit/circuit_var/div/fixtures.rs`
assert `dividend.div(&divisor)? == quotient` with the rule "the quotient is the dividend
over the divisor": `Div` takes `dividend`, `divisor` and the claimed `quotient` as private
inputs (variables 1, 2 and 3), the inverse witness i is variable 4 and the product witness
q is variable 5. `ByFour` divides by `constant(4)`, `FourOver` divides `constant(4)` by the
divisor, and `ByZero` divides by `constant(0)`. The valid vectors are 0 / 1 = 0, 7 / 1 = 7,
1 / 2 = (p + 1) / 2, 6 / 3 = 2, 7 / 2 = (p + 7) / 2, x / (p - 1) = -x, 7 / x and x / x = 1;
the invalid ones are 7 / 2 = 3, 7 / 2 = 4, 6 / 3 = 3, x / x = 0 and 0 / x = x; the zero
vectors claim 0 / 0 = 0, 1 / 0 = 0 and x / 0 = 1. The circom reference `div.circom`
computes `inv <-- 1 / divisor; inv * divisor === 1; product <== dividend * inv;
quotient === product`.

### Semantics

- [x] **INV-CV-DIV-01: the native quotient is the dividend times the divisor's inverse**
  - Covered by: `tests/unit/circuit_var/div/native.rs` `the_native_quotient_is_the_dividend_times_the_divisors_inverse_and_stays_a_constant`
  - Kind: semantics
  - Statement: for every valid vector, `constant(dividend).div(&constant(divisor))` is exactly the vector's quotient, the quotient times the divisor is exactly the dividend, and its `Debug` form is exactly `CircuitVar::constant(<quotient>)`: 7 / 2 is exactly (p + 7) / 2, not 3.
  - Location: `src/circuit/builtins/field/arithmetic.rs:21-24` (`fn div`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/div/native.rs`

- [x] **INV-CV-DIV-02: dividing by a nonzero divisor never fails**
  - Covered by: `tests/unit/circuit_var/div/native.rs` `every_valid_vector_holds_natively`; `tests/unit/circuit_var/div/r1cs.rs` `a_zero_divisor_is_refused_with_division_by_zero_in_the_r1cs_synthesis_and_by_the_prover`
  - Kind: semantics
  - Statement: for every valid vector, the native run of `Div` returns exactly `Ok(())`, and so does the proving synthesis alone on a fresh constraint system.
  - Location: `src/circuit/builtins/field/arithmetic.rs:21-24` (`fn div`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/div/native.rs`, `tests/unit/circuit_var/div/r1cs.rs`

- [x] **INV-CV-DIV-03: constant division undoes multiplication**
  - Covered by: `tests/unit/circuit_var/div/native.rs` `constant_division_undoes_multiplication_and_divides_by_one_and_itself_as_expected`
  - Kind: semantics
  - Statement: for every pair a and b of the valid vectors' divisors, as constants, the native (a * b) / b is exactly a, and for every divisor a, a / a is exactly 1 and a / 1 is exactly a.
  - Location: `src/circuit/builtins/field/arithmetic.rs:21-24` (`fn div`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/div/native.rs`

### Constraint

- [x] **INV-CV-DIV-04: the inverse, product and using rows are exact**
  - Covered by: `tests/unit/circuit_var/div/r1cs.rs` `div_exports_exactly_the_golden_rows_and_header`
  - Kind: constraint
  - Statement: `Div` exports exactly three rows: row 0 A = {2: 1}, B = {4: 1}, C = {0: 1} (`divisor * i = 1`), row 1 A = {1: 1}, B = {4: 1}, C = {5: 1} (`dividend * i = q`) and row 2 A = {5: 1, 3: -1}, B = {0: 1}, C = {} (`(q - quotient) * 1 = 0`).
  - Location: `src/circuit/builtins/field/arithmetic.rs:21-24` (`fn div`), `src/circuit/builtins/field/primitive.rs:64-82` (`fn times`, `fn inverted`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/div/r1cs.rs`

- [x] **INV-CV-DIV-05: the exported header counts are exact**
  - Covered by: `tests/unit/circuit_var/div/r1cs.rs` `div_exports_exactly_the_golden_rows_and_header`
  - Kind: constraint
  - Statement: `Div`'s exported header is exactly 6 variables, 0 public outputs, 0 public inputs, 5 private inputs and 3 constraints over the BN254 scalar prime, with the identity label map `[0, 1, 2, 3, 4, 5]`.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/div/r1cs.rs`

- [x] **INV-CV-DIV-06: a constant divisor costs no row and a constant dividend scales the inverse**
  - Covered by: `tests/unit/circuit_var/div/r1cs.rs` `a_constant_divisor_is_free_and_a_constant_dividend_scales_the_inverse`
  - Kind: constraint
  - Statement: `ByFour` exports exactly 3 variables and the one row A = {1: 1/4, 2: -1}, B = {0: 1}, C = {}; `FourOver` exports exactly 4 variables and the two rows `divisor * i = 1` (A = {1: 1}, B = {3: 1}, C = {0: 1}) and A = {2: -1, 3: 4}, B = {0: 1}, C = {}, with no product row.
  - Location: `src/circuit/builtins/field/arithmetic.rs:7-24` (`fn inverse`, `fn div`)
  - Severity: Medium
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/div/r1cs.rs`

- [x] **INV-CV-DIV-07: the inverse and product witnesses follow the proof inputs**
  - Covered by: `tests/unit/circuit_var/div/r1cs.rs` `the_assignment_is_the_inputs_the_inverse_then_the_product`
  - Kind: constraint
  - Statement: for every valid vector, `Div`'s exported assignment is exactly `[1, dividend, divisor, quotient, 1 / divisor, quotient]`.
  - Location: `src/circuit/builtins/field/arithmetic.rs:21-24` (`fn div`), `src/prover/synthesis.rs:275-278` (`fn assignment_of`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/div/r1cs.rs`

### Completeness

- [x] **INV-CV-DIV-08: every valid vector satisfies every row**
  - Covered by: `tests/unit/circuit_var/div/r1cs.rs` `every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row`; `tests/unit/circuit_var/div/r1cs.rs` `the_proving_rows_name_the_rule_for_a_wrong_quotient_and_no_rule_for_a_wrong_witness`; `tests/unit/circuit_var/div/properties.rs` `every_honest_quotient_checks_three_constraints_and_a_wrong_one_names_the_rule` (property)
  - Kind: completeness
  - Statement: for every valid vector, the exported assignment satisfies all three exported rows and the honest assignment satisfies every proving row; for every random dividend and nonzero divisor, `check_constraints` with the honest quotient returns exactly `Ok(3)`.
  - Location: `src/prover/synthesis.rs:174-202` (`fn check`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/div/r1cs.rs`, `tests/unit/circuit_var/div/properties.rs`

### Soundness

- [x] **INV-CV-DIV-09: every wrong quotient leaves some row unsatisfied**
  - Covered by: `tests/unit/circuit_var/div/r1cs.rs` `every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row`; `tests/unit/circuit_var/div/r1cs.rs` `every_wrong_quotient_breaks_a_row_whichever_product_witness_it_takes`
  - Kind: soundness
  - Statement: for every valid vector, the honest assignment with the quotient increased by 1 leaves exactly row 2 first unsatisfied; for every invalid vector with i = 1 / divisor, the assignment with q = dividend * i leaves exactly row 2 first unsatisfied and the one with q = the claim exactly row 1.
  - Location: `src/circuit/builtins/field/arithmetic.rs:21-24` (`fn div`), `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/circuit_var/div/r1cs.rs`

- [x] **INV-CV-DIV-10: a wrong inverse or product witness breaks its row**
  - Covered by: `tests/unit/circuit_var/div/r1cs.rs` `every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row`
  - Kind: soundness
  - Statement: for every valid vector, the honest assignment with i increased by 1 leaves exactly row 0 first unsatisfied, and with q increased by 1 exactly row 1.
  - Location: `src/circuit/builtins/field/primitive.rs:64-82` (`fn times`, `fn inverted`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/circuit_var/div/r1cs.rs`

- [x] **INV-CV-DIV-11: a zero divisor is unprovable**
  - Covered by: `tests/unit/circuit_var/div/r1cs.rs` `a_zero_divisor_breaks_the_inverse_row_whatever_the_witnesses`; `tests/unit/circuit_var/div/r1cs.rs` `every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row`; `tests/unit/circuit_var/div/properties.rs` `a_zero_divisor_is_refused_natively_and_by_every_witness` (property)
  - Kind: soundness
  - Statement: for every zero vector and every i and q in {0, 1, p - 1}, for every random dividend, quotient, i and q, and for every valid vector's honest assignment with the divisor overwritten by 0, the assignment with divisor 0 leaves exactly row 0 first unsatisfied.
  - Location: `src/circuit/builtins/field/primitive.rs:80-82` (`fn inverted`)
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/circuit_var/div/r1cs.rs`, `tests/unit/circuit_var/div/properties.rs`

- [x] **INV-CV-DIV-12: no private variable of the fixture is free**
  - Covered by: `tests/unit/circuit_var/div/r1cs.rs` `no_private_variable_is_free_for_any_valid_vector`
  - Kind: soundness
  - Statement: for every valid vector, `check_private_variables` of `Div` reports exactly 3 constraints, 5 private variables, no free variable and no tolerated variable.
  - Location: `src/prover/synthesis.rs:111-172` (`fn unconstrained_private_variables`), `src/testing.rs:70-99` (`fn check_private_variables`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/circuit_var/div/r1cs.rs`

- [x] **INV-CV-DIV-13: Picus proves the SDK and the circom quotient deterministic**
  - Covered by: `tests/unit/circuit_var/div/picus.rs` `picus_finds_the_sdk_and_the_circom_quotient_deterministic`
  - Kind: soundness
  - Statement: Picus reports exactly Safe for `Div`'s `export_picus_r1cs` with the quotient moved to the outputs next to i and q, exactly Safe for `div.circom` with its `quotient` input moved to the outputs, and exactly Safe for `FourOver`'s Picus export, each under a 120 s limit.
  - Location: `src/prover/snarkjs.rs:19-45` (`fn picus_r1cs`), `tests/unit/harness/equivalence.rs` (`fn picus_verdicts`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/circuit_var/div/picus.rs`

### Shape

- [x] **INV-CV-DIV-14: setup divides by the placeholder's zero without refusing it**
  - Covered by: `tests/unit/circuit_var/div/r1cs.rs` `every_valid_vector_checks_three_constraints_although_the_placeholder_divisor_is_zero`
  - Kind: shape
  - Statement: for every valid vector, `check_constraints` of `Div` returns exactly `Ok(3)`, although the placeholder's divisor is 0.
  - Location: `src/circuit/builtins/field/arithmetic.rs:15-18` (`fn inverse`, the assigned-value check), `src/prover/synthesis.rs:405-429` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/div/r1cs.rs`

### Error

- [x] **INV-CV-DIV-15: a wrong quotient fails natively with exactly the fixture's rule**
  - Covered by: `tests/unit/circuit_var/div/native.rs` `every_wrong_quotient_breaks_exactly_the_fixture_rule_natively`; `tests/unit/circuit_var/div/properties.rs` `natively_div_holds_exactly_when_the_quotient_times_the_divisor_is_the_dividend` (property)
  - Kind: error
  - Statement: for every invalid vector and for every random dividend, nonzero divisor and claim, the native run returns exactly `Ok(())` when the claim times the divisor is the dividend and otherwise exactly `CircuitError.RuleBroken` with the rule "the quotient is the dividend over the divisor", located in the fixture's file.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`, the constant branch)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/circuit_var/div/native.rs`, `tests/unit/circuit_var/div/properties.rs`

- [x] **INV-CV-DIV-16: a zero divisor fails natively with DivisionByZero whatever the dividend and claim**
  - Covered by: `tests/unit/circuit_var/div/native.rs` `a_zero_divisor_fails_natively_with_division_by_zero_whatever_the_dividend_and_claim`; `tests/unit/circuit_var/div/properties.rs` `a_zero_divisor_is_refused_natively_and_by_every_witness` (property)
  - Kind: error
  - Statement: for every zero vector and every random dividend and claim, the native run of `Div` returns exactly `CircuitError.DivisionByZero`, with no rule, located in the fixture's file.
  - Location: `src/circuit/builtins/field/arithmetic.rs:7-24` (`fn inverse`, `fn div`)
  - Error: `CircuitErrorKind::DivisionByZero`
  - Severity: High
  - Suggested test: negative + property; `tests/unit/circuit_var/div/native.rs`, `tests/unit/circuit_var/div/properties.rs`

- [x] **INV-CV-DIV-17: a zero divisor fails in R1CS with DivisionByZero**
  - Covered by: `tests/unit/circuit_var/div/r1cs.rs` `a_zero_divisor_is_refused_with_division_by_zero_in_the_r1cs_synthesis_and_by_the_prover`
  - Kind: error
  - Statement: for every zero vector, the proving synthesis alone on a fresh constraint system, `check_constraints` and `export_assignment` each return exactly `CircuitError.DivisionByZero`, with no rule, located in the fixture's file.
  - Location: `src/circuit/builtins/field/arithmetic.rs:15-17` (`fn inverse`, the assigned-value check)
  - Error: `CircuitErrorKind::DivisionByZero`
  - Severity: High
  - Suggested test: negative; `tests/unit/circuit_var/div/r1cs.rs`

- [x] **INV-CV-DIV-18: a constant zero divisor fails at the line that divides**
  - Covered by: `tests/unit/circuit_var/div/native.rs` `a_constant_divisor_of_zero_fails_at_the_line_that_divides`
  - Kind: error
  - Statement: `constant(1).div(&constant(0))` returns exactly `CircuitError.DivisionByZero` located in the calling file, the native run of `ByZero` returns exactly `DivisionByZero` located in the fixture's file, and the native runs of `ByFour` (1 / 4) and `FourOver` (4 / 2 = 2) return exactly `Ok(())`.
  - Location: `src/circuit/builtins/field/arithmetic.rs:7-24` (`fn inverse`, `fn div`)
  - Error: `CircuitErrorKind::DivisionByZero`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/circuit_var/div/native.rs`

- [x] **INV-CV-DIV-19: a constant zero divisor is refused when the circuit is built**
  - Covered by: `tests/unit/circuit_var/div/r1cs.rs` `a_constant_zero_divisor_is_refused_when_the_circuit_is_built`
  - Kind: error
  - Statement: `ByZero::export_r1cs` and `ByZero::export_picus_r1cs` each return exactly `CircuitError.DivisionByZero` located in the fixture's file.
  - Location: `src/circuit/builtins/field/arithmetic.rs:7-24` (`fn inverse`, `fn div`), `src/client/zk_circuit.rs:14-25` (`fn export_r1cs`, `fn export_picus_r1cs`)
  - Error: `CircuitErrorKind::DivisionByZero`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/circuit_var/div/r1cs.rs`

- [x] **INV-CV-DIV-20: a tampered quotient fails in R1CS with exactly the fixture's rule**
  - Covered by: `tests/unit/circuit_var/div/r1cs.rs` `the_proving_rows_name_the_rule_for_a_wrong_quotient_and_no_rule_for_a_wrong_witness`; `tests/unit/circuit_var/div/properties.rs` `every_honest_quotient_checks_three_constraints_and_a_wrong_one_names_the_rule` (property)
  - Kind: error
  - Statement: for every valid vector and every random dividend, nonzero divisor and nonzero offset, `check_tampered` with the quotient moved off the honest one returns exactly `ProverError.ProofInputsBreakRule` at row 2 labelled with the fixture's rule.
  - Location: `src/testing.rs:43-68` (`fn check_tampered`), `src/prover/synthesis.rs:174-202` (`fn check`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/circuit_var/div/r1cs.rs`, `tests/unit/circuit_var/div/properties.rs`

- [x] **INV-CV-DIV-21: a tampered witness breaks an unlabelled row**
  - Covered by: `tests/unit/circuit_var/div/r1cs.rs` `the_proving_rows_name_the_rule_for_a_wrong_quotient_and_no_rule_for_a_wrong_witness`
  - Kind: error
  - Statement: for every valid vector, `check_tampered` with i increased by 1 returns exactly `ProverError.ProofInputsBreakRule` at row 0 with no label, and with q increased by 1 exactly at row 1 with no label.
  - Location: `src/circuit/builtins/field/arithmetic.rs:21-24` (`fn div`), `src/circuit/labels.rs:255-270` (`fn report`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/circuit_var/div/r1cs.rs`

### Equivalence

- [x] **INV-CV-DIV-22: circom accepts exactly the cases the SDK accepts**
  - Covered by: `tests/unit/circuit_var/div/external.rs` `circom_accepts_exactly_the_cases_the_sdk_accepts`
  - Kind: equivalence
  - Statement: for every valid, invalid and zero vector, the SDK native run, the SDK R1CS, circom's witness calculation and circom's R1CS all accept exactly when the vector is valid; the SDK R1CS is checked against the honest assignment with the quotient overwritten for an invalid vector and against `[1, dividend, 0, quotient, 0, quotient]` for a zero vector.
  - Location: `src/circuit/builtins/field/arithmetic.rs:21-24` (`fn div`), `tests/unit/circuit_var/div/div.circom`, `tests/unit/harness/equivalence.rs` (`fn assert_relation_equivalent`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/div/external.rs`

- [x] **INV-CV-DIV-23: the rows normalize equal and both sizes are pinned**
  - Covered by: `tests/unit/circuit_var/div/external.rs` `the_rows_normalize_equal_and_both_sizes_are_pinned`
  - Kind: equivalence
  - Statement: circom's `inv` and `product` are wires 4 and 5, the SDK's i and q, both circuits have exactly 3 constraints over 6 variables, and both normalize to exactly the linear {3: 1, 5: -1} and the products dividend * i = q and divisor * i = 1.
  - Location: `src/prover/snarkjs.rs:12-17` (`fn r1cs`), `tests/unit/circuit_var/div/div.circom`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/div/external.rs`

- [x] **INV-CV-DIV-24: the circom witness equals the SDK witness**
  - Covered by: `tests/unit/circuit_var/div/external.rs` `circom_witnesses_equal_the_sdk_assignments`
  - Kind: equivalence
  - Statement: for every valid vector, the witness circom's wasm computes is exactly the SDK's exported assignment of the honest `Div`.
  - Location: `src/prover/synthesis.rs:275-278` (`fn assignment_of`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/div/external.rs`

- [x] **INV-CV-DIV-25: the Picus export makes the inverse and the product its outputs**
  - Covered by: `tests/unit/circuit_var/div/picus.rs` `the_picus_export_makes_the_inverse_and_the_product_its_outputs`
  - Kind: equivalence
  - Statement: `Div`'s `export_picus_r1cs` header is exactly 6 variables, 2 public outputs, 3 private inputs and 3 constraints, with the wire labels exactly `[0, 4, 5, 1, 2, 3]`.
  - Location: `src/prover/snarkjs.rs:19-45` (`fn picus_r1cs`)
  - Severity: High
  - Suggested test: external (Picus); `tests/unit/circuit_var/div/picus.rs`

### Interop

- [x] **INV-CV-DIV-26: snarkjs wtns check accepts the SDK pair and rejects each tampered wire**
  - Covered by: `tests/unit/circuit_var/div/external.rs` `snarkjs_accepts_the_sdk_pair_and_rejects_each_tampered_wire`
  - Kind: interop
  - Statement: for every valid vector, `snarkjs wtns check` accepts the SDK R1CS with the SDK assignment and rejects it with the quotient, i or q increased by exactly 1.
  - Location: `src/prover/snarkjs.rs:12-124` (`fn r1cs`, `fn wtns`)
  - Severity: Critical
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/div/external.rs`

- [x] **INV-CV-DIV-27: snarkjs Groth16 proves and verifies**
  - Covered by: `tests/unit/circuit_var/div/external.rs` `snarkjs_proves_and_verifies_the_sdk_circuit`
  - Kind: interop
  - Statement: `snarkjs groth16 setup` over a throwaway ptau, `groth16 prove` with the SDK assignment of 7 / x and `groth16 verify` accept the SDK R1CS, with exactly the empty public signal list.
  - Location: `src/prover/snarkjs.rs:12-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/div/external.rs`

## Power (`pow`)

`CircuitVar::pow` returns the constant power of a constant and otherwise arkworks'
`FpVar::pow_by_constant`: square-and-multiply over the exponent's bits from the most
significant one, one squaring per bit after the leading one and one product per set bit after
it, each a witness with its own row; x^0 is the constant 1 and x^1 is x itself. The fixture
`Pow<EXPONENT>` in `tests/unit/circuit_var/pow/fixtures.rs` asserts
`x.pow(EXPONENT)? == power` with the rule "the power is x to the exponent": `x` and the claimed
`power` are private inputs (variables 1 and 2), the witnesses start at variable 3, and `Pow5`
is `Pow<5>`, whose witnesses are x^2, x^4 and x^5. The valid vectors are 0^5 = 0, 1^5 = 1,
2^5 = 32, (p - 1)^5 = p - 1 and x^5 for a 77-digit x; the invalid ones are 2^5 = 10,
2^5 = 25, (p - 1)^5 = 1, 0^5 = 1 and x^5 = x. The circom reference `pow.circom` computes
`x2 <== x * x; x4 <== x2 * x2; x5 <== x4 * x; power === x5`.

### Semantics

- [x] **INV-CV-POW-01: the native power of a constant is field exponentiation**
  - Covered by: `tests/unit/circuit_var/pow/native.rs` `the_native_power_is_field_exponentiation_for_every_base_and_exponent`; `tests/unit/circuit_var/pow/properties.rs` `a_constant_power_is_field_exponentiation_for_every_exponent` (property)
  - Kind: semantics
  - Statement: for every base in {0, 1, 2, p - 1, 2^64, x} and every exponent in {0, 1, 2, 3, 5, 2^32, 2^63, 2^64 - 1}, `constant(base).pow(exponent)` is exactly the field element base^exponent and its `Debug` form is exactly `CircuitVar::constant(<power>)`; for every random base and u64 exponent its value is exactly base^exponent.
  - Location: `src/circuit/builtins/field/arithmetic.rs:26-29` (`fn pow`), `src/circuit/builtins/field/primitive.rs:84-86` (`fn power`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/pow/native.rs`, `tests/unit/circuit_var/pow/properties.rs`

- [x] **INV-CV-POW-02: zero to the zero is one, and every base to the zero is one**
  - Covered by: `tests/unit/circuit_var/pow/native.rs` `zero_to_the_zero_is_one_and_every_base_to_the_zero_holds_natively`
  - Kind: semantics
  - Statement: `zero().pow(0)` is exactly the constant 1, and for every base the native run of `Pow<0>` with the claim 1 returns exactly `Ok(())`.
  - Location: `src/circuit/builtins/field/primitive.rs:84-86` (`fn power`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/pow/native.rs`

- [x] **INV-CV-POW-03: constant powers add their exponents, and the first power is the base**
  - Covered by: `tests/unit/circuit_var/pow/native.rs` `constant_powers_add_their_exponents_and_raise_to_one_exactly_the_base`
  - Kind: semantics
  - Statement: for every base and every pair of exponents m and n in {0, 1, 2, 3, 5}, the native base^m times base^n is exactly base^(m + n), and base^1 is exactly the base.
  - Location: `src/circuit/builtins/field/primitive.rs:84-86` (`fn power`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/pow/native.rs`

- [x] **INV-CV-POW-04: every valid vector holds natively**
  - Covered by: `tests/unit/circuit_var/pow/native.rs` `every_valid_vector_holds_natively`
  - Kind: semantics
  - Statement: for every valid vector, the native run of `Pow5` returns exactly `Ok(())`.
  - Location: `src/circuit/builtins/field/arithmetic.rs:26-29` (`fn pow`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/pow/native.rs`

### Constraint

- [x] **INV-CV-POW-05: the x^5 rows and header are exact**
  - Covered by: `tests/unit/circuit_var/pow/r1cs.rs` `x_to_the_5_exports_exactly_the_golden_rows_and_header`
  - Kind: constraint
  - Statement: `Pow5` exports exactly four rows: row 0 A = {1: 1}, B = {1: 1}, C = {3: 1} (`x * x = x^2`), row 1 A = {3: 1}, B = {3: 1}, C = {4: 1} (`x^2 * x^2 = x^4`), row 2 A = {4: 1}, B = {1: 1}, C = {5: 1} (`x^4 * x = x^5`) and row 3 A = {5: 1, 2: -1}, B = {0: 1}, C = {} (`(x^5 - power) * 1 = 0`), under the header 6 variables, 0 public outputs, 0 public inputs, 5 private inputs and 4 constraints over the BN254 scalar prime, with the identity label map.
  - Location: `src/circuit/builtins/field/primitive.rs:84-86` (`fn power`), `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`), `src/prover/snarkjs.rs:13-22` (`fn r1cs`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/pow/r1cs.rs`

- [x] **INV-CV-POW-06: x^0 and x^1 allocate no witness**
  - Covered by: `tests/unit/circuit_var/pow/r1cs.rs` `x_to_the_0_and_to_the_1_allocate_no_witness`
  - Kind: constraint
  - Statement: `Pow<0>` and `Pow<1>` each export exactly 3 variables, 2 private inputs and one row, B = {0: 1}, C = {}: `Pow<0>`'s A is exactly {0: 1, 2: -1} (`1 = power`) and `Pow<1>`'s exactly {1: 1, 2: -1} (`x = power`).
  - Location: `src/circuit/builtins/field/primitive.rs:84-86` (`fn power`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/pow/r1cs.rs`

- [x] **INV-CV-POW-07: one squaring per bit after the leading one and one product per set bit after it**
  - Covered by: `tests/unit/circuit_var/pow/r1cs.rs` `the_size_is_one_square_per_bit_after_the_first_and_one_product_per_set_bit_after_it`
  - Kind: constraint
  - Statement: for the exponents 0, 1, 2, 3, 5, 2^32, 2^63 and 2^64 - 1, `Pow<EXPONENT>` has exactly 1, 1, 2, 3, 4, 33, 64 and 127 constraints and exactly 2 more variables than constraints: the witness count is the bit length minus 1 plus the popcount minus 1, and 0 for the exponent 0.
  - Location: `src/circuit/builtins/field/primitive.rs:84-86` (`fn power`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/pow/r1cs.rs`

- [x] **INV-CV-POW-08: the witnesses follow the proof inputs**
  - Covered by: `tests/unit/circuit_var/pow/r1cs.rs` `the_assignment_is_x_the_power_then_x_squared_x_to_the_4_and_x_to_the_5`
  - Kind: constraint
  - Statement: for every valid vector, `Pow5`'s exported assignment is exactly `[1, x, power, x^2, x^4, x^5]`.
  - Location: `src/circuit/builtins/field/primitive.rs:84-86` (`fn power`), `src/prover/synthesis.rs:275-278` (`fn assignment_of`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/pow/r1cs.rs`

### Completeness

- [x] **INV-CV-POW-09: every honest power satisfies every row**
  - Covered by: `tests/unit/circuit_var/pow/r1cs.rs` `every_valid_vector_checks_four_constraints`; `tests/unit/circuit_var/pow/r1cs.rs` `every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row`; `tests/unit/circuit_var/pow/properties.rs` `every_honest_power_checks_four_constraints_and_a_wrong_one_names_the_rule` (property)
  - Kind: completeness
  - Statement: for every valid vector the exported assignment satisfies all four exported rows, and for every valid vector and every random x, `check_constraints` with the honest x^5 returns exactly `Ok(4)`.
  - Location: `src/prover/synthesis.rs:174-202` (`fn check`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/pow/r1cs.rs`, `tests/unit/circuit_var/pow/properties.rs`

### Soundness

- [x] **INV-CV-POW-10: each tampered wire breaks its own row**
  - Covered by: `tests/unit/circuit_var/pow/r1cs.rs` `every_valid_vector_satisfies_every_row_and_each_tampered_wire_breaks_its_row`
  - Kind: soundness
  - Statement: for every valid vector, the honest assignment with the power, x^2, x^4 or x^5 increased by 1 leaves exactly row 3, 0, 1 or 2 first unsatisfied.
  - Location: `src/circuit/builtins/field/primitive.rs:84-86` (`fn power`), `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/circuit_var/pow/r1cs.rs`

- [x] **INV-CV-POW-11: every wrong power breaks a row whichever x^5 witness it takes**
  - Covered by: `tests/unit/circuit_var/pow/r1cs.rs` `every_invalid_vector_breaks_a_row_with_the_honest_witnesses_or_the_claimed_power`
  - Kind: soundness
  - Statement: for every invalid vector, the assignment with the honest x^2, x^4 and x^5 leaves exactly row 3 first unsatisfied, and the one with the x^5 witness set to the wrong claim exactly row 2.
  - Location: `src/circuit/builtins/field/primitive.rs:84-86` (`fn power`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/circuit_var/pow/r1cs.rs`

- [x] **INV-CV-POW-12: no private variable of x^5 is free, and x^0 leaves exactly x free**
  - Covered by: `tests/unit/circuit_var/pow/r1cs.rs` `no_private_variable_of_x_to_the_5_is_free_and_x_to_the_0_leaves_x_free`
  - Kind: soundness
  - Statement: for every valid vector, `check_private_variables` of `Pow5` reports exactly 4 constraints, 5 private variables, no free variable and no tolerated variable; for `Pow<0>` it reports exactly 1 constraint, 2 private variables and private variable 0 (x) free, which x^0 = 1 does not constrain.
  - Location: `src/prover/synthesis.rs:111-172` (`fn unconstrained_private_variables`), `src/testing.rs:70-99` (`fn check_private_variables`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/circuit_var/pow/r1cs.rs`

- [x] **INV-CV-POW-13: Picus proves the SDK and the circom x^5 deterministic**
  - Covered by: `tests/unit/circuit_var/pow/picus.rs` `picus_finds_the_sdk_and_the_circom_power_deterministic`
  - Kind: soundness
  - Statement: Picus reports exactly Safe for `Pow5`'s `export_picus_r1cs` with the power moved to the outputs next to the witnesses, and exactly Safe for `pow.circom` with its `power` input moved to the outputs, each under a 120 s limit.
  - Location: `src/prover/snarkjs.rs:24-50` (`fn picus_r1cs`), `tests/unit/harness/equivalence.rs` (`fn picus_verdicts`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/circuit_var/pow/picus.rs`

- [x] **INV-CV-POW-14: Picus finds x free in x^0 and fixed by the power in x^1**
  - Covered by: `tests/unit/circuit_var/pow/picus.rs` `picus_finds_x_free_in_x_to_the_0_and_fixed_by_the_power_in_x_to_the_1`
  - Kind: soundness
  - Statement: under a 120 s limit Picus reports exactly Unsafe for `Pow<0>` with x moved to the outputs, exactly Safe for `Pow<0>` with the power moved to the outputs, and exactly Safe for `Pow<1>` with x moved to the outputs.
  - Location: `src/prover/snarkjs.rs:24-50` (`fn picus_r1cs`), `tests/unit/harness/picus.rs` (`fn verdict_within`, `fn promote`)
  - Severity: High
  - Suggested test: external (Picus); `tests/unit/circuit_var/pow/picus.rs`

### Shape

- [x] **INV-CV-POW-15: the setup and the proving synthesis build the same rows**
  - Covered by: `tests/unit/circuit_var/pow/r1cs.rs` `every_valid_vector_checks_four_constraints`
  - Kind: shape
  - Statement: for every valid vector, `check_constraints`, which compares the matrices of the setup synthesis over placeholder inputs with those of the proving synthesis, returns exactly `Ok(4)`: the exponent alone fixes the rows, whatever x is.
  - Location: `src/prover/synthesis.rs:174-202` (`fn check`), `src/client/zk_circuit.rs:9-12` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/pow/r1cs.rs`

### Error

- [x] **INV-CV-POW-16: a wrong power fails natively with exactly the fixture's rule**
  - Covered by: `tests/unit/circuit_var/pow/native.rs` `every_invalid_vector_breaks_exactly_the_fixture_rule_natively`; `tests/unit/circuit_var/pow/properties.rs` `natively_x_to_the_5_holds_exactly_when_the_claim_is_the_fifth_power` (property)
  - Kind: error
  - Statement: for every invalid vector and every random x and claim, the native run of `Pow5` returns exactly `Ok(())` when the claim is x^5 and otherwise exactly `CircuitError.RuleBroken` with the rule "the power is x to the exponent", located in the fixture's file.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`, the constant branch)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/circuit_var/pow/native.rs`, `tests/unit/circuit_var/pow/properties.rs`

- [x] **INV-CV-POW-17: a tampered power fails in R1CS with exactly the fixture's rule**
  - Covered by: `tests/unit/circuit_var/pow/r1cs.rs` `the_proving_rows_name_the_rule_for_a_wrong_power_and_no_rule_for_a_wrong_witness`; `tests/unit/circuit_var/pow/properties.rs` `every_honest_power_checks_four_constraints_and_a_wrong_one_names_the_rule` (property)
  - Kind: error
  - Statement: for every valid vector and every random x and nonzero offset, `check_tampered` with the power moved off x^5 returns exactly `ProverError.ProofInputsBreakRule` at row 3 labelled with the fixture's rule.
  - Location: `src/testing.rs:43-68` (`fn check_tampered`), `src/prover/synthesis.rs:174-202` (`fn check`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/circuit_var/pow/r1cs.rs`, `tests/unit/circuit_var/pow/properties.rs`

- [x] **INV-CV-POW-18: a tampered witness breaks its unlabelled row**
  - Covered by: `tests/unit/circuit_var/pow/r1cs.rs` `the_proving_rows_name_the_rule_for_a_wrong_power_and_no_rule_for_a_wrong_witness`
  - Kind: error
  - Statement: for every valid vector, `check_tampered` with x^2, x^4 or x^5 increased by 1 returns exactly `ProverError.ProofInputsBreakRule` at row 0, 1 or 2 with no label.
  - Location: `src/circuit/builtins/field/primitive.rs:84-86` (`fn power`), `src/circuit/labels.rs:256-270` (`fn report`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/circuit_var/pow/r1cs.rs`

### Equivalence

- [x] **INV-CV-POW-19: the circom rows normalize to the SDK rows over the same wires**
  - Covered by: `tests/unit/circuit_var/pow/external.rs` `circom_rows_normalize_to_the_sdk_rows_over_the_same_wires`
  - Kind: equivalence
  - Statement: circom's `main.x2`, `main.x4` and `main.x5` are exactly wires 3, 4 and 5, circom's header is exactly 6 variables, 2 private inputs and 4 constraints, and both circuits normalize to exactly the same linear constraint `power = x^5` and the same three products.
  - Location: `src/prover/snarkjs.rs:13-22` (`fn r1cs`), `tests/unit/circuit_var/pow/pow.circom`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/pow/external.rs`

- [x] **INV-CV-POW-20: the circom witness equals the SDK witness**
  - Covered by: `tests/unit/circuit_var/pow/external.rs` `circom_witnesses_equal_the_sdk_witnesses`
  - Kind: equivalence
  - Statement: for every valid vector, the witness circom's wasm computes is exactly the SDK's exported assignment, the three witnesses included.
  - Location: `src/prover/synthesis.rs:275-278` (`fn assignment_of`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/pow/external.rs`

- [x] **INV-CV-POW-21: circom refuses every invalid vector**
  - Covered by: `tests/unit/circuit_var/pow/external.rs` `circom_witness_calculation_fails_for_every_invalid_vector`
  - Kind: equivalence
  - Statement: for every invalid vector, circom's witness calculation with aborting asserts fails with exactly an "Assert Failed" error, as the SDK's native run refuses it (INV-CV-POW-16).
  - Location: `tests/unit/circuit_var/pow/pow.circom`, `tests/unit/harness/circom.rs` (`fn calculate`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/pow/external.rs`

- [x] **INV-CV-POW-22: each R1CS accepts the other's witness**
  - Covered by: `tests/unit/circuit_var/pow/external.rs` `each_r1cs_accepts_the_others_witness`
  - Kind: equivalence
  - Statement: for every valid vector, the SDK R1CS is satisfied by circom's witness and circom's R1CS by the SDK's assignment.
  - Location: `src/prover/snarkjs.rs:13-22` (`fn r1cs`)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/pow/external.rs`

- [x] **INV-CV-POW-23: the Picus export makes the three witnesses its outputs**
  - Covered by: `tests/unit/circuit_var/pow/picus.rs` `the_picus_export_makes_the_three_witnesses_its_outputs`
  - Kind: equivalence
  - Statement: `Pow5`'s `export_picus_r1cs` header is exactly 6 variables, 3 public outputs, 2 private inputs and 4 constraints with the wire labels `[0, 3, 4, 5, 1, 2]`, and the Picus exports of `Pow<0>` and `Pow<1>`, which have no witness, are exactly their `export_r1cs`.
  - Location: `src/prover/snarkjs.rs:24-50` (`fn picus_r1cs`)
  - Severity: High
  - Suggested test: external (Picus); `tests/unit/circuit_var/pow/picus.rs`

### Interop

- [x] **INV-CV-POW-24: snarkjs wtns check accepts the SDK pair and rejects each tampered wire**
  - Covered by: `tests/unit/circuit_var/pow/external.rs` `snarkjs_accepts_the_sdk_pair_and_rejects_each_tampered_wire`
  - Kind: interop
  - Statement: for every valid vector, `snarkjs wtns check` accepts the SDK R1CS with the SDK assignment and rejects it with the power, x^2, x^4 or x^5 increased by exactly 1.
  - Location: `src/prover/snarkjs.rs:13-124` (`fn r1cs`, `fn wtns`)
  - Severity: Critical
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/pow/external.rs`

- [x] **INV-CV-POW-25: snarkjs accepts each R1CS with the other's witness**
  - Covered by: `tests/unit/circuit_var/pow/external.rs` `snarkjs_accepts_the_sdk_r1cs_with_the_circom_witness`
  - Kind: interop
  - Statement: for every valid vector, `snarkjs wtns check` accepts the SDK R1CS with circom's witness and circom's R1CS with the SDK's `.wtns`.
  - Location: `src/prover/snarkjs.rs:13-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/pow/external.rs`

- [x] **INV-CV-POW-26: snarkjs Groth16 proves and verifies**
  - Covered by: `tests/unit/circuit_var/pow/external.rs` `snarkjs_proves_and_verifies_the_sdk_circuit`
  - Kind: interop
  - Statement: `snarkjs groth16 setup` over a throwaway ptau, `groth16 prove` with the SDK assignment of x^5 and `groth16 verify` accept the SDK R1CS, with exactly the empty public signal list.
  - Location: `src/prover/snarkjs.rs:13-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/pow/external.rs`

## Bits (`check_bits`, `check_is_bool`, `to_bits_le`, `from_bits_le`)

`src/circuit/builtins/field/bits.rs` implements the `Bits` trait for `CircuitVar`.
`check_bits(n)` decomposes the value with arkworks' `to_bits_le_with_top_bits_zero(n)` into n
boolean witnesses, one booleanity row `(1 - b) * b = 0` each, plus one row equating their
weighted sum to the value, all labelled "a value does not fit in its bit width". A width of 254
or more is refused with `BitWidthTooLarge`, and a constant is checked when the circuit is built
(`ValueTooLarge`) without any row. `check_is_bool` adds the row `x * (x - 1) = 0`, labelled "a
value is neither 0 nor 1" (`NotZeroOrOne` for a constant). `to_bits_le::<N>` returns the same
decomposition as `Bool`s, and `from_bits_le` is the weighted sum of `Bool`s, a linear
combination with no row of its own. The fixtures in `tests/unit/circuit_var/bits/fixtures.rs`
are:

- `CheckBits<N>` over x (variable 1).
- `CheckIsBool` over x.
- `ToBits<N>` over x and N claimed bits, each asserted equal to x's decomposition with the rule
  "the claimed bits are x's little-endian bits".
- `FromBits<N>` over N bits, each converted with `Bool::try_from`, whose `from_bits_le` sum is
  asserted equal to the claimed value with "the value is the bits' little-endian sum".
- `ConstantCheckBits<VALUE, N>` and `ConstantIsBool<VALUE>` over constants.

The width vectors are 0 and 1 in 1 bit against 2 and p - 1; 0, 1 and 15 in 4 bits against 16,
255, 2^64 and p - 1; and 0, 2^252 and 2^253 - 1 in 253 bits against 2^253 and p - 1. The bool
vectors are 0 and 1 against 2, (p + 1) / 2 and p - 1. The 4-bit claims are 0000 = 0,
1010 = 5, 0001 = 8 and 1111 = 15 against 1010 = 6, 0101 = 5, 1111 = 16, and [3, 1, 0, 0] = 5,
whose sum is right but whose first bit is not a bit. The references are circomlib's
`Num2Bits(4)` (`check_bits.circom`, `to_bits.circom`), `Bits2Num(4)` with a booleanity
constraint per bit (`from_bits.circom`) and `is_bool.circom`.

### Semantics

- [x] **INV-CV-BITS-01: check_bits holds natively exactly below 2^width**
  - Covered by: `tests/unit/circuit_var/bits/native.rs` `check_bits_holds_natively_exactly_below_two_to_the_width`; `tests/unit/circuit_var/bits/properties.rs` `check_bits_holds_natively_exactly_when_the_value_fits_the_width` (property)
  - Kind: semantics
  - Statement: for every width-1, width-4 and width-253 vector, and for every random field element at width 253 and every random u64 at widths 64 and 63, the native run of `CheckBits<N>` returns exactly `Ok(())` when the value's bit length is at most N and otherwise exactly `CircuitError.ValueTooLarge`, with no rule, located in the fixture's file.
  - Location: `src/circuit/builtins/field/bits.rs:73-91` (`fn bits_le`, the constant branch)
  - Error: `CircuitErrorKind::ValueTooLarge`
  - Severity: High
  - Suggested test: positive + negative + property; `tests/unit/circuit_var/bits/native.rs`, `tests/unit/circuit_var/bits/properties.rs`

- [x] **INV-CV-BITS-02: a width of 0 admits exactly zero**
  - Covered by: `tests/unit/circuit_var/bits/native.rs` `a_width_of_0_admits_exactly_zero`
  - Kind: semantics
  - Statement: the native run of `CheckBits<0>` returns exactly `Ok(())` for 0 and exactly `CircuitError.ValueTooLarge` for 1.
  - Location: `src/circuit/builtins/field/bits.rs:73-91` (`fn bits_le`)
  - Severity: Medium
  - Suggested test: positive + negative; `tests/unit/circuit_var/bits/native.rs`

- [x] **INV-CV-BITS-03: check_is_bool holds natively exactly for 0 and 1**
  - Covered by: `tests/unit/circuit_var/bits/native.rs` `check_is_bool_holds_natively_exactly_for_0_and_1`
  - Kind: semantics
  - Statement: for every bool vector, the native run of `CheckIsBool` returns exactly `Ok(())` for 0 and 1 and exactly `CircuitError.NotZeroOrOne`, with no rule, located in the fixture's file, for 2, (p + 1) / 2 and p - 1.
  - Location: `src/circuit/builtins/field/bits.rs:50-62` (`fn assert_bool`, the constant branch)
  - Error: `CircuitErrorKind::NotZeroOrOne`
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/circuit_var/bits/native.rs`

- [x] **INV-CV-BITS-04: the native bits of a constant are its little-endian binary digits**
  - Covered by: `tests/unit/circuit_var/bits/native.rs` `the_native_bits_of_a_constant_are_its_little_endian_binary_digits`
  - Kind: semantics
  - Statement: `to_bits_le::<4>` of 5 is exactly [1, 0, 1, 0], `to_bits_le::<1>` of 1 exactly [1], `to_bits_le::<253>` of 2^253 - 1 exactly 253 ones and of 2^252 exactly bit 252 alone, and the x of a natively instantiated `ToBits<4>` over 5 decomposes to exactly [1, 0, 1, 0].
  - Location: `src/circuit/builtins/field/bits.rs:33-39` (`fn to_bits_le`), `src/circuit/builtins/field/bits.rs:73-91` (`fn bits_le`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/bits/native.rs`

- [x] **INV-CV-BITS-05: from_bits_le is the weighted sum, which wraps past 253 bits**
  - Covered by: `tests/unit/circuit_var/bits/native.rs` `from_bits_le_is_the_weighted_sum_and_wraps_past_253_bits`
  - Kind: semantics
  - Statement: `from_bits_le` of no bit is exactly 0, of [1, 0, 1] exactly 5, of 253 ones exactly 2^253 - 1, and of 254 ones exactly 2^254 - 1 reduced modulo p: it neither refuses nor range-checks a sequence longer than a field element holds.
  - Location: `src/circuit/builtins/field/bits.rs:41-48` (`fn from_bits_le`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/bits/native.rs`

- [x] **INV-CV-BITS-06: from_bits_le undoes to_bits_le**
  - Covered by: `tests/unit/circuit_var/bits/native.rs` `from_bits_le_undoes_to_bits_le_at_every_width_edge`; `tests/unit/circuit_var/bits/properties.rs` `to_bits_le_and_from_bits_le_round_trip_every_u64` (property)
  - Kind: semantics
  - Statement: for every fitting width-253 vector, `from_bits_le(to_bits_le::<253>(x))` is exactly x; for every random u64, the same holds at 64 bits, and the native runs of `ToBits<64>` and `FromBits<64>` over its low bits return exactly `Ok(())`.
  - Location: `src/circuit/builtins/field/bits.rs:33-48` (`fn to_bits_le`, `fn from_bits_le`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/bits/native.rs`, `tests/unit/circuit_var/bits/properties.rs`

- [x] **INV-CV-BITS-07: to_bits_le holds natively exactly for the bits of a fitting value**
  - Covered by: `tests/unit/circuit_var/bits/native.rs` `to_bits_le_holds_natively_exactly_for_the_little_endian_bits_of_a_fitting_value`
  - Kind: semantics
  - Statement: for every 4-bit claim, the native run of `ToBits<4>` returns exactly `Ok(())` for an honest claim, `CircuitError.RuleBroken` with the rule "the claimed bits are x's little-endian bits" in the fixture's file for a wrong claim about a value below 16, and `CircuitError.ValueTooLarge` for the value 16.
  - Location: `src/circuit/builtins/field/bits.rs:33-39` (`fn to_bits_le`), `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/circuit_var/bits/native.rs`

- [x] **INV-CV-BITS-08: from_bits holds natively exactly for boolean bits and their sum**
  - Covered by: `tests/unit/circuit_var/bits/native.rs` `from_bits_holds_natively_exactly_for_boolean_bits_and_their_sum`
  - Kind: semantics
  - Statement: for every 4-bit claim, the native run of `FromBits<4>` returns exactly `Ok(())` for an honest claim, `CircuitError.RuleBroken` with the rule "the value is the bits' little-endian sum" in the fixture's file for boolean bits with a wrong value, and `CircuitError.NotZeroOrOne` for [3, 1, 0, 0].
  - Location: `src/circuit/builtins/field/bits.rs:41-48` (`fn from_bits_le`)
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/circuit_var/bits/native.rs`

### Constraint

- [x] **INV-CV-BITS-09: check_bits over 4 bits exports four booleanity rows and one sum row**
  - Covered by: `tests/unit/circuit_var/bits/r1cs.rs` `check_bits_4_exports_exactly_four_booleanity_rows_and_one_sum_row`
  - Kind: constraint
  - Statement: `CheckBits<4>` exports exactly five rows: for each bit wire w in 2..=5 a row A = {0: 1, w: -1}, B = {w: 1}, C = {}, then row 4 A = {1: -1, 2: 1, 3: 2, 4: 4, 5: 8}, B = {0: 1}, C = {}, under the header 6 variables, 5 private inputs and 5 constraints with the identity label map.
  - Location: `src/circuit/builtins/field/bits.rs:64-91` (`fn range_check`, `fn bits_le`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/bits/r1cs.rs`

- [x] **INV-CV-BITS-10: check_is_bool exports exactly x * (x - 1) = 0**
  - Covered by: `tests/unit/circuit_var/bits/r1cs.rs` `check_is_bool_exports_exactly_x_times_x_minus_1_equals_0`
  - Kind: constraint
  - Statement: `CheckIsBool` exports exactly the one row A = {1: 1}, B = {0: -1, 1: 1}, C = {} under the header 2 variables, 1 private input and 1 constraint.
  - Location: `src/circuit/builtins/field/bits.rs:50-62` (`fn assert_bool`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/bits/r1cs.rs`

- [x] **INV-CV-BITS-11: from_bits over 4 bits exports four booleanity rows and one sum row**
  - Covered by: `tests/unit/circuit_var/bits/r1cs.rs` `from_bits_4_exports_exactly_four_booleanity_rows_and_one_sum_row`
  - Kind: constraint
  - Statement: `FromBits<4>` exports exactly five rows: for each bit wire w in 1..=4 a row A = {w: 1}, B = {0: -1, w: 1}, C = {} from `Bool::try_from`, then row 4 A = {1: 1, 2: 2, 3: 4, 4: 8, 5: -1}, B = {0: 1}, C = {}, under the header 6 variables, 5 private inputs and 5 constraints: `from_bits_le` adds no row of its own.
  - Location: `src/circuit/builtins/field/bits.rs:41-48` (`fn from_bits_le`), `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/bits/r1cs.rs`

- [x] **INV-CV-BITS-12: to_bits over 4 bits decomposes, then asserts each claimed bit**
  - Covered by: `tests/unit/circuit_var/bits/r1cs.rs` `to_bits_4_decomposes_then_asserts_each_claimed_bit`
  - Kind: constraint
  - Statement: `ToBits<4>` exports exactly nine rows: the four booleanity rows over the witnesses 6..=9, the sum row A = {1: -1, 6: 1, 7: 2, 8: 4, 9: 8}, B = {0: 1}, C = {}, and for each bit i a row A = {2 + i: -1, 6 + i: 1}, B = {0: 1}, C = {}, under the header 10 variables, 9 private inputs and 9 constraints.
  - Location: `src/circuit/builtins/field/bits.rs:33-39` (`fn to_bits_le`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/circuit_var/bits/r1cs.rs`

- [x] **INV-CV-BITS-13: the sizes grow by one constraint and one witness per bit**
  - Covered by: `tests/unit/circuit_var/bits/r1cs.rs` `the_sizes_grow_by_one_constraint_and_one_witness_per_bit`
  - Kind: constraint
  - Statement: `CheckBits<N>` for N in {1, 4, 64, 253} and `FromBits<N>` for N in {1, 4, 64} have exactly N + 1 constraints and N + 2 variables, and `ToBits<N>` for N in {1, 4, 64} exactly 2N + 1 constraints and 2N + 2 variables.
  - Location: `src/circuit/builtins/field/bits.rs:64-91` (`fn range_check`, `fn bits_le`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/bits/r1cs.rs`

- [x] **INV-CV-BITS-14: a constant that passes its check adds nothing**
  - Covered by: `tests/unit/circuit_var/bits/r1cs.rs` `a_constant_that_passes_its_check_adds_nothing`
  - Kind: constraint
  - Statement: `ConstantCheckBits<7, 3>` and `ConstantIsBool<1>` each export exactly 2 variables, 1 private input and no row.
  - Location: `src/circuit/builtins/field/bits.rs:50-91` (`fn assert_bool`, `fn bits_le`, the constant branches)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/bits/r1cs.rs`

- [x] **INV-CV-BITS-15: the bit witnesses follow x**
  - Covered by: `tests/unit/circuit_var/bits/r1cs.rs` `every_honest_bit_claim_checks_and_is_assigned_after_x`
  - Kind: constraint
  - Statement: for every honest 4-bit claim, `CheckBits<4>`'s exported assignment is exactly `[1, x, b0, b1, b2, b3]`, least significant bit first.
  - Location: `src/circuit/builtins/field/bits.rs:73-91` (`fn bits_le`), `src/prover/synthesis.rs:275-278` (`fn assignment_of`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/bits/r1cs.rs`

### Completeness

- [x] **INV-CV-BITS-16: every fitting value and every honest claim satisfies every row**
  - Covered by: `tests/unit/circuit_var/bits/r1cs.rs` `every_fitting_value_checks_one_constraint_per_bit_plus_the_sum`; `tests/unit/circuit_var/bits/r1cs.rs` `every_honest_bit_claim_checks_and_is_assigned_after_x`; `tests/unit/circuit_var/bits/properties.rs` `check_bits_holds_natively_exactly_when_the_value_fits_the_width` (property)
  - Kind: completeness
  - Statement: `check_constraints` returns exactly `Ok(2)`, `Ok(5)` and `Ok(254)` for every fitting value of `CheckBits<1>`, `CheckBits<4>` and `CheckBits<253>`, `Ok(1)` for `CheckIsBool` over 0 and 1, `Ok(9)` and `Ok(5)` for `ToBits<4>` and `FromBits<4>` over every honest claim, and `Ok(65)` for `CheckBits<64>` over every random u64.
  - Location: `src/prover/synthesis.rs:174-202` (`fn check`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/bits/r1cs.rs`, `tests/unit/circuit_var/bits/properties.rs`

### Soundness

- [x] **INV-CV-BITS-17: a value outside the width breaks the sum row whatever boolean bits it takes**
  - Covered by: `tests/unit/circuit_var/bits/r1cs.rs` `a_value_outside_the_width_breaks_the_sum_row_whatever_boolean_bits_it_takes`
  - Kind: soundness
  - Statement: for every width-4 value outside the width and all 16 boolean bit assignments, the first unsatisfied row of `CheckBits<4>` is exactly row 4; for every width-253 value outside the width with all-zero bits, all-one bits and its own low 253 bits, exactly row 253; and for every width-1 value outside the width with the bit 0 or 1, exactly row 1.
  - Location: `src/circuit/builtins/field/bits.rs:73-91` (`fn bits_le`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/circuit_var/bits/r1cs.rs`

- [x] **INV-CV-BITS-18: a non-boolean decomposition that sums to x breaks a booleanity row**
  - Covered by: `tests/unit/circuit_var/bits/r1cs.rs` `a_non_boolean_decomposition_that_sums_to_x_breaks_a_booleanity_row`
  - Kind: soundness
  - Statement: with x = 5, `CheckBits<4>` is satisfied by exactly the honest [1, 0, 1, 0], its first unsatisfied row is exactly row 0 for [3, 1, 0, 0] and [7, -1, 0, 0] and exactly row 1 for [1, 2, 0, 0], and `FromBits<4>` over [3, 1, 0, 0] with the value 5 leaves exactly row 0 first unsatisfied.
  - Location: `src/circuit/builtins/field/bits.rs:50-91` (`fn assert_bool`, `fn bits_le`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/circuit_var/bits/r1cs.rs`

- [x] **INV-CV-BITS-19: no private variable is free in any bits fixture**
  - Covered by: `tests/unit/circuit_var/bits/r1cs.rs` `no_private_variable_is_free_in_any_bits_fixture`
  - Kind: soundness
  - Statement: `check_private_variables` reports no free and no tolerated variable, with exactly 5 constraints over 5 private variables for `CheckBits<4>` over every fitting value, 1 over 1 for `CheckIsBool` over 0 and 1, and 5 over 5 and 9 over 9 for `FromBits<4>` and `ToBits<4>` over every honest claim.
  - Location: `src/prover/synthesis.rs:111-172` (`fn unconstrained_private_variables`), `src/testing.rs:70-99` (`fn check_private_variables`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/circuit_var/bits/r1cs.rs`

- [x] **INV-CV-BITS-20: Picus proves check_bits and Num2Bits deterministic**
  - Covered by: `tests/unit/circuit_var/bits/picus.rs` `picus_finds_check_bits_and_num2bits_deterministic`
  - Kind: soundness
  - Statement: under a 120 s limit Picus reports exactly Safe for `CheckBits<4>`'s Picus export, whose outputs are the four bit witnesses, and exactly Safe for circomlib's `Num2Bits(4)` reference.
  - Location: `src/prover/snarkjs.rs:24-50` (`fn picus_r1cs`), `tests/unit/harness/equivalence.rs` (`fn picus_verdicts`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/circuit_var/bits/picus.rs`

- [x] **INV-CV-BITS-21: Picus proves the claimed bits fixed by x in both**
  - Covered by: `tests/unit/circuit_var/bits/picus.rs` `picus_finds_the_claimed_bits_fixed_by_x_in_both`
  - Kind: soundness
  - Statement: under a 120 s limit Picus reports exactly Safe for `ToBits<4>` with the claimed bits (wires 2..=5) moved to the outputs, and exactly Safe for `to_bits.circom` with `main.bits[0..4]` moved to the outputs.
  - Location: `src/prover/snarkjs.rs:24-50` (`fn picus_r1cs`), `tests/unit/harness/equivalence.rs` (`fn picus_verdicts`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/circuit_var/bits/picus.rs`

- [x] **INV-CV-BITS-22: Picus proves the value fixed by its bits in both**
  - Covered by: `tests/unit/circuit_var/bits/picus.rs` `picus_finds_the_value_fixed_by_its_bits_in_both`
  - Kind: soundness
  - Statement: under a 120 s limit Picus reports exactly Safe for `FromBits<4>` with the value (wire 5) moved to the outputs, and exactly Safe for `from_bits.circom` with `main.value` moved to the outputs.
  - Location: `src/prover/snarkjs.rs:24-50` (`fn picus_r1cs`), `tests/unit/harness/equivalence.rs` (`fn picus_verdicts`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/circuit_var/bits/picus.rs`

- [x] **INV-CV-BITS-23: Picus proves the 1-bit and 5-bit decompositions deterministic**
  - Covered by: `tests/unit/circuit_var/bits/picus.rs` `picus_finds_the_1_and_5_bit_decompositions_deterministic`
  - Kind: soundness
  - Statement: under a 120 s limit Picus reports exactly Safe for the Picus exports of `CheckBits<1>` and `CheckBits<5>`.
  - Location: `src/prover/snarkjs.rs:24-50` (`fn picus_r1cs`), `tests/unit/harness/picus.rs` (`fn verdict_within`)
  - Severity: High
  - Suggested test: external (Picus); `tests/unit/circuit_var/bits/picus.rs`

### Shape

- [x] **INV-CV-BITS-24: the setup and the proving synthesis build the same rows**
  - Covered by: `tests/unit/circuit_var/bits/r1cs.rs` `every_fitting_value_checks_one_constraint_per_bit_plus_the_sum`; `tests/unit/circuit_var/bits/r1cs.rs` `every_honest_bit_claim_checks_and_is_assigned_after_x`
  - Kind: shape
  - Statement: for every fitting value and every honest claim, `check_constraints`, which compares the setup matrices over placeholder inputs with the proving ones, returns exactly the fixture's row count (INV-CV-BITS-16): the width alone fixes the rows, whatever the value is.
  - Location: `src/prover/synthesis.rs:174-202` (`fn check`), `src/client/zk_circuit.rs:9-12` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/bits/r1cs.rs`

### Error

- [x] **INV-CV-BITS-25: a width of 254 or more is refused for every value**
  - Covered by: `tests/unit/circuit_var/bits/native.rs` `a_width_of_254_or_more_is_refused_for_every_value`
  - Kind: error
  - Statement: the native runs of `CheckBits<254>` over 0 and 1, `CheckBits<255>` and `CheckBits<256>` over 0, and `ToBits<254>` over 0 each return exactly `CircuitError.BitWidthTooLarge`, with no rule, located in the fixture's file.
  - Location: `src/circuit/builtins/field/bits.rs:74-76` (`fn bits_le`, the width check)
  - Error: `CircuitErrorKind::BitWidthTooLarge`
  - Severity: High
  - Suggested test: negative; `tests/unit/circuit_var/bits/native.rs`

- [x] **INV-CV-BITS-26: each refusal names the width**
  - Covered by: `tests/unit/circuit_var/bits/native.rs` `each_width_refusal_names_the_width`
  - Kind: error
  - Statement: the messages of `constant(16).check_bits(4)`, `constant(0).check_bits(254)` and `constant(2).check_is_bool()` are exactly "a value does not fit in 4 bits", "a check over 254 bits is too wide; a circuit value holds at most 253 bits" and "a value is neither 0 nor 1".
  - Location: `src/error.rs` (`CircuitErrorKind::ValueTooLarge`, `BitWidthTooLarge`, `NotZeroOrOne`)
  - Severity: Low
  - Suggested test: negative; `tests/unit/circuit_var/bits/native.rs`

- [x] **INV-CV-BITS-27: a constant is checked natively**
  - Covered by: `tests/unit/circuit_var/bits/native.rs` `a_constant_is_checked_when_the_circuit_is_built`
  - Kind: error
  - Statement: the native runs of `ConstantCheckBits<7, 3>` and `ConstantIsBool<1>` return exactly `Ok(())`, of `ConstantCheckBits<8, 3>` exactly `CircuitError.ValueTooLarge`, and of `ConstantIsBool<2>` exactly `CircuitError.NotZeroOrOne`.
  - Location: `src/circuit/builtins/field/bits.rs:50-91` (`fn assert_bool`, `fn bits_le`, the constant branches)
  - Severity: Medium
  - Suggested test: positive + negative; `tests/unit/circuit_var/bits/native.rs`

- [x] **INV-CV-BITS-28: a width of 254 and a failing constant are refused when the circuit is built**
  - Covered by: `tests/unit/circuit_var/bits/r1cs.rs` `a_width_of_254_and_a_failing_constant_are_refused_when_the_circuit_is_built`
  - Kind: error
  - Statement: `export_r1cs` returns exactly `CircuitError.BitWidthTooLarge` for `CheckBits<254>` and `ToBits<254>`, `CircuitError.ValueTooLarge` for `ConstantCheckBits<8, 3>` and `CircuitError.NotZeroOrOne` for `ConstantIsBool<2>`, each located in the fixture's file.
  - Location: `src/circuit/builtins/field/bits.rs:50-91` (`fn assert_bool`, `fn bits_le`), `src/client/zk_circuit.rs:14-25` (`fn export_r1cs`)
  - Severity: Medium
  - Suggested test: negative; `tests/unit/circuit_var/bits/r1cs.rs`

- [x] **INV-CV-BITS-29: the proving rows name the width, bool, bits and sum rules**
  - Covered by: `tests/unit/circuit_var/bits/r1cs.rs` `the_proving_rows_name_the_width_and_bool_rules`
  - Kind: error
  - Statement: `check_tampered` returns exactly `ProverError.ProofInputsBreakRule` at the named row with the named label: for `CheckBits<4>` over 5, x set to 16 at row 4, bit wire 2 set to 2 at row 0, and bit wire 3 set to 1 at row 4, each with "a value does not fit in its bit width"; for `CheckIsBool` over 1, x set to 2 at row 0 with "a value is neither 0 nor 1"; for `FromBits<4>` over 5, bit wire 1 set to 2 at row 0 with the bool rule and the value set to 6 at row 4 with the sum rule; and for `ToBits<4>` over 5, claimed bit wire 2 set to 0 at row 5 with the bits rule and x set to 4 at row 4 with the width rule.
  - Location: `src/testing.rs:43-68` (`fn check_tampered`), `src/circuit/labels.rs:76-88` (`fn check`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/circuit_var/bits/r1cs.rs`

### Equivalence

- [x] **INV-CV-BITS-30: check_bits accepts exactly the values circomlib's Num2Bits accepts**
  - Covered by: `tests/unit/circuit_var/bits/external.rs` `check_bits_accepts_exactly_the_values_circomlib_num2bits_accepts`
  - Kind: equivalence
  - Statement: for every width-4 vector, the SDK native run, the SDK R1CS, circom's witness calculation and circom's R1CS all accept exactly the fitting values, and the sizes are exactly 5 constraints over 6 variables for the SDK and 10 over 11 for `Num2Bits(4)`.
  - Location: `src/circuit/builtins/field/bits.rs:64-91` (`fn range_check`, `fn bits_le`), `tests/unit/circuit_var/bits/check_bits.circom`, `tests/unit/harness/equivalence.rs` (`fn assert_relation_equivalent`)
  - Severity: High
  - Suggested test: external (circomlib); `tests/unit/circuit_var/bits/external.rs`

- [x] **INV-CV-BITS-31: to_bits_le accepts exactly the claims circomlib's Num2Bits accepts**
  - Covered by: `tests/unit/circuit_var/bits/external.rs` `to_bits_le_accepts_exactly_the_claims_circomlib_num2bits_accepts`
  - Kind: equivalence
  - Statement: for every 4-bit claim, the four acceptance checks agree exactly with the claim's validity, and the sizes are exactly 9 constraints over 10 variables for the SDK and 10 over 11 for circom.
  - Location: `src/circuit/builtins/field/bits.rs:33-39` (`fn to_bits_le`), `tests/unit/circuit_var/bits/to_bits.circom`
  - Severity: High
  - Suggested test: external (circomlib); `tests/unit/circuit_var/bits/external.rs`

- [x] **INV-CV-BITS-32: from_bits_le accepts exactly the claims Bits2Num with booleanity accepts**
  - Covered by: `tests/unit/circuit_var/bits/external.rs` `from_bits_le_accepts_exactly_the_claims_circomlib_bits2num_with_booleanity_accepts`
  - Kind: equivalence
  - Statement: for every 4-bit claim, the four acceptance checks agree exactly with the claim's validity, the non-boolean [3, 1, 0, 0] included, and the sizes are exactly 5 constraints over 6 variables for the SDK and 10 over 11 for circom.
  - Location: `src/circuit/builtins/field/bits.rs:41-48` (`fn from_bits_le`), `tests/unit/circuit_var/bits/from_bits.circom`
  - Severity: High
  - Suggested test: external (circomlib); `tests/unit/circuit_var/bits/external.rs`

- [x] **INV-CV-BITS-33: check_is_bool is row for row the circom booleanity constraint**
  - Covered by: `tests/unit/circuit_var/bits/external.rs` `check_is_bool_is_row_for_row_the_circom_booleanity_constraint`
  - Kind: equivalence
  - Statement: the SDK and `is_bool.circom` have exactly the same header and label map, both normalize to exactly the one product A = {0: 1, 1: -1}, B = {1: 1}, C = {}, both accept exactly 0 and 1 of the bool vectors, and circom's witness for 0 and 1 is exactly the SDK's assignment.
  - Location: `src/circuit/builtins/field/bits.rs:50-62` (`fn assert_bool`), `tests/unit/circuit_var/bits/is_bool.circom`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/circuit_var/bits/external.rs`

- [x] **INV-CV-BITS-34: the Picus export makes the bit witnesses its outputs**
  - Covered by: `tests/unit/circuit_var/bits/picus.rs` `the_picus_export_makes_the_bit_witnesses_its_outputs`
  - Kind: equivalence
  - Statement: `CheckBits<4>`'s `export_picus_r1cs` header is exactly 6 variables, 4 public outputs, 1 private input and 5 constraints with the wire labels `[0, 2, 3, 4, 5, 1]`.
  - Location: `src/prover/snarkjs.rs:24-50` (`fn picus_r1cs`)
  - Severity: High
  - Suggested test: external (Picus); `tests/unit/circuit_var/bits/picus.rs`

### Interop

- [x] **INV-CV-BITS-35: snarkjs wtns check accepts the check_bits pair and rejects each flipped bit**
  - Covered by: `tests/unit/circuit_var/bits/external.rs` `snarkjs_accepts_the_check_bits_pair_and_rejects_each_flipped_bit`
  - Kind: interop
  - Statement: for every fitting width-4 value, `snarkjs wtns check` accepts `CheckBits<4>`'s R1CS with the SDK assignment and rejects it with each of the four bit witnesses flipped to 1 minus the bit.
  - Location: `src/prover/snarkjs.rs:13-124` (`fn r1cs`, `fn wtns`)
  - Severity: Critical
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/bits/external.rs`

- [x] **INV-CV-BITS-36: snarkjs Groth16 proves and verifies a 253-bit range check**
  - Covered by: `tests/unit/circuit_var/bits/external.rs` `snarkjs_proves_and_verifies_a_253_bit_range_check`
  - Kind: interop
  - Statement: `CheckBits<253>` over 2^253 - 1 exports exactly a 255-wire `.wtns`, and `snarkjs groth16 setup`, `prove` and `verify` accept it with exactly the empty public signal list.
  - Location: `src/prover/snarkjs.rs:13-124` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/circuit_var/bits/external.rs`

### Generated Boolean membership

- [x] **INV-CV-BITS-37: generated Boolean checks admit exactly the host field members 0 and 1**
  - Covered by: `tests/unit/circuit_var/bits/properties.rs` `generated_boolean_checks_accept_exactly_zero_and_one` (property)
  - Kind: soundness
  - Statement: for every generated non-Boolean canonical field value together with the explicitly included values 0 and 1, the accepted native and exported-row relation is exactly membership in the host field set {0,1}; a rejected native value returns exactly `NotZeroOrOne` at the fixture, and a rejected proving witness fails exactly row 0 with the Booleanity rule.
  - Location: `src/circuit/builtins/field/bits.rs:28-30` (`check_is_bool`), `src/circuit/builtins/field/bits.rs:52-64` (`assert_bool`)
  - Error: `CircuitErrorKind::NotZeroOrOne`, `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: positive + negative + property; `tests/unit/circuit_var/bits/properties.rs`

## Constants (`constant`, `zero`, `value`)

`constant(value: impl Into<Field>)` builds a constant `CircuitVar`, `zero()` is `constant(0)`,
and `value(&var)` returns a constant's field value and otherwise
`CircuitError.ReadsVariableValue` at the caller's line. The tests sit in
`tests/unit/circuit_var/neg/constants.rs` and reuse negation's vectors and file:
`EqualsSeven` asserts `constant(7) == value`, and `ReadsValue` returns `value(&self.value)`
read in `fixtures::read`, which also returns the line of the read.

### Semantics

- [x] **INV-CV-CONST-01: a constant holds exactly its field value and prints as a constant**
  - Covered by: `tests/unit/circuit_var/neg/constants.rs` `a_constant_holds_exactly_its_field_value_and_prints_as_a_constant`
  - Kind: semantics
  - Statement: for every value and every negation of the negation vectors, `value(&constant(x))` is exactly `Ok(x)` and the constant's `Debug` form is exactly `CircuitVar::constant(<x>)`.
  - Location: `src/circuit/builtins/field/var.rs:86-108` (`fmt::Debug for CircuitVar`, `fn constant`, `fn value`)
  - Severity: High
  - Suggested test: positive; `tests/unit/circuit_var/neg/constants.rs`

- [x] **INV-CV-CONST-02: constant takes every integer width and a bool**
  - Covered by: `tests/unit/circuit_var/neg/constants.rs` `constant_takes_every_integer_width_and_a_bool`
  - Kind: semantics
  - Statement: `value(&constant(v))` is exactly 255, 65535, 4294967295, 18446744073709551615, 340282366920938463463374607431768211455, 1 and 0 for `u8::MAX`, `u16::MAX`, `u32::MAX`, `u64::MAX`, `u128::MAX`, `true` and `false`.
  - Location: `src/circuit/builtins/field/var.rs:95-97` (`fn constant`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/circuit_var/neg/constants.rs`

- [x] **INV-CV-CONST-03: zero is exactly the constant zero**
  - Covered by: `tests/unit/circuit_var/neg/constants.rs` `zero_is_exactly_the_constant_zero`
  - Kind: semantics
  - Statement: `zero()`'s `Debug` form is exactly `constant(0)`'s, and its value is exactly 0.
  - Location: `src/circuit/builtins/field/var.rs:99-101` (`fn zero`)
  - Severity: Low
  - Suggested test: positive; `tests/unit/circuit_var/neg/constants.rs`

### Constraint

- [x] **INV-CV-CONST-04: a constant operand puts its value on variable 0 and allocates nothing**
  - Covered by: `tests/unit/circuit_var/neg/constants.rs` `a_constant_operand_puts_its_value_on_variable_zero_and_allocates_nothing`
  - Kind: constraint
  - Statement: `EqualsSeven` exports exactly 2 variables, 1 private input and the one row A = {0: 7, 1: -1}, B = {0: 1}, C = {}; `check_constraints` with the value 7 returns exactly `Ok(1)`, and the native run with 8 exactly `CircuitError.RuleBroken` with the fixture's rule, in the fixture's file.
  - Location: `src/circuit/builtins/field/var.rs:95-97` (`fn constant`), `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Severity: Medium
  - Suggested test: positive + negative; `tests/unit/circuit_var/neg/constants.rs`

### Error

- [x] **INV-CV-CONST-05: reading a proof input fails in R1CS at the line of the read**
  - Covered by: `tests/unit/circuit_var/neg/constants.rs` `reading_a_proof_input_fails_in_r1cs_at_the_line_of_the_read`
  - Kind: error
  - Statement: `ReadsValue`'s `check_constraints`, `export_r1cs` and `export_assignment` each return exactly `CircuitError.ReadsVariableValue` located in the fixture's file at exactly the line of the `value` call in `fixtures::read`: no R1CS run can branch on a proof input.
  - Location: `src/circuit/builtins/field/var.rs:103-108` (`fn value`)
  - Error: `CircuitErrorKind::ReadsVariableValue`
  - Severity: High
  - Suggested test: negative; `tests/unit/circuit_var/neg/constants.rs`

- [x] **INV-CV-CONST-06: native proof inputs are readable constants**
  - Covered by: `tests/unit/circuit_var/neg/constants.rs` `reading_a_proof_input_natively_returns_its_constant_value`
  - Kind: semantics
  - Statement: for the canonical proof-input values 0, 1, 3 and p-1, the native allocator represents each input as a constant: reading it returns exactly that value, and native execution of `ReadsValue` returns exactly `Ok(())`. INV-CV-CONST-05 separately pins rejection during R1CS setup, assignment export and constraint checking.
  - Location: `src/conversion/mod.rs` (`Allocator::witness`), `src/circuit/builtins/field/var.rs` (`value`)
  - Severity: Medium
  - Suggested test: positive characterization; `tests/unit/circuit_var/neg/constants.rs`

### Generated constant values

- [x] **INV-CV-CONST-07: generated constants round-trip through value and zero identity**
  - Covered by: `tests/unit/circuit_var/neg/constants.rs` `generated_constants_round_trip_with_zero_and_keep_their_representation` (property)
  - Kind: semantics
  - Statement: for every generated canonical field value x, `value(constant(x))` and the values after adding `zero()` on either side are exactly x; the original constant's native representation is exactly `CircuitVar::constant(x)` before and after the read.
  - Location: `src/circuit/builtins/field/var.rs:134-160` (`CircuitVar::fmt`, `constant`, `zero`, `value`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/circuit_var/neg/constants.rs`
