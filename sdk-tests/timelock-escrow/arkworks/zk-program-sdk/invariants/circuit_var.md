# CircuitVar Invariants

Covers the `CircuitVar` operators of `src/circuit/builtins/field/var.rs`. For now only
addition (`INV-CV-ADD`); `-`, `*`, unary `-`, `inverse`, `div` and `pow` follow the same
pattern. Invariants every builtin shares live in `cross-cutting.md`.

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
