# Assert and Select Invariants

Covers the `Assert` and `Select` traits of `src/circuit/builtins/ops/`: the trait-level
helpers and the `CircuitVar` and array impls. The impls for `Bool`, `Uint`, `Bytes` and
the protocol types are in their own files. Invariants every builtin shares live in
`cross-cutting.md`. ID prefixes: `INV-ASSERT`, `INV-SELECT`; the tests live in
`tests/unit/ops/`.

## Assert (`is_equal`, `assert_equal`, `assert_equal_if`, `assert_not_equal`, `all_equal`, `assert_all_equal`, `assert_all_equal_if`, `assert_equal_unless`)

The fixtures in `tests/unit/ops/assert/fixtures.rs` take `left` and `right` as field proof
inputs (variables 1 and 2) and, where a condition is involved, `condition` as a `bool` proof
input, which adds its own row `c * (c - 1) = 0` labelled "a bool proof input is neither 0 nor
1". `AssertEqual` asserts `left == right` with the rule "the sides are equal", `IsEqual`
asserts `is_equal(left, right) == claimed` with "the claim is whether the sides are equal",
`AssertNotEqual` asserts `left != right` with "the sides differ", and `AssertEqualIf` asserts
`left == right` if `condition`. `AssertEqualIfConstant<C>` does so under `Bool::constant(C)`,
`ConditionInCircuit` under a constant taken from a proof input whose placeholder is `false`,
`AssertEqualIfItself` asserts `left == left` if `condition`, and `EqualConstantsIf` and
`ConstantsIf` assert `3 == 3` and `3 == 5` if `condition`. The array fixtures do the same over
`[Field; N]`: `[T; N]` has no `assert_not_equal` of its own, so `ArrayAssertNotEqual` covers the
trait's default `is_equal(..)?.assert_false(rule)` and, through it, `all_equal`. The equal pairs
are 0, 1, p - 1, 2^64 and x on both sides; the different pairs are 0 and 1, 1 and 0, 0 and
p - 1, (p - 1) / 2 and (p + 1) / 2, 2^253 and 2^64, x and -x, and 1 and 2. The arrays of
length 3 are equal, differ in the first, middle or last element, differ everywhere, or hold
swapped elements. `assert_equal_unless` is crate-private: its only public route is the owner
tag check of `client::Owner`'s `ProofInput`, which never skips (`Boolean::FALSE`).

### Semantics

- [x] **INV-ASSERT-01: the native is_equal of two constants is the constant 1 exactly when they are equal**
  - Covered by: `tests/unit/ops/assert/native.rs` `is_equal_of_constants_is_the_constant_one_exactly_when_the_sides_are_equal`; `tests/unit/ops/assert/properties.rs` `natively_each_assertion_holds_exactly_when_its_relation_does` (property)
  - Kind: semantics
  - Statement: for every pair of field elements, the native `CircuitVar::from(left.is_equal(&right)?)` is exactly `CircuitVar::constant(1)` when left = right and exactly `CircuitVar::constant(0)` otherwise.
  - Location: `src/circuit/builtins/ops/assert.rs:32-35` (`fn is_equal`), `src/circuit/builtins/types/boolean.rs:22-26` (`fn of_equality`), `src/circuit/builtins/field/primitive.rs:88-100` (`fn equals`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/ops/assert/native.rs`, `tests/unit/ops/assert/properties.rs`

- [x] **INV-ASSERT-02: native assert_equal holds exactly for equal constants**
  - Covered by: `tests/unit/ops/assert/native.rs` `assert_equal_holds_natively_exactly_for_equal_sides`; `tests/unit/ops/assert/properties.rs` `natively_each_assertion_holds_exactly_when_its_relation_does` (property)
  - Kind: semantics
  - Statement: for every pair of constants, the native `left.assert_equal(&right, rule)` returns exactly `Ok(())` when left = right; every other pair is refused (INV-ASSERT-36).
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`, the constant branch)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/ops/assert/native.rs`, `tests/unit/ops/assert/properties.rs`

- [x] **INV-ASSERT-03: native assert_not_equal holds exactly for different constants**
  - Covered by: `tests/unit/ops/assert/native.rs` `assert_not_equal_holds_natively_exactly_for_different_sides`; `tests/unit/ops/assert/properties.rs` `natively_each_assertion_holds_exactly_when_its_relation_does` (property)
  - Kind: semantics
  - Statement: for every pair of constants, the native `left.assert_not_equal(&right, rule)` returns exactly `Ok(())` when left != right; every equal pair is refused (INV-ASSERT-36).
  - Location: `src/circuit/builtins/ops/assert.rs:70-87` (`fn assert_not_equal`, the constant branch)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/ops/assert/native.rs`, `tests/unit/ops/assert/properties.rs`

- [x] **INV-ASSERT-04: under a false condition native assert_equal_if holds for every pair**
  - Covered by: `tests/unit/ops/assert/native.rs` `assert_equal_if_holds_natively_for_every_pair_under_false_and_for_equal_sides_under_true`; `tests/unit/ops/assert/native.rs` `assert_equal_if_on_constant_sides_holds_natively_unless_they_differ_under_true`; `tests/unit/ops/assert/properties.rs` `natively_each_assertion_holds_exactly_when_its_relation_does` (property)
  - Kind: semantics
  - Statement: for every equal and every different pair, `assert_equal_if` with the condition false returns exactly `Ok(())` natively, whether the condition is a `bool` proof input, `Bool::constant(false)` or a constant from a proof input, and so does `constant(3).assert_equal_if(&constant(5), ..)`.
  - Location: `src/circuit/builtins/ops/assert.rs:51-68` (`fn assert_equal_if`, the constant-condition branch)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/ops/assert/native.rs`, `tests/unit/ops/assert/properties.rs`

- [x] **INV-ASSERT-05: under a true condition native assert_equal_if holds exactly for equal sides**
  - Covered by: `tests/unit/ops/assert/native.rs` `assert_equal_if_holds_natively_for_every_pair_under_false_and_for_equal_sides_under_true`; `tests/unit/ops/assert/native.rs` `assert_equal_if_on_constant_sides_holds_natively_unless_they_differ_under_true`; `tests/unit/ops/assert/properties.rs` `natively_each_assertion_holds_exactly_when_its_relation_does` (property)
  - Kind: semantics
  - Statement: for every pair, `assert_equal_if` with the condition true in each of the three condition forms returns exactly `Ok(())` when the sides are equal and exactly the fixture's `RuleBroken` otherwise: `3 == 3` holds and `3 == 5` is refused.
  - Location: `src/circuit/builtins/ops/assert.rs:51-68` (`fn assert_equal_if`)
  - Severity: High
  - Suggested test: positive + negative + property; `tests/unit/ops/assert/native.rs`, `tests/unit/ops/assert/properties.rs`

- [x] **INV-ASSERT-06: the native array is_equal is 1 exactly when every element pair is equal**
  - Covered by: `tests/unit/ops/assert/native.rs` `array_assertions_hold_natively_exactly_when_every_element_pair_is_equal`; `tests/unit/ops/assert/native.rs` `a_one_element_array_is_equal_exactly_when_its_element_is`; `tests/unit/ops/assert/properties.rs` `natively_arrays_are_equal_exactly_when_every_element_is` (property)
  - Kind: semantics
  - Statement: for every pair of `[Field; 3]` arrays, the native array `is_equal` is exactly `CircuitVar::constant(1)` when every element pair is equal and exactly `CircuitVar::constant(0)` otherwise, including swapped elements; for every pair of one-element arrays it is exactly the `is_equal` of the elements.
  - Location: `src/circuit/builtins/ops/assert.rs:90-94` (`fn is_equal` for `[T; N]`), `src/circuit/builtins/ops/assert.rs:112-119` (`fn all_equal`), `src/circuit/builtins/types/boolean.rs:60-68` (`fn all`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/ops/assert/native.rs`, `tests/unit/ops/assert/properties.rs`

- [x] **INV-ASSERT-07: native array assertions are element-wise**
  - Covered by: `tests/unit/ops/assert/native.rs` `array_assertions_hold_natively_exactly_when_every_element_pair_is_equal`; `tests/unit/ops/assert/properties.rs` `natively_arrays_are_equal_exactly_when_every_element_is` (property)
  - Kind: semantics
  - Statement: for every array vector, the native array `assert_equal` and `assert_equal_if` under true hold exactly when every element pair is equal, `assert_equal_if` under false holds for every vector, and the default `assert_not_equal` holds exactly when some element pair differs.
  - Location: `src/circuit/builtins/ops/assert.rs:90-110` (`impl Assert for [T; N]`), `src/circuit/builtins/ops/assert.rs:121-144` (`fn assert_all_equal`, `fn assert_all_equal_if`), `src/circuit/builtins/ops/assert.rs:25-28` (the default `fn assert_not_equal`)
  - Severity: High
  - Suggested test: positive + negative + property; `tests/unit/ops/assert/native.rs`, `tests/unit/ops/assert/properties.rs`

- [x] **INV-ASSERT-08: empty arrays are equal**
  - Covered by: `tests/unit/ops/assert/native.rs` `empty_arrays_are_always_equal_natively`
  - Kind: semantics
  - Statement: for `N = 0`, the native array `is_equal` is exactly `CircuitVar::constant(1)`, `assert_equal` and `assert_equal_if` under both conditions return exactly `Ok(())`, and `assert_not_equal` returns exactly `RuleBroken` with the fixture's rule.
  - Location: `src/circuit/builtins/ops/assert.rs:112-119` (`fn all_equal`), `src/circuit/builtins/types/boolean.rs:60-68` (`fn all`, the empty case)
  - Severity: Medium
  - Suggested test: positive + negative; `tests/unit/ops/assert/native.rs`

- [x] **INV-ASSERT-09: assert_equal_unless that never skips refuses every owner tag but S and P**
  - Covered by: `tests/unit/ops/assert/native.rs` `assert_equal_unless_never_skipping_refuses_every_owner_tag_but_s_and_p_natively`
  - Kind: semantics
  - Statement: for every owner tag, instantiating a `client::Owner` natively returns exactly `Ok` for the tags `S` (0x53) and `P` (0x50) and exactly `RuleBroken` with the rule "the owner tag is neither S nor P", located in `src/conversion/owner.rs`, for 0, `Q`, `T` and 255.
  - Location: `src/circuit/builtins/ops/assert.rs:146-163` (`fn assert_equal_unless`), `src/circuit/protocol/owner.rs:27-46` (`fn new`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/ops/assert/native.rs`

### Constraint

- [x] **INV-ASSERT-10: assert_equal on two variables exports exactly one row and allocates no variable**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `assert_equal_on_two_variables_exports_exactly_one_row_and_no_variable`
  - Kind: constraint
  - Statement: the R1CS of `left.assert_equal(&right, rule)` is exactly one row A = {1: 1, 2: -1}, B = {0: 1}, C = {} under the header of 3 variables, 2 private inputs and 1 constraint, and the exported assignment is exactly `[1, left, right]`.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`), `src/circuit/builtins/field/primitive.rs:107-109` (`fn enforce_equal`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-11: is_equal adds exactly two rows and two private variables**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `is_equal_adds_exactly_two_rows_and_two_private_variables`
  - Kind: constraint
  - Statement: a circuit that only computes `left.is_equal(&right)` exports exactly 5 variables and the two rows `(left - right) * h = n` and `(left - right) * (1 - n) = 0`, with n the inequality bit (variable 3) and h the inverse hint (variable 4); the returned `Bool` is the linear combination `1 - n`.
  - Location: `src/circuit/builtins/types/boolean.rs:22-26` (`fn of_equality`), `src/circuit/builtins/field/primitive.rs:88-100` (`fn equals`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-12: the is_equal claim exports exactly the golden rows**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `the_is_equal_claim_exports_exactly_the_golden_rows`
  - Kind: constraint
  - Statement: `IsEqual` exports exactly 6 variables and 3 rows: the two rows of INV-ASSERT-11 over n = 4 and h = 5, then A = {0: 1, 3: -1, 4: -1}, B = {0: 1}, C = {}, the claim `1 - n = claimed`.
  - Location: `src/circuit/builtins/ops/assert.rs:32-49` (`fn is_equal`, `fn assert_equal`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-13: the is_equal witnesses are the inequality bit and the inverse hint**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `the_is_equal_assignment_holds_the_inequality_bit_and_the_inverse_hint`
  - Kind: constraint
  - Statement: for every equal pair the `IsEqual` assignment is exactly `[1, left, right, 1, 0, 1]`, and for every different pair exactly `[1, left, right, 0, 1, (left - right)^-1]`.
  - Location: `src/circuit/builtins/field/primitive.rs:88-100` (`fn equals`, arkworks `is_neq`)
  - Severity: High
  - Suggested test: positive; `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-14: assert_equal_if with a variable condition adds exactly one product row**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `assert_equal_if_exports_the_condition_row_then_exactly_one_product_row`
  - Kind: constraint
  - Statement: `AssertEqualIf` exports exactly 4 variables and 2 rows: the condition's boolean row, then A = {1: 1, 2: -1}, B = {3: 1}, C = {}, the row `(left - right) * condition = 0`; `assert_equal_if` allocates no variable.
  - Location: `src/circuit/builtins/ops/assert.rs:51-68` (`fn assert_equal_if`, the last arm), `src/circuit/builtins/field/primitive.rs:119-121` (`fn enforce_product`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-15: a false constant condition adds no row**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `a_false_constant_condition_exports_no_row_and_a_true_one_exactly_assert_equal`
  - Kind: constraint
  - Statement: `assert_equal_if` under `Bool::constant(false)` exports exactly 3 variables and 0 constraints.
  - Location: `src/circuit/builtins/ops/assert.rs:61` (`fn assert_equal_if`, the false-constant arm)
  - Severity: High
  - Suggested test: positive (golden rows); `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-16: a true constant condition is exactly assert_equal**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `a_false_constant_condition_exports_no_row_and_a_true_one_exactly_assert_equal`
  - Kind: constraint
  - Statement: `assert_equal_if` under `Bool::constant(true)` exports a `.r1cs` file byte-identical to `AssertEqual`'s.
  - Location: `src/circuit/builtins/ops/assert.rs:62` (`fn assert_equal_if`, the true-constant arm)
  - Severity: High
  - Suggested test: positive; `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-17: equal constant sides add no row under a variable condition**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `constant_sides_export_no_row_when_equal_and_force_the_condition_false_when_different`
  - Kind: constraint
  - Statement: `constant(3).assert_equal_if(&constant(3), &condition, rule)` exports exactly the condition's boolean row and nothing else.
  - Location: `src/circuit/builtins/ops/assert.rs:63` (`fn assert_equal_if`, the zero-difference arm)
  - Severity: Medium
  - Suggested test: positive (golden rows); `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-18: different constant sides force the condition false**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `constant_sides_export_no_row_when_equal_and_force_the_condition_false_when_different`
  - Kind: constraint
  - Statement: `constant(3).assert_equal_if(&constant(5), &condition, rule)` exports exactly the condition's boolean row and A = {1: 2}, B = {0: 1}, C = {}, the row `2 * condition = 0`.
  - Location: `src/circuit/builtins/ops/assert.rs:64-66` (`fn assert_equal_if`, the last arm)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-19: a variable asserted against itself exports an empty product row**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `a_variable_asserted_against_itself_under_a_variable_condition_exports_an_empty_row`
  - Kind: constraint
  - Statement: `left.assert_equal_if(&left, &condition, rule)` exports exactly the condition's boolean row and A = {}, B = {2: 1}, C = {}: `left - left` is a linear combination, not a constant, so the zero-difference arm is not taken and the row `0 * condition = 0` holds for every assignment: it costs a constraint and restricts no variable.
  - Location: `src/circuit/builtins/ops/assert.rs:58-66` (`fn assert_equal_if`), `src/circuit/builtins/field/primitive.rs:26-31` (`fn constant_value`)
  - Severity: Medium
  - Suggested test: positive (golden rows); `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-20: assert_not_equal adds exactly one row and one inverse variable**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `assert_not_equal_exports_exactly_one_row_and_one_inverse_variable`
  - Kind: constraint
  - Statement: `AssertNotEqual` exports exactly 4 variables and one row A = {1: 1, 2: -1}, B = {3: 1}, C = {0: 1}, the row `(left - right) * inverse = 1`.
  - Location: `src/circuit/builtins/ops/assert.rs:70-87` (`fn assert_not_equal`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-21: the assert_not_equal hint is exactly the inverse of the difference**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `the_assert_not_equal_hint_is_exactly_the_inverse_of_the_difference`; `tests/unit/ops/assert/properties.rs` `the_inverse_hint_proves_every_different_pair_and_nothing_proves_an_equal_one` (property)
  - Kind: constraint
  - Statement: for every different pair, the `AssertNotEqual` assignment is exactly `[1, left, right, (left - right)^-1]`.
  - Location: `src/circuit/builtins/ops/assert.rs:82-84` (the inverse witness)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/ops/assert/r1cs.rs`, `tests/unit/ops/assert/properties.rs`

- [x] **INV-ASSERT-22: array assert_equal and assert_equal_if export one row per element**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `array_assert_equal_exports_exactly_one_row_per_element`; `tests/unit/ops/assert/r1cs.rs` `array_assert_equal_if_exports_the_condition_row_then_one_product_row_per_element`
  - Kind: constraint
  - Statement: for `N = 3`, the array `assert_equal` exports exactly the rows A = {1 + i: 1, 4 + i: -1}, B = {0: 1}, C = {} for i = 0, 1, 2 in order, and the array `assert_equal_if` exports exactly the condition's boolean row then A = {1 + i: 1, 4 + i: -1}, B = {7: 1}, C = {}; for `N = 0` the array `assert_equal` exports exactly 1 variable and 0 constraints.
  - Location: `src/circuit/builtins/ops/assert.rs:121-144` (`fn assert_all_equal`, `fn assert_all_equal_if`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-23: the array is_equal tests each pair, then the sum of their bits**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `array_is_equal_of_two_elements_tests_each_pair_then_their_sum`
  - Kind: constraint
  - Statement: for `N = 2`, `ArrayIsEqual` exports exactly 12 variables and 7 rows: the two `is_equal` rows of each element pair (bits 6 and 8, hints 7 and 9), the two `is_equal` rows of the bit sum n6 + n8 against 0 (bit 10, hint 11), and the claim A = {0: 1, 5: -1, 10: -1}.
  - Location: `src/circuit/builtins/ops/assert.rs:112-119` (`fn all_equal`), `src/circuit/builtins/types/boolean.rs:60-68` (`fn all`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-24: array equality costs two rows per element plus two for the conjunction**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `array_equality_costs_two_rows_per_element_plus_two_for_the_conjunction`
  - Kind: constraint
  - Statement: `ArrayIsEqual<N>` exports exactly (constraints, variables) (1, 2), (3, 6), (7, 12) and (9, 16) for N = 0, 1, 2 and 3, and `ArrayAssertNotEqual<N>` exactly (3, 5), (7, 11) and (9, 15) for N = 1, 2 and 3: 2 rows and 2 variables per element, 2 more once N is at least 2, and 1 for the claim or `assert_false`.
  - Location: `src/circuit/builtins/ops/assert.rs:112-119` (`fn all_equal`), `src/circuit/builtins/ops/assert.rs:25-28` (the default `fn assert_not_equal`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/ops/assert/r1cs.rs`

### Completeness

- [x] **INV-ASSERT-25: every honest pair satisfies every row**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `every_honest_pair_satisfies_every_exported_row_and_checks_every_proving_row`; `tests/unit/ops/assert/properties.rs` `every_honest_equality_claim_checks_three_rows_and_the_other_claim_breaks_the_last` (property); `tests/unit/ops/assert/properties.rs` `the_inverse_hint_proves_every_different_pair_and_nothing_proves_an_equal_one` (property)
  - Kind: completeness
  - Statement: for every equal pair the assignments of `AssertEqual`, `IsEqual` claiming 1, `AssertEqualIf` under false and true and `AssertEqualIfConstant<true>`, and for every different pair those of `IsEqual` claiming 0, `AssertEqualIf` under false, `AssertEqualIfConstant<false>` and `AssertNotEqual`, leave no exported row unsatisfied, and `check_constraints` returns exactly 1, 3, 2, 2, 1 and 3, 2, 0, 1.
  - Location: `src/prover/synthesis.rs` (`fn check_constraints`), `src/prover/snarkjs.rs` (`fn wtns`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/ops/assert/r1cs.rs`, `tests/unit/ops/assert/properties.rs`

- [x] **INV-ASSERT-26: every honest array pair satisfies every row**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `every_honest_array_pair_satisfies_every_exported_row_and_checks_every_proving_row`
  - Kind: completeness
  - Statement: for every array vector, the honest assignments of `ArrayIsEqual<3>` and `ArrayAssertEqualIf<3>` under false, plus `ArrayAssertEqual<3>` and `ArrayAssertEqualIf<3>` under true for the equal vector and `ArrayAssertNotEqual<3>` for the others, leave no exported row unsatisfied, and `check_constraints` returns exactly 9, 4, 3, 4 and 9.
  - Location: `src/circuit/builtins/ops/assert.rs:90-144` (`impl Assert for [T; N]` and its helpers)
  - Severity: High
  - Suggested test: positive; `tests/unit/ops/assert/r1cs.rs`

### Soundness

- [x] **INV-ASSERT-27: every different right side breaks the assert_equal row**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `every_different_right_side_breaks_exactly_row_0_of_assert_equal`
  - Kind: soundness
  - Statement: for every different pair, `[1, left, right]` leaves exactly row 0 of `AssertEqual`'s export unsatisfied, and tampering the right side of the honest x = x fixture to that pair's right side is refused at row 0 by `AssertEqual` and `AssertEqualIfConstant<true>`.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-28: no inverse proves equal sides different**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `no_inverse_proves_equal_sides_different`; `tests/unit/ops/assert/properties.rs` `the_inverse_hint_proves_every_different_pair_and_nothing_proves_an_equal_one` (property)
  - Kind: soundness
  - Statement: for every equal pair and every inverse value (0, 1, p - 1, x and random values), `[1, left, left, inverse]` leaves exactly row 0 of `AssertNotEqual`'s export unsatisfied; for every different pair, tampering right to left or the inverse to any other value is refused at row 0.
  - Location: `src/circuit/builtins/ops/assert.rs:70-87` (`fn assert_not_equal`)
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/ops/assert/r1cs.rs`, `tests/unit/ops/assert/properties.rs`

- [x] **INV-ASSERT-29: no witness flips an equality claim**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `no_witness_flips_an_equality_claim`; `tests/unit/ops/assert/properties.rs` `every_honest_equality_claim_checks_three_rows_and_the_other_claim_breaks_the_last` (property)
  - Kind: soundness
  - Statement: for every equal pair, claiming 0 with inequality bit 1 leaves row 0 unsatisfied for every hint (0, 1, p - 1, x); for every different pair, claiming 1 with bit 0 leaves row 1 unsatisfied under hint 0 and row 0 under every other hint; with the honest bit and hint, every claim other than the honest one (the flipped bit and 2) leaves exactly row 2 unsatisfied.
  - Location: `src/circuit/builtins/field/primitive.rs:88-100` (`fn equals`)
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/ops/assert/r1cs.rs`, `tests/unit/ops/assert/properties.rs`

- [x] **INV-ASSERT-30: a false condition leaves both sides free and a true one leaves neither free**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `a_false_condition_binds_neither_side_and_a_true_one_binds_both`; `tests/unit/ops/assert/picus.rs` `picus_finds_the_right_side_free_whenever_the_condition_can_be_false`; `tests/unit/ops/assert/picus.rs` `picus_finds_every_binding_assertion_deterministic`
  - Kind: soundness
  - Statement: for every different pair under a false condition (variable or constant), `check_private_variables` reports exactly `left` and `right` free and a tampered right side is accepted; for every equal pair under a true variable condition it reports no free variable and a tampered right side is refused at row 1; Picus reports right exactly Unsafe for `AssertEqualIf` and `AssertEqualIfConstant<false>` and exactly Safe for `AssertEqualIfConstant<true>`.
  - Location: `src/circuit/builtins/ops/assert.rs:51-68` (`fn assert_equal_if`)
  - Severity: Critical
  - Suggested test: negative + external (Picus); `tests/unit/ops/assert/r1cs.rs`, `tests/unit/ops/assert/picus.rs`

- [x] **INV-ASSERT-31: a true condition on different sides breaks the product row**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `a_true_condition_on_different_sides_breaks_the_product_row`; `tests/unit/ops/assert/external.rs` `both_assert_equal_if_circuits_refuse_a_condition_of_two`
  - Kind: soundness
  - Statement: for every different pair, tampering the condition of an honest `AssertEqualIf` from 0 to 1 is refused at row 1 with the fixture's rule and to 2 at row 0 with the bool rule; tampering `ConstantsIf`'s condition from 0 to 1 is refused at row 1.
  - Location: `src/circuit/builtins/ops/assert.rs:64-66` (`fn assert_equal_if`), `src/conversion/var.rs:134-146` (`impl ProofInput for bool`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-32: no private variable is free in an unconditional assertion**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `no_private_variable_is_free_when_the_assertion_binds`; `tests/unit/ops/assert/picus.rs` `picus_finds_every_binding_assertion_deterministic`
  - Kind: soundness
  - Statement: `check_private_variables` reports no free variable for `AssertEqual` on every equal pair and for `AssertNotEqual` and `IsEqual` on every different pair; on every equal pair `IsEqual`'s only unconstrained variable is the hint (variable 4), reported exactly as tolerated with role `Multiplier`; Picus reports exactly Safe for `AssertEqual` with right promoted, `AssertNotEqual` with its inverse as output, `IsEqual` and `ArrayIsEqual<2>` with the claim promoted, `ArrayAssertEqual<3>` with every right element promoted and `ArrayAssertNotEqual<2>`.
  - Location: `src/testing.rs` (`fn check_private_variables`), `src/prover/snarkjs.rs` (`fn picus_r1cs`)
  - Severity: Critical
  - Suggested test: negative + external (Picus); `tests/unit/ops/assert/r1cs.rs`, `tests/unit/ops/assert/picus.rs`

- [x] **INV-ASSERT-33: a tampered array element breaks exactly its own row**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `a_tampered_array_element_breaks_exactly_its_own_row`
  - Kind: soundness
  - Statement: for the equal array vector, tampering right element i is refused at row i by `ArrayAssertEqual<3>` and at row 1 + i by `ArrayAssertEqualIf<3>` under true, and tampering `ArrayIsEqual<3>`'s claim to 0 at row 8 with the claim rule; tampering the only differing element of `ArrayAssertNotEqual<3>` back to equal is refused at row 0 inside "an equality test"; setting `ArrayAssertEqualIf<3>`'s condition to 0 is accepted.
  - Location: `src/circuit/builtins/ops/assert.rs:112-144` (`fn all_equal`, `fn assert_all_equal`, `fn assert_all_equal_if`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-49: assert_equal_unless with a variable skip forces the sides equal exactly when skip is false**
  - Covered by: `tests/unit/protocol/token/r1cs.rs` `variable_skip_row_binds_the_trailing_asset_byte_exactly_when_the_input_is_not_dummy`; `tests/unit/protocol/utxo/r1cs.rs` `the_tag_check_is_skipped_exactly_for_a_dummy_input`
  - Kind: soundness
  - Statement: the trailing asset-byte comparison of the second token input exports exactly `(right - left) * non_dummy = 0` under the asset rule, where the existing equality-test witness is 1 for a real input and 0 for a dummy. The pinned row accepts all equal operands and all skipped operands, and refuses unequal operands when enabled; the owner-tag check accepts every byte-valued tag for a dummy and only S/P for a real input. The skip adds no negation row: the dummy test already stores the not-equal witness.
  - Location: `src/circuit/builtins/ops/assert.rs:160-162` (`fn assert_equal_unless`, the variable branch)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/utxo/r1cs.rs`

### Shape

- [x] **INV-ASSERT-34: a constant condition is part of the circuit**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `a_constant_condition_other_than_the_placeholders_changes_the_shape`
  - Kind: shape
  - Statement: for every equal pair, `check_constraints` on `ConditionInCircuit` returns exactly `Ok(0)` when the constant condition equals the placeholder's (false) and exactly `ProverError.ShapeDiffers` when it is true: the true-constant arm adds a row the placeholder's setup does not have.
  - Location: `src/circuit/builtins/ops/assert.rs:60-62` (`fn assert_equal_if`, the constant-condition arms), `src/prover/synthesis.rs` (`fn check_constraints`)
  - Error: `ProverErrorKind::ShapeDiffers`
  - Severity: High
  - Suggested test: negative; `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-35: is_equal has the same shape for equal and different sides**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `every_honest_pair_satisfies_every_exported_row_and_checks_every_proving_row`; `tests/unit/ops/assert/properties.rs` `every_honest_equality_claim_checks_three_rows_and_the_other_claim_breaks_the_last` (property)
  - Kind: shape
  - Statement: for every equal and every different pair, `check_constraints` on `IsEqual` returns exactly `Ok(3)`: the placeholder's equal sides (0 = 0) and the proof's sides build the same rows.
  - Location: `src/circuit/builtins/field/primitive.rs:88-100` (`fn equals`), `src/prover/synthesis.rs` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/ops/assert/r1cs.rs`, `tests/unit/ops/assert/properties.rs`

### Error

- [x] **INV-ASSERT-36: a broken assertion fails natively with exactly the fixture's rule and file**
  - Covered by: `tests/unit/ops/assert/native.rs` `assert_equal_holds_natively_exactly_for_equal_sides`; `tests/unit/ops/assert/native.rs` `assert_not_equal_holds_natively_exactly_for_different_sides`; `tests/unit/ops/assert/native.rs` `assert_equal_if_holds_natively_for_every_pair_under_false_and_for_equal_sides_under_true`; `tests/unit/ops/assert/native.rs` `array_assertions_hold_natively_exactly_when_every_element_pair_is_equal`; `tests/unit/ops/assert/properties.rs` `natively_each_assertion_holds_exactly_when_its_relation_does` (property)
  - Kind: error
  - Statement: every refused native assertion (`assert_equal` and `assert_equal_if` under true on different sides, `assert_not_equal` on equal sides, and their array forms including the default `assert_not_equal`) returns exactly `CircuitError.RuleBroken` with the rule passed in, located in the fixture's file: `#[track_caller]` passes the location through the array helpers and the trait default.
  - Location: `src/circuit/builtins/ops/assert.rs:10-163` (every `#[track_caller]` method and helper)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/ops/assert/native.rs`, `tests/unit/ops/assert/properties.rs`

- [x] **INV-ASSERT-37: a tampered side fails in R1CS with exactly the fixture's rule**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `every_different_right_side_breaks_exactly_row_0_of_assert_equal`; `tests/unit/ops/assert/r1cs.rs` `no_inverse_proves_equal_sides_different`; `tests/unit/ops/assert/r1cs.rs` `a_tampered_array_element_breaks_exactly_its_own_row`; `tests/unit/ops/assert/properties.rs` `every_honest_equality_claim_checks_three_rows_and_the_other_claim_breaks_the_last` (property)
  - Kind: error
  - Statement: `check_tampered` on a side, an inverse or a claim that breaks an assertion returns exactly `ProverError.ProofInputsBreakRule` at the assertion's row labelled with the rule passed to it.
  - Location: `src/circuit/labels.rs` (`fn check`), `src/testing.rs` (`fn check_tampered`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/ops/assert/r1cs.rs`, `tests/unit/ops/assert/properties.rs`

- [x] **INV-ASSERT-38: equal sides asserted different are refused before synthesis**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `check_constraints_refuses_equal_sides_asserted_different_before_synthesis`
  - Kind: error
  - Statement: for every equal pair, `AssertNotEqual::check_constraints` returns exactly `CircuitError.RuleBroken` with "the sides differ", located in the fixture's file, from the native run that precedes synthesis.
  - Location: `src/client/zk_circuit.rs:9-11` (`fn check_constraints`), `src/circuit/builtins/ops/assert.rs:70-78` (the constant branch)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/ops/assert/r1cs.rs`

- [x] **INV-ASSERT-39: empty arrays cannot be asserted different**
  - Covered by: `tests/unit/ops/assert/r1cs.rs` `empty_arrays_can_never_be_asserted_different`; `tests/unit/ops/assert/native.rs` `empty_arrays_are_always_equal_natively`
  - Kind: error
  - Statement: for `N = 0`, `ArrayAssertNotEqual::export_r1cs` returns exactly `CircuitError.RuleBroken` with "the sides differ", and `check_constraints` exactly `CircuitError.RuleBroken`: the conjunction of no flag is the constant true, so the placeholder itself breaks the rule.
  - Location: `src/circuit/builtins/types/boolean.rs:60-68` (`fn all`), `src/circuit/builtins/ops/assert.rs:25-28` (the default `fn assert_not_equal`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/ops/assert/r1cs.rs`

### Equivalence

- [x] **INV-ASSERT-40: assert_not_equal normalizes to its circom reference's row**
  - Covered by: `tests/unit/ops/assert/external.rs` `the_assert_not_equal_reference_normalizes_to_the_sdk_row_over_the_same_variables`
  - Kind: equivalence
  - Statement: the SDK export and `assert_not_equal.circom` normalize to exactly the same single quadratic constraint (left - right) * inverse = 1 over the same 4 variables; the headers differ only in the private-input count (3 in the SDK, where the inverse is a witness, 2 in circom, where it is an intermediate signal).
  - Location: `src/circuit/builtins/ops/assert.rs:70-87` (`fn assert_not_equal`), `tests/unit/ops/assert/assert_not_equal.circom`
  - Severity: High
  - Suggested test: external (circom); `tests/unit/ops/assert/external.rs`

- [x] **INV-ASSERT-41: the circom inverse witness equals the SDK assignment**
  - Covered by: `tests/unit/ops/assert/external.rs` `the_circom_inverse_witness_equals_the_sdk_assignment`; `tests/unit/ops/assert/external.rs` `each_assert_not_equal_r1cs_accepts_the_others_witness`
  - Kind: equivalence
  - Statement: for every different pair, circom's witness is exactly the SDK's `AssertNotEqual` assignment, and each R1CS accepts the other's witness.
  - Location: `src/circuit/builtins/ops/assert.rs:82-84` (the inverse witness)
  - Severity: High
  - Suggested test: external (circom); `tests/unit/ops/assert/external.rs`

- [x] **INV-ASSERT-42: circom witness calculation fails for every equal pair**
  - Covered by: `tests/unit/ops/assert/external.rs` `circom_witness_calculation_fails_for_every_equal_pair`
  - Kind: equivalence
  - Statement: for every equal pair, `assert_not_equal.circom`'s witness calculation aborts with exactly "Assert Failed".
  - Location: `tests/unit/ops/assert/assert_not_equal.circom`
  - Severity: Medium
  - Suggested test: external (circom); `tests/unit/ops/assert/external.rs`

- [x] **INV-ASSERT-43: is_equal is relation-equivalent to circomlib IsEqual**
  - Covered by: `tests/unit/ops/assert/external.rs` `is_equal_is_relation_equivalent_to_circomlib_is_equal_and_both_are_deterministic`
  - Kind: equivalence
  - Statement: for every equal and every different pair claiming 0, 1 and 2, the SDK (natively and by its R1CS) and `is_equal.circom` over circomlib `IsEqual` (by witness calculation and by its R1CS) accept exactly the honest claim; the SDK exports exactly 3 constraints over 6 variables and circom exactly 7 over 10 (`--O0`), and Picus reports the claim exactly Safe in both.
  - Location: `src/circuit/builtins/types/boolean.rs:22-26` (`fn of_equality`), `tests/unit/ops/assert/is_equal.circom`
  - Severity: High
  - Suggested test: external (circomlib, Picus); `tests/unit/ops/assert/external.rs`

- [x] **INV-ASSERT-44: assert_equal_if is relation-equivalent to circomlib ForceEqualIfEnabled**
  - Covered by: `tests/unit/ops/assert/external.rs` `assert_equal_if_is_relation_equivalent_to_force_equal_if_enabled_and_neither_binds_right`; `tests/unit/ops/assert/external.rs` `both_assert_equal_if_circuits_refuse_a_condition_of_two`
  - Kind: equivalence
  - Statement: for every equal and every different pair under both conditions, the SDK and `force_equal_if_enabled.circom` (circomlib `ForceEqualIfEnabled` plus the booleanity row the `bool` proof input adds) accept exactly the cases where the sides are equal or the condition is false, and both refuse a condition of 2; the SDK exports exactly 2 constraints over 4 variables and circom exactly 8 over 10, and Picus reports right exactly Unsafe in both.
  - Location: `src/circuit/builtins/ops/assert.rs:51-68` (`fn assert_equal_if`), `tests/unit/ops/assert/force_equal_if_enabled.circom`
  - Severity: High
  - Suggested test: external (circomlib, Picus); `tests/unit/ops/assert/external.rs`

- [x] **INV-ASSERT-45: the Picus export leads with gadget witnesses and ends with inverse hints**
  - Covered by: `tests/unit/ops/assert/picus.rs` `the_picus_export_leads_with_the_gadget_witnesses_and_ends_with_the_inverse_hints`
  - Kind: equivalence
  - Statement: `AssertEqual`'s Picus export is byte-identical to its snarkjs export; `AssertNotEqual`'s wire labels are exactly `[0, 3, 1, 2]` with 1 output (the inverse), `IsEqual`'s exactly `[0, 4, 1, 2, 3, 5]` with 1 output (the bit; the hint last), and `ArrayIsEqual<2>`'s exactly `[0, 6, 8, 10, 1, 2, 3, 4, 5, 7, 9, 11]` with 3 outputs.
  - Location: `src/prover/snarkjs.rs` (`fn picus_r1cs`), `src/circuit/builtins/field/primitive.rs:88-100` (`fn equals`, the `Multiplier` mark)
  - Severity: High
  - Suggested test: positive; `tests/unit/ops/assert/picus.rs`

### Interop

- [x] **INV-ASSERT-46: snarkjs accepts the assert_not_equal pairs and rejects a tampered inverse**
  - Covered by: `tests/unit/ops/assert/external.rs` `snarkjs_accepts_the_sdk_assert_not_equal_pair_and_both_cross_pairs`
  - Kind: interop
  - Statement: for every different pair, `snarkjs wtns check` accepts the SDK R1CS with the SDK assignment, rejects it with the inverse increased by 1, and accepts both cross pairs with circom's R1CS and witness.
  - Location: `src/prover/snarkjs.rs` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs, circom); `tests/unit/ops/assert/external.rs`

- [x] **INV-ASSERT-47: snarkjs accepts the equality pairs and rejects a tampered claim or condition**
  - Covered by: `tests/unit/ops/assert/external.rs` `snarkjs_accepts_the_sdk_equality_pairs_and_rejects_a_tampered_claim`
  - Kind: interop
  - Statement: for every different pair, `snarkjs wtns check` accepts `IsEqual` claiming 0 and `AssertEqualIf` under false, and rejects the claim flipped to 1 and the condition set to 1.
  - Location: `src/prover/snarkjs.rs` (`fn r1cs`, `fn wtns`)
  - Severity: Critical
  - Suggested test: external (snarkjs); `tests/unit/ops/assert/external.rs`

- [x] **INV-ASSERT-48: snarkjs Groth16 proves and verifies assert_not_equal**
  - Covered by: `tests/unit/ops/assert/external.rs` `snarkjs_proves_and_verifies_assert_not_equal`
  - Kind: interop
  - Statement: `snarkjs groth16 setup`, `prove` with the SDK assignment of x != -x and `verify` accept `AssertNotEqual`'s R1CS, with exactly the empty public signal list.
  - Location: `src/prover/snarkjs.rs` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/ops/assert/external.rs`

## Select (`select` on `CircuitVar` and arrays)

The fixtures in `tests/unit/ops/select/fixtures.rs` take `condition` as a `bool` proof input
(variable 1, with its boolean row) and assert `select(condition, if_true, if_false) ==
selected` with the rule "the selected value is the chosen branch". `Selected<FORM>` covers the
two call forms `CircuitVar::select(c, t, f)` and `c.select(t, f)`, `SelectConstantCondition<C>`
selects under `Bool::constant(C)`, `SelectConstantBranches` between the constants 7 and 3,
`Unasserted` selects and asserts nothing, and `ArraySelected<N>` selects `[Field; N]`. The
branch vectors are 0 or 0, 0 or 1, 1 or 0, p - 1 or 1, (p - 1) / 2 or (p + 1) / 2, 2^253 or
2^64 and x or -x, each under both conditions.

### Semantics

- [x] **INV-SELECT-01: the native select is exactly the chosen branch**
  - Covered by: `tests/unit/ops/select/native.rs` `the_native_select_is_exactly_the_chosen_branch_in_every_form`; `tests/unit/ops/select/properties.rs` `natively_every_form_selects_exactly_the_chosen_branch` (property)
  - Kind: semantics
  - Statement: for every branch vector, every condition and both forms, the native select is exactly `CircuitVar::constant(if_true)` under true and exactly `CircuitVar::constant(if_false)` under false.
  - Location: `src/circuit/builtins/ops/select.rs:7-11` (`impl Select for CircuitVar`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/ops/select/native.rs`, `tests/unit/ops/select/properties.rs`

- [x] **INV-SELECT-02: a native claim holds exactly for the chosen branch**
  - Covered by: `tests/unit/ops/select/native.rs` `every_chosen_branch_holds_natively_and_every_other_value_breaks_the_rule`; `tests/unit/ops/select/native.rs` `a_constant_condition_or_constant_branches_select_natively_the_chosen_value`
  - Kind: semantics
  - Statement: for every branch vector and condition, claiming the chosen branch holds natively in both forms, and claiming the chosen branch plus 1, or the other branch where it differs, returns exactly the fixture's `RuleBroken`; under a constant condition and between constant branches the chosen value holds and the other is refused.
  - Location: `src/circuit/builtins/ops/select.rs:7-11` (`impl Select for CircuitVar`)
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/ops/select/native.rs`

- [x] **INV-SELECT-03: the native array select is element-wise**
  - Covered by: `tests/unit/ops/select/native.rs` `the_native_array_select_is_exactly_the_chosen_array_element_by_element`; `tests/unit/ops/select/native.rs` `a_wrong_array_element_breaks_the_rule_natively`; `tests/unit/ops/select/properties.rs` `natively_the_array_select_is_the_chosen_array` (property)
  - Kind: semantics
  - Statement: for every condition and every pair of `[Field; 3]` arrays, the native array select is exactly the chosen array element by element, an empty array selects exactly the empty array, and a wrong element at every index returns exactly the fixture's `RuleBroken`.
  - Location: `src/circuit/builtins/ops/select.rs:13-21` (`impl Select for [T; N]`)
  - Severity: High
  - Suggested test: positive + negative + property; `tests/unit/ops/select/native.rs`, `tests/unit/ops/select/properties.rs`

### Constraint

- [x] **INV-SELECT-04: the select claim exports exactly the golden rows**
  - Covered by: `tests/unit/ops/select/r1cs.rs` `select_exports_the_condition_row_one_product_row_and_the_claim_row`
  - Kind: constraint
  - Statement: `Selected<0>` exports exactly 6 variables and 3 rows: the condition's boolean row, the product A = {1: 1}, B = {2: 1, 3: -1}, C = {5: 1} (w = c * (t - f)), and the claim A = {3: 1, 4: -1, 5: 1}, B = {0: 1}, C = {} (f + w = selected).
  - Location: `src/circuit/builtins/ops/select.rs:7-11` (`impl Select for CircuitVar`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/ops/select/r1cs.rs`

- [x] **INV-SELECT-05: select on variables adds exactly one row and one variable**
  - Covered by: `tests/unit/ops/select/r1cs.rs` `select_on_variables_adds_exactly_one_row_and_one_variable`
  - Kind: constraint
  - Statement: a circuit that only selects between two variables exports exactly 5 variables and 2 rows: the condition's boolean row and the product row with the product at variable 4.
  - Location: `src/circuit/builtins/ops/select.rs:7-11` (`impl Select for CircuitVar`)
  - Severity: Medium
  - Suggested test: positive (golden rows); `tests/unit/ops/select/r1cs.rs`

- [x] **INV-SELECT-06: the product variable is exactly the condition times the branch difference**
  - Covered by: `tests/unit/ops/select/r1cs.rs` `the_product_variable_is_exactly_the_condition_times_the_branch_difference`
  - Kind: constraint
  - Statement: for every branch vector, condition and form, the assignment is exactly `[1, c, t, f, selected, c * (t - f)]`.
  - Location: `src/circuit/builtins/ops/select.rs:7-11` (`impl Select for CircuitVar`)
  - Severity: High
  - Suggested test: positive; `tests/unit/ops/select/r1cs.rs`

- [x] **INV-SELECT-07: every form exports byte-identical R1CS**
  - Covered by: `tests/unit/ops/select/r1cs.rs` `every_form_exports_byte_identical_r1cs`
  - Kind: constraint
  - Statement: `CircuitVar::select(c, t, f)` and `c.select(t, f)` export byte-identical `.r1cs` files.
  - Location: `src/circuit/builtins/ops/select.rs:3-5` (`trait Select`), `src/circuit/builtins/types/boolean.rs:78-80` (`fn select`)
  - Severity: High
  - Suggested test: positive; `tests/unit/ops/select/r1cs.rs`

- [x] **INV-SELECT-08: a constant condition selects with no row and no variable**
  - Covered by: `tests/unit/ops/select/r1cs.rs` `a_constant_condition_selects_a_branch_with_no_row_and_no_variable`
  - Kind: constraint
  - Statement: under `Bool::constant(true)` the fixture exports exactly the claim row A = {1: 1, 3: -1} (if_true = selected) and under `Bool::constant(false)` exactly A = {2: 1, 3: -1}, each with B = {0: 1}, C = {}, over 4 variables.
  - Location: `src/circuit/builtins/ops/select.rs:7-11` (`impl Select for CircuitVar`)
  - Severity: High
  - Suggested test: positive (golden rows); `tests/unit/ops/select/r1cs.rs`

- [x] **INV-SELECT-09: constant branches select with no product row**
  - Covered by: `tests/unit/ops/select/r1cs.rs` `constant_branches_select_with_no_product_row`
  - Kind: constraint
  - Statement: selecting between the constants 7 and 3 under a variable condition exports exactly the condition's boolean row and the claim A = {0: 3, 1: 4, 2: -1}, B = {0: 1}, C = {} (3 + 4c = selected) over 3 variables.
  - Location: `src/circuit/builtins/ops/select.rs:7-11` (`impl Select for CircuitVar`)
  - Severity: Medium
  - Suggested test: positive (golden rows); `tests/unit/ops/select/r1cs.rs`

- [x] **INV-SELECT-10: the array select exports one product row and one claim row per element**
  - Covered by: `tests/unit/ops/select/r1cs.rs` `array_select_exports_one_product_row_and_one_claim_row_per_element`
  - Kind: constraint
  - Statement: for `N = 3`, `ArraySelected` exports exactly 14 variables and 7 rows: the condition's boolean row, the product rows of elements 0, 1, 2 (products at 11, 12, 13), then their claim rows; for `N = 0` exactly the boolean row over 2 variables.
  - Location: `src/circuit/builtins/ops/select.rs:13-21` (`impl Select for [T; N]`)
  - Severity: Critical
  - Suggested test: positive (golden rows); `tests/unit/ops/select/r1cs.rs`

### Completeness

- [x] **INV-SELECT-11: every honest selection satisfies every row**
  - Covered by: `tests/unit/ops/select/r1cs.rs` `every_honest_selection_satisfies_every_exported_row_and_checks_every_proving_row`; `tests/unit/ops/select/properties.rs` `every_honest_selection_checks_three_rows_and_every_other_value_breaks_the_claim` (property); `tests/unit/ops/select/properties.rs` `natively_the_array_select_is_the_chosen_array` (property)
  - Kind: completeness
  - Statement: for every branch vector and condition, the honest assignments of both forms, both constant conditions, the constant branches and `ArraySelected<3>` leave no exported row unsatisfied, and `check_constraints` returns exactly 3, 1, 2 and 7.
  - Location: `src/circuit/builtins/ops/select.rs:7-21`
  - Severity: High
  - Suggested test: positive + property; `tests/unit/ops/select/r1cs.rs`, `tests/unit/ops/select/properties.rs`

### Soundness

- [x] **INV-SELECT-12: every value but the chosen branch breaks the claim row**
  - Covered by: `tests/unit/ops/select/r1cs.rs` `every_value_but_the_chosen_branch_breaks_the_claim_row`; `tests/unit/ops/select/properties.rs` `every_honest_selection_checks_three_rows_and_every_other_value_breaks_the_claim` (property)
  - Kind: soundness
  - Statement: for every branch vector, condition and form, the honest assignment with the selection replaced by the other branch leaves exactly row 2 unsatisfied where the branches differ (and none where they are equal), and every tampered selection is refused at row 2.
  - Location: `src/circuit/builtins/ops/select.rs:7-11` (`impl Select for CircuitVar`)
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/ops/select/r1cs.rs`, `tests/unit/ops/select/properties.rs`

- [x] **INV-SELECT-13: a tampered product breaks the product row**
  - Covered by: `tests/unit/ops/select/r1cs.rs` `a_tampered_product_breaks_its_unlabelled_row`
  - Kind: soundness
  - Statement: for every branch vector and condition, tampering the product variable is refused at row 1, which has no `Check` label: `select` creates it outside any rule.
  - Location: `src/circuit/builtins/ops/select.rs:7-11` (`impl Select for CircuitVar`)
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/ops/select/r1cs.rs`

- [x] **INV-SELECT-14: only the condition's boolean row refuses a condition of 2**
  - Covered by: `tests/unit/ops/select/r1cs.rs` `only_the_condition_row_refuses_a_condition_of_two`
  - Kind: soundness
  - Statement: for every branch vector, the witness with c = 2, w = 2(t - f) and selected = f + w satisfies the product and claim rows and leaves exactly row 0 unsatisfied, and tampering an honest condition to 2 is refused at row 0 with the bool rule: `select` itself relies on its `Bool` being boolean.
  - Location: `src/circuit/builtins/ops/select.rs:7-11`, `src/conversion/var.rs:134-146` (`impl ProofInput for bool`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/ops/select/r1cs.rs`

- [x] **INV-SELECT-15: under a false condition exactly the unchosen branch is free**
  - Covered by: `tests/unit/ops/select/r1cs.rs` `under_a_false_condition_exactly_the_unchosen_branch_is_free`; `tests/unit/ops/select/picus.rs` `picus_finds_a_branch_free_whenever_it_can_go_unchosen`
  - Kind: soundness
  - Statement: for every branch vector and form, `check_private_variables` reports exactly `if_true` (variable 1) free under false and no free variable under true; Picus reports each branch exactly Unsafe once promoted, and `if_false` exactly Unsafe under `Bool::constant(true)`: a select constrains only the chosen branch.
  - Location: `src/circuit/builtins/ops/select.rs:7-11`
  - Severity: Critical
  - Suggested test: negative + external (Picus); `tests/unit/ops/select/r1cs.rs`, `tests/unit/ops/select/picus.rs`

- [x] **INV-SELECT-16: Picus proves the selection fixed by the condition and the branches**
  - Covered by: `tests/unit/ops/select/picus.rs` `picus_finds_the_selection_fixed_by_the_condition_and_the_branches`
  - Kind: soundness
  - Statement: Picus reports exactly Safe for both forms with the selection promoted, for `Unasserted` with its product as output, for `ArraySelected<3>` with every selection promoted and for `SelectConstantCondition<true>` with the selection promoted.
  - Location: `src/circuit/builtins/ops/select.rs:7-21`, `src/prover/snarkjs.rs` (`fn picus_r1cs`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/ops/select/picus.rs`

- [x] **INV-SELECT-17: a tampered array element breaks exactly its own claim row**
  - Covered by: `tests/unit/ops/select/r1cs.rs` `a_tampered_array_element_breaks_exactly_its_own_claim_row`
  - Kind: soundness
  - Statement: for `ArraySelected<3>` under true, tampering selection i is refused at row 4 + i with the fixture's rule.
  - Location: `src/circuit/builtins/ops/select.rs:13-21` (`impl Select for [T; N]`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/ops/select/r1cs.rs`

### Shape

- [x] **INV-SELECT-18: every selection checks the placeholder's shape**
  - Covered by: `tests/unit/ops/select/r1cs.rs` `every_selection_checks_the_same_shape_as_the_placeholder`; `tests/unit/ops/select/properties.rs` `every_honest_selection_checks_three_rows_and_every_other_value_breaks_the_claim` (property)
  - Kind: shape
  - Statement: for every branch vector, condition and form, `check_constraints` returns exactly `Ok(3)`.
  - Location: `src/prover/synthesis.rs` (`fn check_constraints`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/ops/select/r1cs.rs`, `tests/unit/ops/select/properties.rs`

### Error

- [x] **INV-SELECT-19: a wrong selection fails with exactly the fixture's rule**
  - Covered by: `tests/unit/ops/select/native.rs` `every_chosen_branch_holds_natively_and_every_other_value_breaks_the_rule`; `tests/unit/ops/select/r1cs.rs` `every_value_but_the_chosen_branch_breaks_the_claim_row`; `tests/unit/ops/select/properties.rs` `every_honest_selection_checks_three_rows_and_every_other_value_breaks_the_claim` (property)
  - Kind: error
  - Statement: a wrong selection returns exactly `CircuitError.RuleBroken` with "the selected value is the chosen branch" in the fixture's file natively, and `check_tampered` on it exactly `ProverError.ProofInputsBreakRule` at row 2 with that rule.
  - Location: `src/circuit/builtins/ops/assert.rs:37-49` (`fn assert_equal`)
  - Error: `CircuitErrorKind::RuleBroken`, `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Medium
  - Suggested test: negative + property; `tests/unit/ops/select/native.rs`, `tests/unit/ops/select/r1cs.rs`

### Equivalence

- [x] **INV-SELECT-20: select is relation-equivalent to circomlib Mux1**
  - Covered by: `tests/unit/ops/select/external.rs` `select_is_relation_equivalent_to_circomlib_mux1_and_both_are_deterministic`
  - Kind: equivalence
  - Statement: for every branch vector and condition, claiming the chosen branch, the other branch and the chosen branch plus 1, the SDK and `select.circom` (circomlib `Mux1` plus the booleanity row the `bool` proof input adds) accept exactly the chosen value; the SDK exports exactly 3 constraints over 6 variables and circom exactly 10 over 13 (`--O0`), and Picus reports the selection exactly Safe in both.
  - Location: `src/circuit/builtins/ops/select.rs:7-11`, `tests/unit/ops/select/select.circom`
  - Severity: High
  - Suggested test: external (circomlib, Picus); `tests/unit/ops/select/external.rs`

- [x] **INV-SELECT-21: the Picus export leads with every product variable**
  - Covered by: `tests/unit/ops/select/picus.rs` `the_picus_export_leads_with_every_product_variable`
  - Kind: equivalence
  - Statement: the Picus wire labels are exactly `[0, 5, 1, 2, 3, 4]` with 1 output for `Selected<0>`, `[0, 4, 1, 2, 3]` with 1 output for `Unasserted`, and `[0, 11, 12, 13, 1, ..., 10]` with 3 outputs for `ArraySelected<3>`.
  - Location: `src/prover/snarkjs.rs` (`fn picus_r1cs`)
  - Severity: High
  - Suggested test: positive; `tests/unit/ops/select/picus.rs`

### Interop

- [x] **INV-SELECT-22: snarkjs accepts every SDK selection and rejects a tampered one**
  - Covered by: `tests/unit/ops/select/external.rs` `snarkjs_accepts_every_sdk_selection_and_rejects_a_tampered_one`
  - Kind: interop
  - Statement: for every branch vector and condition, `snarkjs wtns check` accepts the SDK R1CS with the honest assignment and rejects it with the selection increased by 1.
  - Location: `src/prover/snarkjs.rs` (`fn r1cs`, `fn wtns`)
  - Severity: Critical
  - Suggested test: external (snarkjs); `tests/unit/ops/select/external.rs`

- [x] **INV-SELECT-23: snarkjs Groth16 proves and verifies select**
  - Covered by: `tests/unit/ops/select/external.rs` `snarkjs_proves_and_verifies_select`
  - Kind: interop
  - Statement: `snarkjs groth16 setup`, `prove` with the SDK assignment selecting x from x or -x and `verify` accept `Selected<0>`'s R1CS, with exactly the empty public signal list.
  - Location: `src/prover/snarkjs.rs` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/ops/select/external.rs`

## Product assertion (`CircuitVar::assert_product`)

- [x] **INV-ASSERT-PRODUCT-01: native product relation**
  - Covered by: `tests/unit/ops/product/mod.rs` `constant_and_variable_products_accept_exactly_the_independent_vectors`; `tests/unit/ops/product/mod.rs` `random_products_match_big_integer_arithmetic_and_bind_every_claim` (property)
  - Kind: semantics
  - Statement: for every independent boundary vector, the native assertion accepts exactly when the claim equals left times right modulo p.
  - Location: `src/circuit/builtins/ops/assert.rs` (`CircuitVar::assert_product`)
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/ops/product/mod.rs`

- [x] **INV-ASSERT-PRODUCT-02: one product row without an intermediate**
  - Covered by: `tests/unit/ops/product/mod.rs` `a_product_assertion_is_exactly_one_multiplication_row_without_an_intermediate`
  - Kind: constraint
  - Statement: the product assertion exports exactly four variables, zero public inputs, and the row A = {1: 1}, B = {2: 1}, C = {3: 1}, with no intermediate variable.
  - Location: `src/circuit/builtins/ops/assert.rs` (`CircuitVar::assert_product`)
  - Severity: Critical
  - Suggested test: positive + negative; `tests/unit/ops/product/mod.rs`

- [x] **INV-ASSERT-PRODUCT-03: constant products allocate nothing**
  - Covered by: `tests/unit/ops/product/mod.rs` `all_constant_products_add_nothing_and_wrong_constants_return_the_callers_rule`
  - Kind: constraint
  - Statement: the all-constant 2 * 3 = 6 fixture exports exactly one variable, zero rows, and the assignment [1].
  - Location: `src/circuit/builtins/ops/assert.rs` (`CircuitVar::assert_product`)
  - Severity: Medium
  - Suggested test: positive + negative; `tests/unit/ops/product/mod.rs`

- [x] **INV-ASSERT-PRODUCT-04: honest product witnesses satisfy the export**
  - Covered by: `tests/unit/ops/product/mod.rs` `constant_and_variable_products_accept_exactly_the_independent_vectors`; `tests/unit/ops/product/mod.rs` `random_products_match_big_integer_arithmetic_and_bind_every_claim` (property)
  - Kind: completeness
  - Statement: every honest boundary vector and every generated canonical factor pair satisfies every exported row.
  - Location: `src/circuit/builtins/ops/assert.rs` (`CircuitVar::assert_product`)
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/ops/product/mod.rs`

- [x] **INV-ASSERT-PRODUCT-05: wrong product claims fail the named row**
  - Covered by: `tests/unit/ops/product/mod.rs` `constant_and_variable_products_accept_exactly_the_independent_vectors`; `tests/unit/ops/product/mod.rs` `random_products_match_big_integer_arithmetic_and_bind_every_claim` (property)
  - Kind: soundness
  - Statement: for every boundary vector, increasing the claimed product by one fails exactly row 0 with the product rule.
  - Location: `src/circuit/builtins/ops/assert.rs` (`CircuitVar::assert_product`)
  - Severity: Critical
  - Suggested test: positive + negative; `tests/unit/ops/product/mod.rs`

- [x] **INV-ASSERT-PRODUCT-06: zero does not constrain the other factor**
  - Covered by: `tests/unit/ops/product/mod.rs` `a_zero_factor_still_binds_the_product_while_leaving_the_other_factor_free`
  - Kind: soundness
  - Statement: for the assignment 0 * 9 = 0, changing the second factor to 0 leaves every row satisfied while changing the product to 1 fails exactly row 0.
  - Location: `src/circuit/builtins/ops/assert.rs` (`CircuitVar::assert_product`)
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/ops/product/mod.rs`

- [x] **INV-ASSERT-PRODUCT-07: nonzero factors leave no variable free**
  - Covered by: `tests/unit/ops/product/mod.rs` `a_product_assertion_is_exactly_one_multiplication_row_without_an_intermediate`
  - Kind: soundness
  - Statement: for the assignment 2 * 3 = 6, the private-variable report is exactly one constraint, three private variables, no free variables and no tolerated variables.
  - Location: `src/circuit/builtins/ops/assert.rs` (`CircuitVar::assert_product`)
  - Severity: Critical
  - Suggested test: positive + negative; `tests/unit/ops/product/mod.rs`

- [x] **INV-ASSERT-PRODUCT-08: product setup and proving agree**
  - Covered by: `tests/unit/ops/product/mod.rs` `random_products_match_big_integer_arithmetic_and_bind_every_claim` (property)
  - Kind: shape
  - Statement: every boundary vector and generated canonical factor pair checks exactly one constraint against the placeholder setup.
  - Location: `src/circuit/builtins/ops/assert.rs` (`CircuitVar::assert_product`)
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/ops/product/mod.rs`

- [x] **INV-ASSERT-PRODUCT-09: wrong constants retain the rule and caller**
  - Covered by: `tests/unit/ops/product/mod.rs` `all_constant_products_add_nothing_and_wrong_constants_return_the_callers_rule`
  - Kind: error
  - Statement: the native assertion 2 * 3 = 7 returns exactly CircuitError.RuleBroken with the product rule and the calling test file.
  - Location: `src/circuit/builtins/ops/assert.rs` (`CircuitVar::assert_product`)
  - Severity: Medium
  - Suggested test: positive + negative; `tests/unit/ops/product/mod.rs`

- [x] **INV-ASSERT-PRODUCT-10: circom matches the product relation**
  - Covered by: `tests/unit/ops/product/external.rs` `circom_has_the_same_product_relation_for_honest_and_wrong_boundary_claims`
  - Kind: equivalence
  - Statement: the SDK and circom exports normalize to exactly the same rows, accepting all honest boundary claims and rejecting every claim increased by one.
  - Location: `src/circuit/builtins/ops/assert.rs` (`CircuitVar::assert_product`)
  - Severity: Critical
  - Suggested test: external; `tests/unit/ops/product/external.rs`

- [x] **INV-ASSERT-PRODUCT-11: snarkjs checks and proves the exported relation**
  - Covered by: `tests/unit/ops/product/external.rs` `snarkjs_checks_the_relation_rejects_a_wrong_product_and_verifies_a_proof`
  - Kind: interop
  - Statement: snarkjs accepts the honest product witness, rejects its changed claim, and verifies the exported Groth16 proof with exactly zero public signals.
  - Location: `src/circuit/builtins/ops/assert.rs` (`CircuitVar::assert_product`)
  - Severity: High
  - Suggested test: external; `tests/unit/ops/product/external.rs`

- [x] **INV-ASSERT-PRODUCT-12: Picus proves the product fixed**
  - Covered by: `tests/unit/ops/product/external.rs` `picus_proves_the_claimed_product_fixed_by_its_factors`
  - Kind: soundness
  - Statement: Picus reports exactly Safe for both SDK and circom exports with the claimed product promoted to an output.
  - Location: `src/circuit/builtins/ops/assert.rs` (`CircuitVar::assert_product`)
  - Severity: Critical
  - Suggested test: external; `tests/unit/ops/product/external.rs`
