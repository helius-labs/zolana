# Uint Invariants

Covers every public `Uint<BITS>` arithmetic, conversion, comparison, range, division,
`Assert` and `Select` operation in `src/circuit/builtins/types/uint.rs`. ID prefix:
`INV-UINT`. Tests live in `tests/unit/uint/`; generic SDK export/synthesis invariants
remain in `cross-cutting.md`. `from_var` is crate-private and is exercised through
checked arithmetic, narrowing, and division. Integer oracles use Rust u64/u128 or
BigUint, not the SDK operation under test.

Widths: range checks 1/4/64/252/253; arithmetic maximum valid widths 126/251/252/253;
division 4/64/128 with quotient+divisor <=252. Small exported rows are derived by
hand; wide rows/digests and circom constraint counts are pinned.

No SPEC_DIVERGENCE was found against `../spec.md` (Types and range checks).
Compile-time invalid width combinations are outside these runtime fixtures; the
public method const assertions remain the specification for those combinations.
Picus Unknown is recorded as partial determinism coverage, never as proof.
The observations in partial entries describe the initial filtered run; concurrent
integration load can produce Unknown for additional fixtures within the same budget.

## Coverage notes

All ten widening and narrowing alias pairs have separate macro-expanded tests.
`Covered by` names in `conversions.rs` refer to every expansion of the named test.
Groth16 runs on one representative fixture per family; relation equivalence and witness
checks cover the remaining operations. Constants and identity conversions add no
independent relation beyond the already checked input/claim rows.

## Invariants

### CONSTRUCT (`TryFrom`)

- [x] **INV-UINT-CONSTRUCT-01: construction accepts exactly bounded integers**
  - Kind: semantics
  - Statement: For every construction vector at widths 1, 4, 64, 252 and 253, owned and borrowed TryFrom accept exactly values below 2^BITS.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/construction/native.rs`
  - Covered by: `tests/unit/uint/construction/native.rs` `try_from_accepts_exactly_the_values_below_two_to_the_width_natively`

- [x] **INV-UINT-CONSTRUCT-02: construction preserves the integer**
  - Kind: semantics
  - Statement: For every accepted construction constant, the native result is exactly the input field element.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/construction/native.rs`
  - Covered by: `tests/unit/uint/construction/native.rs` `try_from_keeps_the_value_of_every_accepted_constant`

- [x] **INV-UINT-CONSTRUCT-03: four-bit construction has exact golden rows**
  - Kind: constraint
  - Statement: Every Uint<4> construction export has exactly four boolean rows (1-b_i)*b_i=0 followed by sum(2^i*b_i)-x=0, with 6 variables and 5 constraints.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/construction/r1cs.rs`
  - Covered by: `tests/unit/uint/construction/r1cs.rs` `a_4_bit_try_from_exports_exactly_the_golden_rows_and_header`

- [x] **INV-UINT-CONSTRUCT-04: range check count formula**
  - Kind: constraint
  - Statement: For every tested width n in {1,4,64,252,253}, construction allocates exactly n bit variables and n+1 constraints; the constraint-only fixture has zero public inputs.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/construction/r1cs.rs`
  - Covered by: `tests/unit/uint/construction/r1cs.rs` `a_range_check_over_bits_costs_bits_plus_one_constraints_and_bits_variables`

- [x] **INV-UINT-CONSTRUCT-05: wide exports have pinned digests**
  - Kind: constraint
  - Statement: Every Uint<64> and Uint<252> construction export is exactly the hand-derived decomposition with its pinned SHA-256 digest.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/construction/r1cs.rs`
  - Covered by: `tests/unit/uint/construction/r1cs.rs` `the_64_and_252_bit_range_checks_export_the_derived_rows_and_pinned_digests`

- [x] **INV-UINT-CONSTRUCT-06: owned and borrowed matrices coincide**
  - Kind: shape
  - Statement: For every tested width, the exported bytes for owned TryFrom are exactly the borrowed TryFrom bytes.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/construction/r1cs.rs`
  - Covered by: `tests/unit/uint/construction/r1cs.rs` `the_owned_and_borrowed_forms_export_byte_identical_r1cs_at_every_width`

- [x] **INV-UINT-CONSTRUCT-07: honest digits satisfy every row**
  - Kind: completeness
  - Statement: For every accepted edge vector at widths 1,4,64,252,253, its binary digits satisfy every exported row and check_constraints accepts the setup/proving matrices.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/construction/r1cs.rs`
  - Covered by: `tests/unit/uint/construction/r1cs.rs` `every_value_below_two_to_the_width_satisfies_every_row_with_its_binary_digits`

- [x] **INV-UINT-CONSTRUCT-08: no alternative four-bit decomposition**
  - Kind: soundness
  - Statement: For every tested four-bit input and every possible four-bit digit pattern, the rows hold exactly when the digits encode the bounded input.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/construction/r1cs.rs`
  - Covered by: `tests/unit/uint/construction/r1cs.rs` `at_4_bits_only_the_binary_digits_of_a_value_below_16_satisfy_the_rows`

- [x] **INV-UINT-CONSTRUCT-09: overflow fails recomposition**
  - Kind: soundness
  - Statement: For every out-of-range construction vector, the candidate using the input low bits leaves exactly the recomposition row unsatisfied.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/construction/r1cs.rs`
  - Covered by: `tests/unit/uint/construction/r1cs.rs` `a_value_that_does_not_fit_leaves_exactly_the_sum_row_unsatisfied_at_every_width`

- [x] **INV-UINT-CONSTRUCT-10: bad constants name their width**
  - Kind: error
  - Statement: For every out-of-range native construction vector, the error is exactly CircuitError.ValueTooLarge with its bit width.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/construction/native.rs`
  - Covered by: `tests/unit/uint/construction/native.rs` `try_from_accepts_exactly_the_values_below_two_to_the_width_natively`

- [x] **INV-UINT-CONSTRUCT-11: tampered values report the width rule**
  - Kind: error
  - Statement: For every tampered value or bit in the construction diagnostic vectors, proving reports exactly ProofInputsBreakRule with the expected row and width rule.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/construction/r1cs.rs`
  - Covered by: `tests/unit/uint/construction/r1cs.rs` `the_proving_rows_name_the_width_rule_for_a_tampered_value_or_digit`

- [x] **INV-UINT-CONSTRUCT-12: Num2Bits accepts the same relation**
  - Kind: equivalence
  - Statement: For every honest and rejected construction vector at widths 4,64,252, SDK native/R1CS and circomlib Num2Bits witness/R1CS acceptance are exactly equal.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/construction/external.rs`
  - Covered by: `tests/unit/uint/construction/external.rs` `try_from_is_relation_equivalent_to_circomlib_num2bits_with_equal_sizes`

- [x] **INV-UINT-CONSTRUCT-13: snarkjs checks honest and altered values**
  - Kind: interop
  - Statement: For every exported construction witness in the external vectors, snarkjs accepts the honest witness and rejects the changed input.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/uint/construction/external.rs`
  - Covered by: `tests/unit/uint/construction/external.rs` `snarkjs_accepts_every_sdk_pair_and_rejects_a_tampered_value`

- [x] **INV-UINT-CONSTRUCT-14: construction Groth16 interoperability**
  - Kind: interop
  - Statement: For the Uint<64> maximum input fixture, snarkjs Groth16 setup/prove/verify succeeds with zero public inputs.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/uint/construction/external.rs`
  - Covered by: `tests/unit/uint/construction/external.rs` `snarkjs_proves_and_verifies_the_64_bit_range_check`

- [x] **INV-UINT-CONSTRUCT-15: the rows fix random construction witnesses**
  - Kind: soundness
  - Statement: For every generated u64 input and positive tamper offset, the honest witness satisfies all rows and the changed value breaks exactly the width rule.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/construction/properties.rs`
  - Covered by: `tests/unit/uint/construction/properties.rs` `every_u64_satisfies_the_64_bit_rows_and_a_tampered_value_breaks_the_width_rule`

### CONST (`constant`)

- [x] **INV-UINT-CONST-01: constant respects its bit width**
  - Kind: semantics
  - Statement: For every tested u64 constant and width, Uint::constant accepts exactly values below 2^BITS.
  - Location: `src/circuit/builtins/types/uint.rs:46` (`constant`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/construction/native.rs`
  - Covered by: `tests/unit/uint/construction/native.rs` `constant_accepts_exactly_the_u64_values_below_two_to_the_width`

- [x] **INV-UINT-CONST-02: zero is a field constant**
  - Kind: semantics
  - Statement: For every tested width in {1,64,253}, Uint::zero is exactly the constant zero.
  - Location: `src/circuit/builtins/types/uint.rs:41` (`zero`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/construction/native.rs`
  - Covered by: `tests/unit/uint/construction/native.rs` `zero_is_the_constant_zero_at_every_width`

- [x] **INV-UINT-CONST-03: constants need no decomposition**
  - Kind: constraint
  - Statement: The constant construction fixture has exactly two claim rows and one input variable; every constant range check adds zero rows.
  - Location: `src/circuit/builtins/types/uint.rs:46` (`constant`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/construction/r1cs.rs`
  - Covered by: `tests/unit/uint/construction/r1cs.rs` `a_constant_uint_adds_no_range_check_row`

- [x] **INV-UINT-CONST-04: the rows fix constant claims**
  - Kind: soundness
  - Statement: For every four-bit alternative claim to the constant 15 fixture, the proving rows accept exactly claim 15.
  - Location: `src/circuit/builtins/types/uint.rs:46` (`constant`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/construction/r1cs.rs`
  - Covered by: `tests/unit/uint/construction/r1cs.rs` `bool_conversion_and_constants_refuse_every_wrong_four_bit_claim`

### BOOL (`From<Bool>`)

- [x] **INV-UINT-BOOL-01: boolean conversion is zero or one**
  - Kind: semantics
  - Statement: For each boolean and tested target width 1,64,253, the native converted Uint is exactly 0 or 1.
  - Location: `src/circuit/builtins/types/uint.rs:294` (`From<Bool>`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/construction/native.rs`
  - Covered by: `tests/unit/uint/construction/native.rs` `a_bool_converts_to_exactly_zero_or_one_at_every_width`

- [x] **INV-UINT-BOOL-02: boolean conversion adds no range check**
  - Kind: constraint
  - Statement: For every tested FromBool target width 4 and 253, the export contains exactly the input booleanity row and the claimed-value equality row.
  - Location: `src/circuit/builtins/types/uint.rs:294` (`From<Bool>`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/construction/r1cs.rs`
  - Covered by: `tests/unit/uint/construction/r1cs.rs` `from_bool_adds_no_row_beyond_the_bool_input_check`

- [x] **INV-UINT-BOOL-03: boolean conversion rows fix the claim**
  - Kind: soundness
  - Statement: For each boolean input and every four-bit candidate claim, the rows accept exactly the integer encoding of that boolean.
  - Location: `src/circuit/builtins/types/uint.rs:294` (`From<Bool>`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/construction/r1cs.rs`
  - Covered by: `tests/unit/uint/construction/r1cs.rs` `bool_conversion_and_constants_refuse_every_wrong_four_bit_claim`

### INTO (`From<Uint> for CircuitVar`)

- [x] **INV-UINT-INTO-01: conversion to a field preserves value**
  - Kind: semantics
  - Statement: The native CircuitVar converted from Uint<4>(13) is exactly the constant 13.
  - Location: `src/circuit/builtins/types/uint.rs:300` (`From<Uint> for CircuitVar`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/construction/native.rs`
  - Covered by: `tests/unit/uint/construction/native.rs` `into_circuit_var_is_the_same_constant`

- [x] **INV-UINT-INTO-02: conversion to a field adds no rows**
  - Kind: constraint
  - Statement: For every tested IntoVar width, converting a bounded Uint into CircuitVar adds exactly zero rows before its equality assertion.
  - Location: `src/circuit/builtins/types/uint.rs:300` (`From<Uint> for CircuitVar`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/construction/r1cs.rs`
  - Covered by: `tests/unit/uint/construction/r1cs.rs` `into_circuit_var_adds_only_the_row_asserting_it`

- [x] **INV-UINT-INTO-03: field conversion rows fix the output**
  - Kind: soundness
  - Statement: Every tested wrong IntoVar claim breaks exactly its claim row.
  - Location: `src/circuit/builtins/types/uint.rs:300` (`From<Uint> for CircuitVar`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/construction/r1cs.rs`
  - Covered by: `tests/unit/uint/construction/r1cs.rs` `a_rule_other_than_the_width_rule_labels_the_claim_row`

### WIDEN (`conversions!`)

- [x] **INV-UINT-WIDEN-01: all alias widenings preserve values**
  - Kind: semantics
  - Statement: For every one of the ten alias pairs and its 0,1,maximum-narrow vectors, widening preserves exactly the integer.
  - Location: `src/circuit/builtins/types/uint.rs:326` (`conversions!`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/conversions.rs`
  - Covered by: `tests/unit/uint/conversions.rs` `widening_preserves_the_value_and_adds_no_rows_or_variables`

- [x] **INV-UINT-WIDEN-02: widening has no circuit cost**
  - Kind: constraint
  - Statement: For every one of the ten alias pairs, widening exports exactly the bytes of the narrow IntoVar fixture.
  - Location: `src/circuit/builtins/types/uint.rs:326` (`conversions!`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/conversions.rs`
  - Covered by: `tests/unit/uint/conversions.rs` `widening_preserves_the_value_and_adds_no_rows_or_variables`

- [x] **INV-UINT-WIDEN-03: widened claims cannot change**
  - Kind: soundness
  - Statement: For every alias pair and tested accepted vector, incrementing the widened claim leaves a proving row unsatisfied.
  - Location: `src/circuit/builtins/types/uint.rs:326` (`conversions!`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/conversions.rs`
  - Covered by: `tests/unit/uint/conversions.rs` `widening_preserves_the_value_and_adds_no_rows_or_variables`

### NARROW (`conversions!`)

- [x] **INV-UINT-NARROW-01: all narrowing boundaries hold**
  - Kind: semantics
  - Statement: For every one of the ten alias pairs, narrowing accepts 0,1,maximum-narrow and rejects 2^narrow and maximum-wide.
  - Location: `src/circuit/builtins/types/uint.rs:333` (`conversions!`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/conversions.rs`
  - Covered by: `tests/unit/uint/conversions.rs` `narrowing_preserves_fitting_values_and_enforces_its_bound`

- [x] **INV-UINT-NARROW-02: narrowing count formula**
  - Kind: constraint
  - Statement: For every alias pair (n,w), the narrowing fixture exports exactly n+w+3 constraints.
  - Location: `src/circuit/builtins/types/uint.rs:333` (`conversions!`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/conversions.rs`
  - Covered by: `tests/unit/uint/conversions.rs` `narrowing_preserves_fitting_values_and_enforces_its_bound`

- [x] **INV-UINT-NARROW-03: narrowing rejects forged overflow digits**
  - Kind: soundness
  - Statement: For every alias pair and out-of-range boundary, a witness using the true low digits leaves exactly the narrowing recomposition row unsatisfied.
  - Location: `src/circuit/builtins/types/uint.rs:333` (`conversions!`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/conversions.rs`
  - Covered by: `tests/unit/uint/conversions.rs` `narrowing_preserves_fitting_values_and_enforces_its_bound`

- [x] **INV-UINT-NARROW-04: random narrowing has stable matrices**
  - Kind: shape
  - Statement: For every generated fitting input in every alias pair, setup and proving matrices compare exactly equal.
  - Location: `src/circuit/builtins/types/uint.rs:333` (`conversions!`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/conversions.rs`
  - Covered by: `tests/unit/uint/conversions.rs` `random_conversion_roundtrips_hold_and_false_claims_are_rejected`

- [x] **INV-UINT-NARROW-05: narrowing overflow names the destination width**
  - Kind: error
  - Statement: For every alias pair and tested overflow, the native error is exactly RuleBroken("a value does not fit in N bits") for destination N.
  - Location: `src/circuit/builtins/types/uint.rs:333` (`conversions!`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/conversions.rs`
  - Covered by: `tests/unit/uint/conversions.rs` `narrowing_preserves_fitting_values_and_enforces_its_bound`

- [x] **INV-UINT-NARROW-06: all narrowings match Num2Bits**
  - Kind: equivalence
  - Statement: For every alias pair boundary vector, SDK and circomlib acceptance are exactly equal, with SDK n+w+3 rows and circom n+w+5 rows.
  - Location: `src/circuit/builtins/types/uint.rs:333` (`conversions!`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/conversions.rs`
  - Covered by: `tests/unit/uint/conversions.rs` `narrowing_relation_matches_circomlib_num2bits`

- [x] **INV-UINT-NARROW-07: narrowing supports snarkjs Groth16**
  - Kind: interop
  - Statement: For the U64 to U8 fixture at 255, snarkjs setup/prove/verify succeeds with no public inputs.
  - Location: `src/circuit/builtins/types/uint.rs:333` (`conversions!`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/uint/conversions.rs`
  - Covered by: `tests/unit/uint/conversions.rs` `narrowing_matches_num2bits_and_roundtrips_through_snarkjs`

### ADD (`add`)

- [x] **INV-UINT-ADD-01: add has integer semantics**
  - Kind: semantics
  - Statement: For every fitting four-bit arithmetic test vector, add returns exactly x+y.
  - Location: `src/circuit/builtins/types/uint.rs:75` (`add`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/native.rs`
  - Covered by: `tests/unit/uint/arithmetic/native.rs` `at_4_bits_add_mul_and_sum_give_the_integer_result_for_every_operand`

- [x] **INV-UINT-ADD-02: add golden rows**
  - Kind: constraint
  - Statement: The Uint<4> add fixture exports exactly 11 hand-derived rows and 12 variables.
  - Location: `src/circuit/builtins/types/uint.rs:75` (`add`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `every_4_bit_operation_exports_exactly_its_golden_rows_and_header`

- [x] **INV-UINT-ADD-03: add honest rows hold**
  - Kind: completeness
  - Statement: For every fitting add test vector, the honest witness satisfies every exported row.
  - Location: `src/circuit/builtins/types/uint.rs:75` (`add`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `at_4_bits_every_fitting_operation_satisfies_every_row_with_the_derived_witness`

- [x] **INV-UINT-ADD-04: add setup agrees with proving**
  - Kind: shape
  - Statement: For every fitting add fixture vector, check_constraints accepts identical setup and proving matrices.
  - Location: `src/circuit/builtins/types/uint.rs:75` (`add`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `at_4_bits_every_fitting_operation_satisfies_every_row_with_the_derived_witness`

- [x] **INV-UINT-ADD-05: add refuses dishonest witnesses**
  - Kind: soundness
  - Statement: For every tested false result of add, the proving or exported rows contain an unsatisfied constraint.
  - Location: `src/circuit/builtins/types/uint.rs:75` (`add`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `at_4_bits_add_and_mul_rows_hold_exactly_for_the_integer_result`

- [x] **INV-UINT-ADD-06: add matches circom**
  - Kind: equivalence
  - Statement: For every add external vector, the SDK and circom accept exactly the same operand/result relation.
  - Location: `src/circuit/builtins/types/uint.rs:75` (`add`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/arithmetic/external.rs`
  - Covered by: `tests/unit/uint/arithmetic/external.rs` `every_4_bit_operation_is_relation_equivalent_to_its_circom_reference`

- [x] **INV-UINT-ADD-07: add random wide integer result**
  - Kind: semantics
  - Statement: For every generated u64 pair, add returns exactly its u128 host result.
  - Location: `src/circuit/builtins/types/uint.rs:75` (`add`)
  - Severity: High
  - Suggested test: property; `tests/unit/uint/arithmetic/properties.rs`
  - Covered by: `tests/unit/uint/arithmetic/properties.rs` `natively_add_and_mul_at_64_bits_give_the_u128_result`

### MUL (`mul`)

- [x] **INV-UINT-MUL-01: mul has integer semantics**
  - Kind: semantics
  - Statement: For every fitting four-bit arithmetic test vector, mul returns exactly x*y.
  - Location: `src/circuit/builtins/types/uint.rs:87` (`mul`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/native.rs`
  - Covered by: `tests/unit/uint/arithmetic/native.rs` `at_4_bits_add_mul_and_sum_give_the_integer_result_for_every_operand`

- [x] **INV-UINT-MUL-02: mul golden rows**
  - Kind: constraint
  - Statement: The Uint<4> mul fixture exports exactly 12 hand-derived rows and 13 variables.
  - Location: `src/circuit/builtins/types/uint.rs:87` (`mul`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `every_4_bit_operation_exports_exactly_its_golden_rows_and_header`

- [x] **INV-UINT-MUL-03: mul honest rows hold**
  - Kind: completeness
  - Statement: For every fitting mul test vector, the honest witness satisfies every exported row.
  - Location: `src/circuit/builtins/types/uint.rs:87` (`mul`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `at_4_bits_every_fitting_operation_satisfies_every_row_with_the_derived_witness`

- [x] **INV-UINT-MUL-04: mul setup agrees with proving**
  - Kind: shape
  - Statement: For every fitting mul fixture vector, check_constraints accepts identical setup and proving matrices.
  - Location: `src/circuit/builtins/types/uint.rs:87` (`mul`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `at_4_bits_every_fitting_operation_satisfies_every_row_with_the_derived_witness`

- [x] **INV-UINT-MUL-05: mul refuses dishonest witnesses**
  - Kind: soundness
  - Statement: For every tested false result of mul, the proving or exported rows contain an unsatisfied constraint.
  - Location: `src/circuit/builtins/types/uint.rs:87` (`mul`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `at_4_bits_add_and_mul_rows_hold_exactly_for_the_integer_result`

- [x] **INV-UINT-MUL-06: mul matches circom**
  - Kind: equivalence
  - Statement: For every mul external vector, the SDK and circom accept exactly the same operand/result relation.
  - Location: `src/circuit/builtins/types/uint.rs:87` (`mul`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/arithmetic/external.rs`
  - Covered by: `tests/unit/uint/arithmetic/external.rs` `every_4_bit_operation_is_relation_equivalent_to_its_circom_reference`

- [x] **INV-UINT-MUL-07: mul random wide integer result**
  - Kind: semantics
  - Statement: For every generated u64 pair, mul returns exactly its u128 host result.
  - Location: `src/circuit/builtins/types/uint.rs:87` (`mul`)
  - Severity: High
  - Suggested test: property; `tests/unit/uint/arithmetic/properties.rs`
  - Covered by: `tests/unit/uint/arithmetic/properties.rs` `natively_add_and_mul_at_64_bits_give_the_u128_result`

### SUM (`sum`)

- [x] **INV-UINT-SUM-01: sum has integer semantics**
  - Kind: semantics
  - Statement: For every fitting four-bit arithmetic test vector, sum returns exactly x+y+z.
  - Location: `src/circuit/builtins/types/uint.rs:99` (`sum`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/native.rs`
  - Covered by: `tests/unit/uint/arithmetic/native.rs` `at_4_bits_add_mul_and_sum_give_the_integer_result_for_every_operand`

- [x] **INV-UINT-SUM-02: sum golden rows**
  - Kind: constraint
  - Statement: The Uint<4> sum fixture exports exactly 16 hand-derived rows and 17 variables.
  - Location: `src/circuit/builtins/types/uint.rs:99` (`sum`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `every_4_bit_operation_exports_exactly_its_golden_rows_and_header`

- [x] **INV-UINT-SUM-03: sum honest rows hold**
  - Kind: completeness
  - Statement: For every fitting sum test vector, the honest witness satisfies every exported row.
  - Location: `src/circuit/builtins/types/uint.rs:99` (`sum`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `sum_rows_bind_every_operand_and_the_claim`

- [x] **INV-UINT-SUM-04: sum setup agrees with proving**
  - Kind: shape
  - Statement: For every fitting sum fixture vector, check_constraints accepts identical setup and proving matrices.
  - Location: `src/circuit/builtins/types/uint.rs:99` (`sum`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `sum_rows_bind_every_operand_and_the_claim`

- [x] **INV-UINT-SUM-05: sum refuses dishonest witnesses**
  - Kind: soundness
  - Statement: For every tested false result of sum, the proving or exported rows contain an unsatisfied constraint.
  - Location: `src/circuit/builtins/types/uint.rs:99` (`sum`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `sum_rows_bind_every_operand_and_the_claim`

- [x] **INV-UINT-SUM-06: sum matches circom**
  - Kind: equivalence
  - Statement: For every sum external vector, the SDK and circom accept exactly the same operand/result relation.
  - Location: `src/circuit/builtins/types/uint.rs:99` (`sum`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/arithmetic/external.rs`
  - Covered by: `tests/unit/uint/arithmetic/external.rs` `sum_matches_circom_and_snarkjs_accepts_only_the_true_claim`

- [x] **INV-UINT-SUM-07: empty and singleton sum identities**
  - Kind: semantics
  - Statement: Every tested singleton sum equals its operand; the empty sum is exactly zero.
  - Location: `src/circuit/builtins/types/uint.rs:99` (`sum`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/native.rs`
  - Covered by: `tests/unit/uint/arithmetic/native.rs` `empty_and_singleton_sums_have_the_integer_identity`

- [x] **INV-UINT-SUM-08: the rows fix random three-operand sums**
  - Kind: soundness
  - Statement: For every generated three-u64 vector, the sum is exactly the u128 host sum and incrementing its claim is refused.
  - Location: `src/circuit/builtins/types/uint.rs:99` (`sum`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/arithmetic/properties.rs`
  - Covered by: `tests/unit/uint/arithmetic/properties.rs` `random_sums_match_three_independent_u64_operands`

### CHECKED-ADD (`checked_add`)

- [x] **INV-UINT-CHECKED-ADD-01: checked_add has integer semantics**
  - Kind: semantics
  - Statement: For every fitting four-bit arithmetic test vector, checked_add returns exactly x+y when x+y < 2^BITS.
  - Location: `src/circuit/builtins/types/uint.rs:112` (`checked_add`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/native.rs`
  - Covered by: `tests/unit/uint/arithmetic/native.rs` `at_4_bits_every_checked_result_that_fits_is_the_integer_result`

- [x] **INV-UINT-CHECKED-ADD-02: checked_add golden rows**
  - Kind: constraint
  - Statement: The Uint<4> checked_add fixture exports exactly 16 hand-derived rows and 16 variables.
  - Location: `src/circuit/builtins/types/uint.rs:112` (`checked_add`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `every_4_bit_operation_exports_exactly_its_golden_rows_and_header`

- [x] **INV-UINT-CHECKED-ADD-03: checked_add honest rows hold**
  - Kind: completeness
  - Statement: For every fitting checked_add test vector, the honest witness satisfies every exported row.
  - Location: `src/circuit/builtins/types/uint.rs:112` (`checked_add`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `at_4_bits_every_fitting_operation_satisfies_every_row_with_the_derived_witness`

- [x] **INV-UINT-CHECKED-ADD-04: checked_add setup agrees with proving**
  - Kind: shape
  - Statement: For every fitting checked_add fixture vector, check_constraints accepts identical setup and proving matrices.
  - Location: `src/circuit/builtins/types/uint.rs:112` (`checked_add`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `every_fitting_wide_edge_satisfies_every_row_with_the_derived_witness`

- [x] **INV-UINT-CHECKED-ADD-05: checked_add refuses dishonest witnesses**
  - Kind: soundness
  - Statement: For every tested false result of checked_add, the proving or exported rows contain an unsatisfied constraint.
  - Location: `src/circuit/builtins/types/uint.rs:112` (`checked_add`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `at_4_bits_only_the_digits_of_a_fitting_result_satisfy_a_checked_operation`

- [x] **INV-UINT-CHECKED-ADD-06: checked_add matches circom**
  - Kind: equivalence
  - Statement: For every checked_add external vector, the SDK and circom accept exactly the same operand/result relation.
  - Location: `src/circuit/builtins/types/uint.rs:112` (`checked_add`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/arithmetic/external.rs`
  - Covered by: `tests/unit/uint/arithmetic/external.rs` `every_4_bit_operation_is_relation_equivalent_to_its_circom_reference`

- [x] **INV-UINT-CHECKED-ADD-07: checked_add overflow reports its rule**
  - Kind: error
  - Statement: For every tested non-fitting checked_add input at widths 64 and the maximum supported width, native evaluation reports exactly its supplied rule.
  - Location: `src/circuit/builtins/types/uint.rs:112` (`checked_add`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/native.rs`
  - Covered by: `tests/unit/uint/arithmetic/native.rs` `at_64_126_and_252_bits_every_checked_operation_refuses_exactly_past_the_edge`

- [x] **INV-UINT-CHECKED-ADD-08: the rows fix random fitting checked_add results**
  - Kind: soundness
  - Statement: For every generated fitting u64 pair, checked_add satisfies setup/proving checks and a false output is refused.
  - Location: `src/circuit/builtins/types/uint.rs:112` (`checked_add`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/arithmetic/properties.rs`
  - Covered by: `tests/unit/uint/arithmetic/properties.rs` `every_fitting_64_bit_checked_sum_satisfies_the_rows_and_a_wrong_claim_breaks_the_claim_rule`

### CHECKED-MUL (`checked_mul`)

- [x] **INV-UINT-CHECKED-MUL-01: checked_mul has integer semantics**
  - Kind: semantics
  - Statement: For every fitting four-bit arithmetic test vector, checked_mul returns exactly x*y when x*y < 2^BITS.
  - Location: `src/circuit/builtins/types/uint.rs:125` (`checked_mul`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/native.rs`
  - Covered by: `tests/unit/uint/arithmetic/native.rs` `at_4_bits_every_checked_result_that_fits_is_the_integer_result`

- [x] **INV-UINT-CHECKED-MUL-02: checked_mul golden rows**
  - Kind: constraint
  - Statement: The Uint<4> checked_mul fixture exports exactly 17 hand-derived rows and 17 variables.
  - Location: `src/circuit/builtins/types/uint.rs:125` (`checked_mul`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `every_4_bit_operation_exports_exactly_its_golden_rows_and_header`

- [x] **INV-UINT-CHECKED-MUL-03: checked_mul honest rows hold**
  - Kind: completeness
  - Statement: For every fitting checked_mul test vector, the honest witness satisfies every exported row.
  - Location: `src/circuit/builtins/types/uint.rs:125` (`checked_mul`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `at_4_bits_every_fitting_operation_satisfies_every_row_with_the_derived_witness`

- [x] **INV-UINT-CHECKED-MUL-04: checked_mul setup agrees with proving**
  - Kind: shape
  - Statement: For every fitting checked_mul fixture vector, check_constraints accepts identical setup and proving matrices.
  - Location: `src/circuit/builtins/types/uint.rs:125` (`checked_mul`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `every_fitting_wide_edge_satisfies_every_row_with_the_derived_witness`

- [x] **INV-UINT-CHECKED-MUL-05: checked_mul refuses dishonest witnesses**
  - Kind: soundness
  - Statement: For every tested false result of checked_mul, the proving or exported rows contain an unsatisfied constraint.
  - Location: `src/circuit/builtins/types/uint.rs:125` (`checked_mul`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `at_4_bits_only_the_digits_of_a_fitting_result_satisfy_a_checked_operation`

- [x] **INV-UINT-CHECKED-MUL-06: checked_mul matches circom**
  - Kind: equivalence
  - Statement: For every checked_mul external vector, the SDK and circom accept exactly the same operand/result relation.
  - Location: `src/circuit/builtins/types/uint.rs:125` (`checked_mul`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/arithmetic/external.rs`
  - Covered by: `tests/unit/uint/arithmetic/external.rs` `every_4_bit_operation_is_relation_equivalent_to_its_circom_reference`

- [x] **INV-UINT-CHECKED-MUL-07: checked_mul overflow reports its rule**
  - Kind: error
  - Statement: For every tested non-fitting checked_mul input at widths 64 and the maximum supported width, native evaluation reports exactly its supplied rule.
  - Location: `src/circuit/builtins/types/uint.rs:125` (`checked_mul`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/native.rs`
  - Covered by: `tests/unit/uint/arithmetic/native.rs` `at_64_126_and_252_bits_every_checked_operation_refuses_exactly_past_the_edge`

- [x] **INV-UINT-CHECKED-MUL-08: the rows fix random fitting checked_mul results**
  - Kind: soundness
  - Statement: For every generated fitting u64 pair, checked_mul satisfies setup/proving checks and a false output is refused.
  - Location: `src/circuit/builtins/types/uint.rs:125` (`checked_mul`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/arithmetic/properties.rs`
  - Covered by: `tests/unit/uint/arithmetic/properties.rs` `every_fitting_64_bit_checked_sum_satisfies_the_rows_and_a_wrong_claim_breaks_the_claim_rule`

### CHECKED-SUB (`checked_sub`)

- [x] **INV-UINT-CHECKED-SUB-01: checked_sub has integer semantics**
  - Kind: semantics
  - Statement: For every fitting four-bit arithmetic test vector, checked_sub returns exactly x-y when x>=y.
  - Location: `src/circuit/builtins/types/uint.rs:138` (`checked_sub`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/native.rs`
  - Covered by: `tests/unit/uint/arithmetic/native.rs` `at_4_bits_every_checked_result_that_fits_is_the_integer_result`

- [x] **INV-UINT-CHECKED-SUB-02: checked_sub golden rows**
  - Kind: constraint
  - Statement: The Uint<4> checked_sub fixture exports exactly 16 hand-derived rows and 16 variables.
  - Location: `src/circuit/builtins/types/uint.rs:138` (`checked_sub`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `every_4_bit_operation_exports_exactly_its_golden_rows_and_header`

- [x] **INV-UINT-CHECKED-SUB-03: checked_sub honest rows hold**
  - Kind: completeness
  - Statement: For every fitting checked_sub test vector, the honest witness satisfies every exported row.
  - Location: `src/circuit/builtins/types/uint.rs:138` (`checked_sub`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `at_4_bits_every_fitting_operation_satisfies_every_row_with_the_derived_witness`

- [x] **INV-UINT-CHECKED-SUB-04: checked_sub setup agrees with proving**
  - Kind: shape
  - Statement: For every fitting checked_sub fixture vector, check_constraints accepts identical setup and proving matrices.
  - Location: `src/circuit/builtins/types/uint.rs:138` (`checked_sub`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `every_fitting_wide_edge_satisfies_every_row_with_the_derived_witness`

- [x] **INV-UINT-CHECKED-SUB-05: checked_sub refuses dishonest witnesses**
  - Kind: soundness
  - Statement: For every tested false result of checked_sub, the proving or exported rows contain an unsatisfied constraint.
  - Location: `src/circuit/builtins/types/uint.rs:138` (`checked_sub`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `at_4_bits_only_the_digits_of_a_fitting_result_satisfy_a_checked_operation`

- [x] **INV-UINT-CHECKED-SUB-06: checked_sub matches circom**
  - Kind: equivalence
  - Statement: For every checked_sub external vector, the SDK and circom accept exactly the same operand/result relation.
  - Location: `src/circuit/builtins/types/uint.rs:138` (`checked_sub`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/arithmetic/external.rs`
  - Covered by: `tests/unit/uint/arithmetic/external.rs` `every_4_bit_operation_is_relation_equivalent_to_its_circom_reference`

- [x] **INV-UINT-CHECKED-SUB-07: checked_sub overflow reports its rule**
  - Kind: error
  - Statement: For every tested non-fitting checked_sub input at widths 64 and the maximum supported width, native evaluation reports exactly its supplied rule.
  - Location: `src/circuit/builtins/types/uint.rs:138` (`checked_sub`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/native.rs`
  - Covered by: `tests/unit/uint/arithmetic/native.rs` `at_64_126_and_252_bits_every_checked_operation_refuses_exactly_past_the_edge`

- [x] **INV-UINT-CHECKED-SUB-08: the rows fix random fitting checked_sub results**
  - Kind: soundness
  - Statement: For every generated fitting u64 pair, checked_sub satisfies setup/proving checks and a false output is refused.
  - Location: `src/circuit/builtins/types/uint.rs:138` (`checked_sub`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/arithmetic/properties.rs`
  - Covered by: `tests/unit/uint/arithmetic/properties.rs` `every_fitting_64_bit_checked_sum_satisfies_the_rows_and_a_wrong_claim_breaks_the_claim_rule`

### ARITH (`checked_add/checked_mul/checked_sub`)

- [x] **INV-UINT-ARITH-01: wide checked rows and digests are pinned**
  - Kind: constraint
  - Statement: Every tested 64/126/252-bit checked arithmetic export has exactly its independently derived rows and pinned SHA-256 digest.
  - Location: `src/circuit/builtins/types/uint.rs:112` (`checked_add/checked_mul/checked_sub`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `the_wide_checked_operations_export_the_derived_rows_and_pinned_digests`

- [x] **INV-UINT-ARITH-02: wide arithmetic count formulas**
  - Kind: constraint
  - Statement: Every tested wide arithmetic export has exactly the constraint/variable count derived from its operand and result range checks.
  - Location: `src/circuit/builtins/types/uint.rs:75` (`add/mul/checked operations`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/arithmetic/r1cs.rs`
  - Covered by: `tests/unit/uint/arithmetic/r1cs.rs` `every_operation_costs_its_counted_constraints_and_variables_at_64_126_and_252_bits`

- [x] **INV-UINT-ARITH-03: snarkjs accepts bounded arithmetic witnesses**
  - Kind: interop
  - Statement: For every fitting wide checked arithmetic fixture, snarkjs accepts its honest assignment and rejects a changed claim.
  - Location: `src/circuit/builtins/types/uint.rs:112` (`checked operations`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/uint/arithmetic/external.rs`
  - Covered by: `tests/unit/uint/arithmetic/external.rs` `snarkjs_accepts_every_fitting_wide_sdk_pair_and_rejects_a_tampered_claim`

- [x] **INV-UINT-ARITH-04: checked multiplication supports Groth16**
  - Kind: interop
  - Statement: For the Uint<64> checked multiplication fixture, snarkjs setup/prove/verify succeeds with zero public inputs.
  - Location: `src/circuit/builtins/types/uint.rs:125` (`checked_mul`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/uint/arithmetic/external.rs`
  - Covered by: `tests/unit/uint/arithmetic/external.rs` `snarkjs_proves_and_verifies_a_64_bit_checked_product`

- [x] **INV-UINT-SUM-09: sum supports Groth16**
  - Kind: interop
  - Statement: For the three-operand Uint<4> sum fixture, snarkjs setup/prove/verify succeeds and its wrong claim fails wtns check.
  - Location: `src/circuit/builtins/types/uint.rs:99` (`sum`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/uint/arithmetic/external.rs`
  - Covered by: `tests/unit/uint/arithmetic/external.rs` `sum_matches_circom_and_snarkjs_accepts_only_the_true_claim`

### LT (`is_less_than`)

- [x] **INV-UINT-LT-01: is_less_than integer result**
  - Kind: semantics
  - Statement: For every pair of four-bit integers, is_less_than returns exactly 1 exactly when x<y.
  - Location: `src/circuit/builtins/types/uint.rs:168` (`is_less_than`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `all_four_bit_comparisons_min_max_and_equalities_match_integer_semantics`

- [x] **INV-UINT-LT-02: is_less_than honest relation**
  - Kind: completeness
  - Statement: For every pair of four-bit integers, the honest is_less_than fixture satisfies every exported row.
  - Location: `src/circuit/builtins/types/uint.rs:168` (`is_less_than`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-LT-03: is_less_than witness-independent shape**
  - Kind: shape
  - Statement: For every pair of four-bit integers, the is_less_than setup matrices are exactly its proving matrices.
  - Location: `src/circuit/builtins/types/uint.rs:168` (`is_less_than`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-LT-04: the claim row refuses an incremented is_less_than claim**
  - Kind: soundness
  - Statement: For every equal/unequal soundness vector, incrementing the is_less_than claim is refused by the named claim row.
  - Location: `src/circuit/builtins/types/uint.rs:168` (`is_less_than`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-LT-05: is_less_than circomlib relation**
  - Kind: equivalence
  - Statement: For every external is_less_than vector, SDK and circomlib accept exactly the same true and false claims with pinned counts.
  - Location: `src/circuit/builtins/types/uint.rs:168` (`is_less_than`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `comparisons_min_max_and_equality_match_circomlib_with_pinned_counts`

- [x] **INV-UINT-LT-06: is_less_than random u64 semantics**
  - Kind: semantics
  - Statement: For every generated u64 pair, is_less_than satisfies its host integer reference in native and proving runs.
  - Location: `src/circuit/builtins/types/uint.rs:168` (`is_less_than`)
  - Severity: High
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_u64_relations_match_the_integer_reference`

### LE (`is_less_or_equal`)

- [x] **INV-UINT-LE-01: is_less_or_equal integer result**
  - Kind: semantics
  - Statement: For every pair of four-bit integers, is_less_or_equal returns exactly 1 exactly when x<=y.
  - Location: `src/circuit/builtins/types/uint.rs:162` (`is_less_or_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `all_four_bit_comparisons_min_max_and_equalities_match_integer_semantics`

- [x] **INV-UINT-LE-02: is_less_or_equal honest relation**
  - Kind: completeness
  - Statement: For every pair of four-bit integers, the honest is_less_or_equal fixture satisfies every exported row.
  - Location: `src/circuit/builtins/types/uint.rs:162` (`is_less_or_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-LE-03: is_less_or_equal witness-independent shape**
  - Kind: shape
  - Statement: For every pair of four-bit integers, the is_less_or_equal setup matrices are exactly its proving matrices.
  - Location: `src/circuit/builtins/types/uint.rs:162` (`is_less_or_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-LE-04: the claim row refuses an incremented is_less_or_equal claim**
  - Kind: soundness
  - Statement: For every equal/unequal soundness vector, incrementing the is_less_or_equal claim is refused by the named claim row.
  - Location: `src/circuit/builtins/types/uint.rs:162` (`is_less_or_equal`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-LE-05: is_less_or_equal circomlib relation**
  - Kind: equivalence
  - Statement: For every external is_less_or_equal vector, SDK and circomlib accept exactly the same true and false claims with pinned counts.
  - Location: `src/circuit/builtins/types/uint.rs:162` (`is_less_or_equal`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `comparisons_min_max_and_equality_match_circomlib_with_pinned_counts`

- [x] **INV-UINT-LE-06: is_less_or_equal random u64 semantics**
  - Kind: semantics
  - Statement: For every generated u64 pair, is_less_or_equal satisfies its host integer reference in native and proving runs.
  - Location: `src/circuit/builtins/types/uint.rs:162` (`is_less_or_equal`)
  - Severity: High
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_u64_relations_match_the_integer_reference`

### MIN (`min`)

- [x] **INV-UINT-MIN-01: min integer result**
  - Kind: semantics
  - Statement: For every pair of four-bit integers, min returns exactly min(x,y).
  - Location: `src/circuit/builtins/types/uint.rs:185` (`min`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `all_four_bit_comparisons_min_max_and_equalities_match_integer_semantics`

- [x] **INV-UINT-MIN-02: min honest relation**
  - Kind: completeness
  - Statement: For every pair of four-bit integers, the honest min fixture satisfies every exported row.
  - Location: `src/circuit/builtins/types/uint.rs:185` (`min`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-MIN-03: min witness-independent shape**
  - Kind: shape
  - Statement: For every pair of four-bit integers, the min setup matrices are exactly its proving matrices.
  - Location: `src/circuit/builtins/types/uint.rs:185` (`min`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-MIN-04: the claim row refuses an incremented min claim**
  - Kind: soundness
  - Statement: For every equal/unequal soundness vector, incrementing the min claim is refused by the named claim row.
  - Location: `src/circuit/builtins/types/uint.rs:185` (`min`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-MIN-05: min circomlib relation**
  - Kind: equivalence
  - Statement: For every external min vector, SDK and circomlib accept exactly the same true and false claims with pinned counts.
  - Location: `src/circuit/builtins/types/uint.rs:185` (`min`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `comparisons_min_max_and_equality_match_circomlib_with_pinned_counts`

- [x] **INV-UINT-MIN-06: min random u64 semantics**
  - Kind: semantics
  - Statement: For every generated u64 pair, min satisfies its host integer reference in native and proving runs.
  - Location: `src/circuit/builtins/types/uint.rs:185` (`min`)
  - Severity: High
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_u64_relations_match_the_integer_reference`

### MAX (`max`)

- [x] **INV-UINT-MAX-01: max integer result**
  - Kind: semantics
  - Statement: For every pair of four-bit integers, max returns exactly max(x,y).
  - Location: `src/circuit/builtins/types/uint.rs:190` (`max`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `all_four_bit_comparisons_min_max_and_equalities_match_integer_semantics`

- [x] **INV-UINT-MAX-02: max honest relation**
  - Kind: completeness
  - Statement: For every pair of four-bit integers, the honest max fixture satisfies every exported row.
  - Location: `src/circuit/builtins/types/uint.rs:190` (`max`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-MAX-03: max witness-independent shape**
  - Kind: shape
  - Statement: For every pair of four-bit integers, the max setup matrices are exactly its proving matrices.
  - Location: `src/circuit/builtins/types/uint.rs:190` (`max`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-MAX-04: the claim row refuses an incremented max claim**
  - Kind: soundness
  - Statement: For every equal/unequal soundness vector, incrementing the max claim is refused by the named claim row.
  - Location: `src/circuit/builtins/types/uint.rs:190` (`max`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-MAX-05: max circomlib relation**
  - Kind: equivalence
  - Statement: For every external max vector, SDK and circomlib accept exactly the same true and false claims with pinned counts.
  - Location: `src/circuit/builtins/types/uint.rs:190` (`max`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `comparisons_min_max_and_equality_match_circomlib_with_pinned_counts`

- [x] **INV-UINT-MAX-06: max random u64 semantics**
  - Kind: semantics
  - Statement: For every generated u64 pair, max satisfies its host integer reference in native and proving runs.
  - Location: `src/circuit/builtins/types/uint.rs:190` (`max`)
  - Severity: High
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_u64_relations_match_the_integer_reference`

### EQ (`is_equal`)

- [x] **INV-UINT-EQ-01: is_equal integer result**
  - Kind: semantics
  - Statement: For every pair of four-bit integers, is_equal returns exactly 1 exactly when x=y.
  - Location: `src/circuit/builtins/types/uint.rs:213` (`is_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `all_four_bit_comparisons_min_max_and_equalities_match_integer_semantics`

- [x] **INV-UINT-EQ-02: is_equal honest relation**
  - Kind: completeness
  - Statement: For every pair of four-bit integers, the honest is_equal fixture satisfies every exported row.
  - Location: `src/circuit/builtins/types/uint.rs:213` (`is_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-EQ-03: is_equal witness-independent shape**
  - Kind: shape
  - Statement: For every pair of four-bit integers, the is_equal setup matrices are exactly its proving matrices.
  - Location: `src/circuit/builtins/types/uint.rs:213` (`is_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-EQ-04: the claim row refuses an incremented is_equal claim**
  - Kind: soundness
  - Statement: For every equal/unequal soundness vector, incrementing the is_equal claim is refused by the named claim row.
  - Location: `src/circuit/builtins/types/uint.rs:213` (`is_equal`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-EQ-05: is_equal circomlib relation**
  - Kind: equivalence
  - Statement: For every external is_equal vector, SDK and circomlib accept exactly the same true and false claims with pinned counts.
  - Location: `src/circuit/builtins/types/uint.rs:213` (`is_equal`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `comparisons_min_max_and_equality_match_circomlib_with_pinned_counts`

- [x] **INV-UINT-EQ-06: is_equal random u64 semantics**
  - Kind: semantics
  - Statement: For every generated u64 pair, is_equal satisfies its host integer reference in native and proving runs.
  - Location: `src/circuit/builtins/types/uint.rs:213` (`is_equal`)
  - Severity: High
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_u64_relations_match_the_integer_reference`

### TRAIT-EQ (`Assert::is_equal`)

- [x] **INV-UINT-TRAIT-EQ-01: Assert::is_equal integer result**
  - Kind: semantics
  - Statement: For every pair of four-bit integers, Assert::is_equal returns exactly 1 exactly when x=y.
  - Location: `src/circuit/builtins/types/uint.rs:365` (`Assert::is_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `all_four_bit_comparisons_min_max_and_equalities_match_integer_semantics`

- [x] **INV-UINT-TRAIT-EQ-02: Assert::is_equal honest relation**
  - Kind: completeness
  - Statement: For every pair of four-bit integers, the honest Assert::is_equal fixture satisfies every exported row.
  - Location: `src/circuit/builtins/types/uint.rs:365` (`Assert::is_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-TRAIT-EQ-03: Assert::is_equal witness-independent shape**
  - Kind: shape
  - Statement: For every pair of four-bit integers, the Assert::is_equal setup matrices are exactly its proving matrices.
  - Location: `src/circuit/builtins/types/uint.rs:365` (`Assert::is_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-TRAIT-EQ-04: the claim row refuses an incremented Assert::is_equal claim**
  - Kind: soundness
  - Statement: For every equal/unequal soundness vector, incrementing the Assert::is_equal claim is refused by the named claim row.
  - Location: `src/circuit/builtins/types/uint.rs:365` (`Assert::is_equal`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `all_four_bit_comparisons_have_matching_setup_and_proving_rows_and_refuse_false_claims`

- [x] **INV-UINT-TRAIT-EQ-05: Assert::is_equal circomlib relation**
  - Kind: equivalence
  - Statement: For every external Assert::is_equal vector, SDK and circomlib accept exactly the same true and false claims with pinned counts.
  - Location: `src/circuit/builtins/types/uint.rs:365` (`Assert::is_equal`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `comparisons_min_max_and_equality_match_circomlib_with_pinned_counts`

- [x] **INV-UINT-TRAIT-EQ-06: Assert::is_equal random u64 semantics**
  - Kind: semantics
  - Statement: For every generated u64 pair, Assert::is_equal satisfies its host integer reference in native and proving runs.
  - Location: `src/circuit/builtins/types/uint.rs:365` (`Assert::is_equal`)
  - Severity: High
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_u64_relations_match_the_integer_reference`

### ORDER (`ordered_below`)

- [x] **INV-UINT-ORDER-01: comparison golden rows**
  - Kind: constraint
  - Statement: Every four-bit strict/inclusive comparison exports exactly two operand decompositions, the shifted (5-bit) difference decomposition, and its top-bit claim row.
  - Location: `src/circuit/builtins/types/uint.rs:278` (`ordered_below`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `ordered_comparisons_export_the_hand_derived_four_bit_rows`

- [x] **INV-UINT-ORDER-02: wide comparison pins**
  - Kind: constraint
  - Statement: The less-than fixtures at widths 64 and 252 have exactly 197 and 761 rows respectively, with their pinned SHA-256 digests.
  - Location: `src/circuit/builtins/types/uint.rs:278` (`ordered_below`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `wide_comparison_and_division_shapes_have_pinned_counts_and_digests`

- [x] **INV-UINT-ORDER-03: 252-bit comparison edges**
  - Kind: completeness
  - Statement: For every pair selected from 0,1,2^251,2^252-1, strict and inclusive comparison fixtures satisfy exactly their integer claims.
  - Location: `src/circuit/builtins/types/uint.rs:278` (`ordered_below`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `wide_comparisons_cover_both_sides_of_the_252_bit_boundary`

- [x] **INV-UINT-EQ-07: cross-width equality uses high bits**
  - Kind: soundness
  - Statement: For every cross-width edge vector with a 4-bit left operand and 64-bit right operand, equality observes all right-operand high bits and rejects a changed output.
  - Location: `src/circuit/builtins/types/uint.rs:213` (`is_equal`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `cross_width_equality_observes_high_bits_of_the_wider_operand`

### ASSERT-LT (`assert_less_than`)

- [x] **INV-UINT-ASSERT-LT-01: assert_less_than acceptance**
  - Kind: semantics
  - Statement: For every four-bit pair, native assert_less_than accepts exactly when x<y.
  - Location: `src/circuit/builtins/types/uint.rs:156` (`assert_less_than`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-ASSERT-LT-02: assert_less_than rule diagnosis**
  - Kind: error
  - Statement: For every four-bit pair violating x<y, native assert_less_than reports exactly CircuitError.RuleBroken with the supplied relation rule.
  - Location: `src/circuit/builtins/types/uint.rs:156` (`assert_less_than`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-ASSERT-LT-03: assert_less_than coordinated forgeries fail**
  - Kind: soundness
  - Statement: For every four-bit pair, the coordinated operand digits and comparison digits/inverse candidate satisfy the assert_less_than export exactly when x<y.
  - Location: `src/circuit/builtins/types/uint.rs:156` (`assert_less_than`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `every_assertion_rejects_coordinated_false_witnesses_after_operand_range_checks`

- [x] **INV-UINT-ASSERT-LT-04: assert_less_than setup/proving agreement**
  - Kind: shape
  - Statement: For every honest assertion fixture in the shape vectors, assert_less_than setup/proving matrices compare exactly equal.
  - Location: `src/circuit/builtins/types/uint.rs:156` (`assert_less_than`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `assertions_range_zero_and_selection_constrain_their_relations`

- [x] **INV-UINT-ASSERT-LT-05: assert_less_than circom relation**
  - Kind: equivalence
  - Statement: For every external assertion pair, SDK and circom accept exactly the same assert_less_than relation even with coordinated false candidate witnesses.
  - Location: `src/circuit/builtins/types/uint.rs:156` (`assert_less_than`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `all_assertion_forms_match_circom_relations_for_honest_and_coordinated_false_witnesses`

### ASSERT-LE (`assert_less_or_equal`)

- [x] **INV-UINT-ASSERT-LE-01: assert_less_or_equal acceptance**
  - Kind: semantics
  - Statement: For every four-bit pair, native assert_less_or_equal accepts exactly when x<=y.
  - Location: `src/circuit/builtins/types/uint.rs:146` (`assert_less_or_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-ASSERT-LE-02: assert_less_or_equal rule diagnosis**
  - Kind: error
  - Statement: For every four-bit pair violating x<=y, native assert_less_or_equal reports exactly CircuitError.RuleBroken with the supplied relation rule.
  - Location: `src/circuit/builtins/types/uint.rs:146` (`assert_less_or_equal`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-ASSERT-LE-03: assert_less_or_equal coordinated forgeries fail**
  - Kind: soundness
  - Statement: For every four-bit pair, the coordinated operand digits and comparison digits/inverse candidate satisfy the assert_less_or_equal export exactly when x<=y.
  - Location: `src/circuit/builtins/types/uint.rs:146` (`assert_less_or_equal`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `every_assertion_rejects_coordinated_false_witnesses_after_operand_range_checks`

- [x] **INV-UINT-ASSERT-LE-04: assert_less_or_equal setup/proving agreement**
  - Kind: shape
  - Statement: For every honest assertion fixture in the shape vectors, assert_less_or_equal setup/proving matrices compare exactly equal.
  - Location: `src/circuit/builtins/types/uint.rs:146` (`assert_less_or_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `assertions_range_zero_and_selection_constrain_their_relations`

- [x] **INV-UINT-ASSERT-LE-05: assert_less_or_equal circom relation**
  - Kind: equivalence
  - Statement: For every external assertion pair, SDK and circom accept exactly the same assert_less_or_equal relation even with coordinated false candidate witnesses.
  - Location: `src/circuit/builtins/types/uint.rs:146` (`assert_less_or_equal`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `all_assertion_forms_match_circom_relations_for_honest_and_coordinated_false_witnesses`

### ASSERT-EQ (`assert_equal`)

- [x] **INV-UINT-ASSERT-EQ-01: assert_equal acceptance**
  - Kind: semantics
  - Statement: For every four-bit pair, native assert_equal accepts exactly when x=y.
  - Location: `src/circuit/builtins/types/uint.rs:195` (`assert_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-ASSERT-EQ-02: assert_equal rule diagnosis**
  - Kind: error
  - Statement: For every four-bit pair violating x=y, native assert_equal reports exactly CircuitError.RuleBroken with the supplied relation rule.
  - Location: `src/circuit/builtins/types/uint.rs:195` (`assert_equal`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-ASSERT-EQ-03: assert_equal coordinated forgeries fail**
  - Kind: soundness
  - Statement: For every four-bit pair, the coordinated operand digits and comparison digits/inverse candidate satisfy the assert_equal export exactly when x=y.
  - Location: `src/circuit/builtins/types/uint.rs:195` (`assert_equal`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `every_assertion_rejects_coordinated_false_witnesses_after_operand_range_checks`

- [x] **INV-UINT-ASSERT-EQ-04: assert_equal setup/proving agreement**
  - Kind: shape
  - Statement: For every honest assertion fixture in the shape vectors, assert_equal setup/proving matrices compare exactly equal.
  - Location: `src/circuit/builtins/types/uint.rs:195` (`assert_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `assertions_range_zero_and_selection_constrain_their_relations`

- [x] **INV-UINT-ASSERT-EQ-05: assert_equal circom relation**
  - Kind: equivalence
  - Statement: For every external assertion pair, SDK and circom accept exactly the same assert_equal relation even with coordinated false candidate witnesses.
  - Location: `src/circuit/builtins/types/uint.rs:195` (`assert_equal`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `all_assertion_forms_match_circom_relations_for_honest_and_coordinated_false_witnesses`

### ASSERT-NE (`assert_not_equal`)

- [x] **INV-UINT-ASSERT-NE-01: assert_not_equal acceptance**
  - Kind: semantics
  - Statement: For every four-bit pair, native assert_not_equal accepts exactly when x!=y.
  - Location: `src/circuit/builtins/types/uint.rs:204` (`assert_not_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-ASSERT-NE-02: assert_not_equal rule diagnosis**
  - Kind: error
  - Statement: For every four-bit pair violating x!=y, native assert_not_equal reports exactly CircuitError.RuleBroken with the supplied relation rule.
  - Location: `src/circuit/builtins/types/uint.rs:204` (`assert_not_equal`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-ASSERT-NE-03: assert_not_equal coordinated forgeries fail**
  - Kind: soundness
  - Statement: For every four-bit pair, the coordinated operand digits and comparison digits/inverse candidate satisfy the assert_not_equal export exactly when x!=y.
  - Location: `src/circuit/builtins/types/uint.rs:204` (`assert_not_equal`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `every_assertion_rejects_coordinated_false_witnesses_after_operand_range_checks`

- [x] **INV-UINT-ASSERT-NE-04: assert_not_equal setup/proving agreement**
  - Kind: shape
  - Statement: For every honest assertion fixture in the shape vectors, assert_not_equal setup/proving matrices compare exactly equal.
  - Location: `src/circuit/builtins/types/uint.rs:204` (`assert_not_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `assertions_range_zero_and_selection_constrain_their_relations`

- [x] **INV-UINT-ASSERT-NE-05: assert_not_equal circom relation**
  - Kind: equivalence
  - Statement: For every external assertion pair, SDK and circom accept exactly the same assert_not_equal relation even with coordinated false candidate witnesses.
  - Location: `src/circuit/builtins/types/uint.rs:204` (`assert_not_equal`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `all_assertion_forms_match_circom_relations_for_honest_and_coordinated_false_witnesses`

### TRAIT-ASSERT-EQ (`Assert::assert_equal`)

- [x] **INV-UINT-TRAIT-ASSERT-EQ-01: Assert::assert_equal acceptance**
  - Kind: semantics
  - Statement: For every four-bit pair, native Assert::assert_equal accepts exactly when x=y.
  - Location: `src/circuit/builtins/types/uint.rs:370` (`Assert::assert_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-TRAIT-ASSERT-EQ-02: Assert::assert_equal rule diagnosis**
  - Kind: error
  - Statement: For every four-bit pair violating x=y, native Assert::assert_equal reports exactly CircuitError.RuleBroken with the supplied relation rule.
  - Location: `src/circuit/builtins/types/uint.rs:370` (`Assert::assert_equal`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-TRAIT-ASSERT-EQ-03: Assert::assert_equal coordinated forgeries fail**
  - Kind: soundness
  - Statement: For every four-bit pair, the coordinated operand digits and comparison digits/inverse candidate satisfy the Assert::assert_equal export exactly when x=y.
  - Location: `src/circuit/builtins/types/uint.rs:370` (`Assert::assert_equal`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `every_assertion_rejects_coordinated_false_witnesses_after_operand_range_checks`

- [x] **INV-UINT-TRAIT-ASSERT-EQ-04: Assert::assert_equal setup/proving agreement**
  - Kind: shape
  - Statement: For every honest assertion fixture in the shape vectors, Assert::assert_equal setup/proving matrices compare exactly equal.
  - Location: `src/circuit/builtins/types/uint.rs:370` (`Assert::assert_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `assertions_range_zero_and_selection_constrain_their_relations`

- [x] **INV-UINT-TRAIT-ASSERT-EQ-05: Assert::assert_equal circom relation**
  - Kind: equivalence
  - Statement: For every external assertion pair, SDK and circom accept exactly the same Assert::assert_equal relation even with coordinated false candidate witnesses.
  - Location: `src/circuit/builtins/types/uint.rs:370` (`Assert::assert_equal`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `all_assertion_forms_match_circom_relations_for_honest_and_coordinated_false_witnesses`

### TRAIT-ASSERT-NE (`Assert::assert_not_equal`)

- [x] **INV-UINT-TRAIT-ASSERT-NE-01: Assert::assert_not_equal acceptance**
  - Kind: semantics
  - Statement: For every four-bit pair, native Assert::assert_not_equal accepts exactly when x!=y.
  - Location: `src/circuit/builtins/types/uint.rs:387` (`Assert::assert_not_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-TRAIT-ASSERT-NE-02: Assert::assert_not_equal rule diagnosis**
  - Kind: error
  - Statement: For every four-bit pair violating x!=y, native Assert::assert_not_equal reports exactly CircuitError.RuleBroken with the supplied relation rule.
  - Location: `src/circuit/builtins/types/uint.rs:387` (`Assert::assert_not_equal`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-TRAIT-ASSERT-NE-03: Assert::assert_not_equal coordinated forgeries fail**
  - Kind: soundness
  - Statement: For every four-bit pair, the coordinated operand digits and comparison digits/inverse candidate satisfy the Assert::assert_not_equal export exactly when x!=y.
  - Location: `src/circuit/builtins/types/uint.rs:387` (`Assert::assert_not_equal`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `every_assertion_rejects_coordinated_false_witnesses_after_operand_range_checks`

- [x] **INV-UINT-TRAIT-ASSERT-NE-04: Assert::assert_not_equal setup/proving agreement**
  - Kind: shape
  - Statement: For every honest assertion fixture in the shape vectors, Assert::assert_not_equal setup/proving matrices compare exactly equal.
  - Location: `src/circuit/builtins/types/uint.rs:387` (`Assert::assert_not_equal`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `assertions_range_zero_and_selection_constrain_their_relations`

- [x] **INV-UINT-TRAIT-ASSERT-NE-05: Assert::assert_not_equal circom relation**
  - Kind: equivalence
  - Statement: For every external assertion pair, SDK and circom accept exactly the same Assert::assert_not_equal relation even with coordinated false candidate witnesses.
  - Location: `src/circuit/builtins/types/uint.rs:387` (`Assert::assert_not_equal`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `all_assertion_forms_match_circom_relations_for_honest_and_coordinated_false_witnesses`

### RANGE (`assert_in_range`)

- [x] **INV-UINT-RANGE-01: assert_in_range acceptance**
  - Kind: semantics
  - Statement: For every four-bit input combination in the native domain, assert_in_range accepts exactly when low<=x<=high.
  - Location: `src/circuit/builtins/types/uint.rs:174` (`assert_in_range`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-RANGE-02: assert_in_range false relation diagnosis**
  - Kind: error
  - Statement: For every tested false assert_in_range relation, native evaluation reports exactly its supplied relation rule.
  - Location: `src/circuit/builtins/types/uint.rs:174` (`assert_in_range`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-RANGE-03: assert_in_range matrices agree**
  - Kind: shape
  - Statement: For every honest assert_in_range shape vector, setup and proving matrices compare exactly equal.
  - Location: `src/circuit/builtins/types/uint.rs:174` (`assert_in_range`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `assertions_range_zero_and_selection_constrain_their_relations`

- [x] **INV-UINT-RANGE-04: assert_in_range rejects coordinated false witnesses**
  - Kind: soundness
  - Statement: For every external false assert_in_range vector, the SDK exported rows reject its coordinated candidate witness.
  - Location: `src/circuit/builtins/types/uint.rs:174` (`assert_in_range`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `range_and_conditional_assertions_match_circom_including_disabled_inequality`

- [x] **INV-UINT-RANGE-05: assert_in_range reference relation**
  - Kind: equivalence
  - Statement: For every external assert_in_range vector, SDK and circom accept exactly the same relation.
  - Location: `src/circuit/builtins/types/uint.rs:174` (`assert_in_range`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `range_and_conditional_assertions_match_circom_including_disabled_inequality`

### IF (`Assert::assert_equal_if`)

- [x] **INV-UINT-IF-01: Assert::assert_equal_if acceptance**
  - Kind: semantics
  - Statement: For every four-bit input combination in the native domain, Assert::assert_equal_if accepts exactly when the condition is false or x=y.
  - Location: `src/circuit/builtins/types/uint.rs:375` (`Assert::assert_equal_if`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-IF-02: Assert::assert_equal_if false relation diagnosis**
  - Kind: error
  - Statement: For every tested false Assert::assert_equal_if relation, native evaluation reports exactly its supplied relation rule.
  - Location: `src/circuit/builtins/types/uint.rs:375` (`Assert::assert_equal_if`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-IF-03: Assert::assert_equal_if matrices agree**
  - Kind: shape
  - Statement: For every honest Assert::assert_equal_if shape vector, setup and proving matrices compare exactly equal.
  - Location: `src/circuit/builtins/types/uint.rs:375` (`Assert::assert_equal_if`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `assertions_range_zero_and_selection_constrain_their_relations`

- [x] **INV-UINT-IF-04: Assert::assert_equal_if rejects coordinated false witnesses**
  - Kind: soundness
  - Statement: For every external false Assert::assert_equal_if vector, the SDK exported rows reject its coordinated candidate witness.
  - Location: `src/circuit/builtins/types/uint.rs:375` (`Assert::assert_equal_if`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `range_and_conditional_assertions_match_circom_including_disabled_inequality`

- [x] **INV-UINT-IF-05: Assert::assert_equal_if reference relation**
  - Kind: equivalence
  - Statement: For every external Assert::assert_equal_if vector, SDK and circom accept exactly the same relation.
  - Location: `src/circuit/builtins/types/uint.rs:375` (`Assert::assert_equal_if`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `range_and_conditional_assertions_match_circom_including_disabled_inequality`

### ASSERT-ZERO (`assert_zero`)

- [x] **INV-UINT-ASSERT-ZERO-01: assert_zero acceptance**
  - Kind: semantics
  - Statement: For every four-bit input combination in the native domain, assert_zero accepts exactly when x=0.
  - Location: `src/circuit/builtins/types/uint.rs:223` (`assert_zero`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-ASSERT-ZERO-02: assert_zero false relation diagnosis**
  - Kind: error
  - Statement: For every tested false assert_zero relation, native evaluation reports exactly its supplied relation rule.
  - Location: `src/circuit/builtins/types/uint.rs:223` (`assert_zero`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-ASSERT-ZERO-03: assert_zero matrices agree**
  - Kind: shape
  - Statement: For every honest assert_zero shape vector, setup and proving matrices compare exactly equal.
  - Location: `src/circuit/builtins/types/uint.rs:223` (`assert_zero`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `assertions_range_zero_and_selection_constrain_their_relations`

- [x] **INV-UINT-ASSERT-ZERO-04: assert_zero rejects coordinated false witnesses**
  - Kind: soundness
  - Statement: For every external false assert_zero vector, the SDK exported rows reject its coordinated candidate witness.
  - Location: `src/circuit/builtins/types/uint.rs:223` (`assert_zero`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `zero_assertions_match_circomlib_iszero`

- [x] **INV-UINT-ASSERT-ZERO-05: assert_zero reference relation**
  - Kind: equivalence
  - Statement: For every external assert_zero vector, SDK and circom accept exactly the same relation.
  - Location: `src/circuit/builtins/types/uint.rs:223` (`assert_zero`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `zero_assertions_match_circomlib_iszero`

### ASSERT-NONZERO (`assert_not_zero`)

- [x] **INV-UINT-ASSERT-NONZERO-01: assert_not_zero acceptance**
  - Kind: semantics
  - Statement: For every four-bit input combination in the native domain, assert_not_zero accepts exactly when x!=0.
  - Location: `src/circuit/builtins/types/uint.rs:228` (`assert_not_zero`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-ASSERT-NONZERO-02: assert_not_zero false relation diagnosis**
  - Kind: error
  - Statement: For every tested false assert_not_zero relation, native evaluation reports exactly its supplied relation rule.
  - Location: `src/circuit/builtins/types/uint.rs:228` (`assert_not_zero`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-ASSERT-NONZERO-03: assert_not_zero matrices agree**
  - Kind: shape
  - Statement: For every honest assert_not_zero shape vector, setup and proving matrices compare exactly equal.
  - Location: `src/circuit/builtins/types/uint.rs:228` (`assert_not_zero`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `assertions_range_zero_and_selection_constrain_their_relations`

- [x] **INV-UINT-ASSERT-NONZERO-04: assert_not_zero rejects coordinated false witnesses**
  - Kind: soundness
  - Statement: For every external false assert_not_zero vector, the SDK exported rows reject its coordinated candidate witness.
  - Location: `src/circuit/builtins/types/uint.rs:228` (`assert_not_zero`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `zero_assertions_match_circomlib_iszero`

- [x] **INV-UINT-ASSERT-NONZERO-05: assert_not_zero reference relation**
  - Kind: equivalence
  - Statement: For every external assert_not_zero vector, SDK and circom accept exactly the same relation.
  - Location: `src/circuit/builtins/types/uint.rs:228` (`assert_not_zero`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `zero_assertions_match_circomlib_iszero`

### SELECT (`Select::select`)

- [x] **INV-UINT-SELECT-01: Select::select integer result**
  - Kind: semantics
  - Statement: For every four-bit input combination in the native vectors, Select::select returns exactly the chosen operand.
  - Location: `src/circuit/builtins/types/uint.rs:357` (`Select::select`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-SELECT-02: Select::select stable shape**
  - Kind: shape
  - Statement: For every tested Select::select branch, honest setup/proving matrices compare exactly equal.
  - Location: `src/circuit/builtins/types/uint.rs:357` (`Select::select`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `assertions_range_zero_and_selection_constrain_their_relations`

- [x] **INV-UINT-SELECT-03: Select::select false output refused**
  - Kind: soundness
  - Statement: For every Select::select soundness vector, incrementing its claim leaves the named output equality row unsatisfied.
  - Location: `src/circuit/builtins/types/uint.rs:357` (`Select::select`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `assertions_range_zero_and_selection_constrain_their_relations`

- [x] **INV-UINT-SELECT-04: Select::select circomlib match**
  - Kind: equivalence
  - Statement: For every external Select::select vector, SDK and circomlib accept exactly the same operand/output relation.
  - Location: `src/circuit/builtins/types/uint.rs:357` (`Select::select`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `selection_and_zero_match_mux1_and_iszero`

### ZERO (`is_zero`)

- [x] **INV-UINT-ZERO-01: is_zero integer result**
  - Kind: semantics
  - Statement: For every four-bit input combination in the native vectors, is_zero returns exactly 1 exactly when x=0.
  - Location: `src/circuit/builtins/types/uint.rs:218` (`is_zero`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `every_four_bit_assertion_accepts_exactly_its_integer_relation`

- [x] **INV-UINT-ZERO-02: is_zero stable shape**
  - Kind: shape
  - Statement: For every tested is_zero branch, honest setup/proving matrices compare exactly equal.
  - Location: `src/circuit/builtins/types/uint.rs:218` (`is_zero`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `assertions_range_zero_and_selection_constrain_their_relations`

- [x] **INV-UINT-ZERO-03: is_zero false output refused**
  - Kind: soundness
  - Statement: For every is_zero soundness vector, incrementing its claim leaves the named output equality row unsatisfied.
  - Location: `src/circuit/builtins/types/uint.rs:218` (`is_zero`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `assertions_range_zero_and_selection_constrain_their_relations`

- [x] **INV-UINT-ZERO-04: is_zero circomlib match**
  - Kind: equivalence
  - Statement: For every external is_zero vector, SDK and circomlib accept exactly the same operand/output relation.
  - Location: `src/circuit/builtins/types/uint.rs:218` (`is_zero`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `selection_and_zero_match_mux1_and_iszero`

### DIV (`div_rem`)

- [x] **INV-UINT-DIV-01: division integer result**
  - Kind: semantics
  - Statement: For every four-bit dividend and nonzero four-bit divisor, native div_rem returns exactly the host quotient and remainder.
  - Location: `src/circuit/builtins/types/uint.rs:233` (`div_rem`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `division_accepts_exactly_nonzero_divisors_and_fitting_quotients`

- [x] **INV-UINT-DIV-02: zero and oversized quotients refused**
  - Kind: error
  - Statement: For every four-bit division vector with zero divisor or quotient exceeding its declared width, native div_rem reports exactly the supplied RuleBroken.
  - Location: `src/circuit/builtins/types/uint.rs:233` (`div_rem`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/relations/native.rs`
  - Covered by: `tests/unit/uint/relations/native.rs` `division_accepts_exactly_nonzero_divisors_and_fitting_quotients`

- [x] **INV-UINT-DIV-03: division satisfies every row**
  - Kind: completeness
  - Statement: For every four-bit division with nonzero divisor and the 128-bit boundary vectors, honest quotient/remainder witnesses satisfy every exported row.
  - Location: `src/circuit/builtins/types/uint.rs:233` (`div_rem`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `division_rows_fix_both_hints_for_all_four_bit_divisions`

- [x] **INV-UINT-DIV-04: division shape is independent of its witness**
  - Kind: shape
  - Statement: For every four-bit division with nonzero divisor, setup and proving matrices compare exactly equal.
  - Location: `src/circuit/builtins/types/uint.rs:233` (`div_rem`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `division_rows_fix_both_hints_for_all_four_bit_divisions`

- [x] **INV-UINT-DIV-05: 64-bit division digest**
  - Kind: constraint
  - Statement: The Division<64,64,64> export has exactly 328 constraints and 327 variables with pinned digest 99b1adc46f05c31b018de28fd2a43c9bee3cbccc660b79cb32c07fbe43e01c38.
  - Location: `src/circuit/builtins/types/uint.rs:233` (`div_rem`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `wide_comparison_and_division_shapes_have_pinned_counts_and_digests`

- [x] **INV-UINT-DIV-06: coordinated division forgeries fail**
  - Kind: soundness
  - Statement: For every enumerated four-bit quotient/remainder candidate and division edge vector, coordinated hints, claims and digits satisfy all rows exactly when d!=0, q*d+r=x and r<d.
  - Location: `src/circuit/builtins/types/uint.rs:233` (`div_rem`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `division_refuses_every_dishonest_bounded_quotient_and_remainder_and_a_zero_divisor`

- [x] **INV-UINT-DIV-07: the rows fix both hints and outputs**
  - Kind: soundness
  - Statement: For every division soundness vector, changing either output or either internal division hint is refused.
  - Location: `src/circuit/builtins/types/uint.rs:233` (`div_rem`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/uint/relations/r1cs.rs`
  - Covered by: `tests/unit/uint/relations/r1cs.rs` `division_rows_fix_both_hints_for_all_four_bit_divisions`

- [x] **INV-UINT-DIV-08: division matches circom relation**
  - Kind: equivalence
  - Statement: For every external division vector and changed quotient/remainder, SDK and circom accept exactly the same bounded division relation.
  - Location: `src/circuit/builtins/types/uint.rs:233` (`div_rem`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `division_matches_the_bounded_integer_relation_in_circom`

- [x] **INV-UINT-DIV-09: random u64 division matches integers**
  - Kind: soundness
  - Statement: For every generated u64 dividend and nonzero divisor, the honest host quotient/remainder passes while either changed claim is refused.
  - Location: `src/circuit/builtins/types/uint.rs:233` (`div_rem`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_u64_divisions_match_integer_quotient_and_remainder`

- [x] **INV-UINT-LT-07: is_less_than snarkjs interoperability**
  - Kind: interop
  - Statement: For the representative is_less_than fixture, snarkjs accepts the honest witness, rejects its changed claim and completes Groth16 setup/prove/verify with zero public inputs.
  - Location: `src/circuit/builtins/types/uint.rs:168` (`is_less_than`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `snarkjs_proves_comparison_division_selection_and_zero_and_rejects_false_claims`

- [x] **INV-UINT-DIV-10: div_rem snarkjs interoperability**
  - Kind: interop
  - Statement: For the representative div_rem fixture, snarkjs accepts the honest witness, rejects its changed claim and completes Groth16 setup/prove/verify with zero public inputs.
  - Location: `src/circuit/builtins/types/uint.rs:233` (`div_rem`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `snarkjs_proves_comparison_division_selection_and_zero_and_rejects_false_claims`

- [x] **INV-UINT-SELECT-05: Select::select snarkjs interoperability**
  - Kind: interop
  - Statement: For the representative Select::select fixture, snarkjs accepts the honest witness, rejects its changed claim and completes Groth16 setup/prove/verify with zero public inputs.
  - Location: `src/circuit/builtins/types/uint.rs:357` (`Select::select`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `snarkjs_proves_comparison_division_selection_and_zero_and_rejects_false_claims`

- [x] **INV-UINT-ZERO-05: is_zero snarkjs interoperability**
  - Kind: interop
  - Statement: For the representative is_zero fixture, snarkjs accepts the honest witness, rejects its changed claim and completes Groth16 setup/prove/verify with zero public inputs.
  - Location: `src/circuit/builtins/types/uint.rs:218` (`is_zero`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/uint/relations/external.rs`
  - Covered by: `tests/unit/uint/relations/external.rs` `snarkjs_proves_comparison_division_selection_and_zero_and_rejects_false_claims`

### PICUS (`TryFrom`)

- [ ] **INV-UINT-PICUS-01: normalized construction determinism**
  - Kind: equivalence
  - Statement: For every tested construction width 4,64,252, Picus returns Safe for both circomlib Num2Bits and the SDK export after solution-preserving boolean/linear row normalization.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/construction/picus.rs`
  - Covered by: `tests/unit/uint/construction/picus.rs` `picus_checks_normalized_range_checks_with_a_bounded_solver_budget`
  - Partial coverage: All widths returned Safe in an initial run; 252-bit SDK and circom exports returned Unknown within 20 seconds under concurrent integration load. Bounded checks reject Unsafe and retain Unknown as incomplete determinism evidence.

- [ ] **INV-UINT-PICUS-02: raw construction determinism**
  - Kind: equivalence
  - Statement: For every raw construction export at widths 4 and 64, Picus proves all bit witnesses uniquely fixed by the input.
  - Location: `src/circuit/builtins/types/uint.rs:306` (`TryFrom`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/construction/picus.rs`
  - Covered by: `tests/unit/uint/construction/picus.rs` `picus_checks_raw_exports_with_a_bounded_solver_budget`
  - Partial coverage: Raw Uint<4> returned Safe initially and Unknown under concurrent load; raw Uint<64> returned Unknown within 10 seconds. The normalized checks are tracked separately.

- [ ] **INV-UINT-PICUS-03: arithmetic determinism**
  - Kind: equivalence
  - Statement: For every arithmetic Picus fixture, SDK and circom outputs are uniquely fixed by the operands.
  - Location: `src/circuit/builtins/types/uint.rs:75` (`arithmetic operations`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/arithmetic/picus.rs`
  - Covered by: `tests/unit/uint/arithmetic/picus.rs` `picus_checks_arithmetic_claims_with_a_bounded_solver_budget`
  - Partial coverage: All 4-bit arithmetic pairs and 64-bit checked multiplication returned Safe. The 64-bit checked-add/sub SDK exports returned Unknown within 20 seconds while their circom references returned Safe.

- [ ] **INV-UINT-PICUS-04: relation determinism**
  - Kind: equivalence
  - Statement: For every comparison, min/max, equality, zero, selection and division Picus fixture, its outputs are uniquely fixed by its inputs.
  - Location: `src/circuit/builtins/types/uint.rs:146` (`comparisons/div_rem/traits`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/relations/picus.rs`
  - Covered by: `tests/unit/uint/relations/picus.rs` `picus_checks_relation_outputs_with_a_bounded_solver_budget`
  - Partial coverage: Equality, zero and selection returned Safe in both circuits. Less-than/less-or-equal/min/max SDK exports returned Unknown (circom Safe); division returned Unknown in both circuits within 20 seconds.

- [ ] **INV-UINT-PICUS-05: sum determinism**
  - Kind: equivalence
  - Statement: The sum Picus fixtures prove the claim uniquely fixed by all three inputs.
  - Location: `src/circuit/builtins/types/uint.rs:99` (`sum`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/arithmetic/picus.rs`
  - Covered by: `tests/unit/uint/arithmetic/picus.rs` `picus_checks_sum_determinism`
  - Partial coverage: Both circuits returned Safe in the filtered run; the bounded test permits Unknown under load and rejects Unsafe, so this remains partial.

- [ ] **INV-UINT-PICUS-06: narrowing determinism**
  - Kind: equivalence
  - Statement: The narrowing Picus fixtures prove all digits and the claim uniquely fixed by the input.
  - Location: `src/circuit/builtins/types/uint.rs:333` (`conversions!`)
  - Severity: High
  - Suggested test: external; `tests/unit/uint/conversions.rs`
  - Covered by: `tests/unit/uint/conversions.rs` `picus_checks_narrowing_determinism`
  - Partial coverage: Both circuits returned Safe in the filtered run; the bounded test permits Unknown under load and rejects Unsafe, so this remains partial.

### Generated conversion and assertion properties

- [x] **INV-UINT-CONST-05: generated constants preserve integer values**
  - Kind: semantics
  - Statement: For every generated u64 x, Uint<64>::constant(x) has exactly value x, while Uint<64>::zero has exactly value zero.
  - Location: `src/circuit/builtins/types/uint.rs:46` (`constant/zero`)
  - Severity: High
  - Suggested test: property; `tests/unit/uint/construction/properties.rs`
  - Covered by: `tests/unit/uint/construction/properties.rs` `random_constants_and_bool_conversions_keep_integer_values_and_bind_claims` (property)

- [x] **INV-UINT-BOOL-04: the equality rule fixes generated boolean conversion claims**
  - Kind: soundness
  - Statement: For every generated positive offset and both boolean inputs, changing the converted Uint claim by that offset is rejected by exactly its named native and proving equality rule.
  - Location: `src/circuit/builtins/types/uint.rs:294` (`From<Bool>`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/construction/properties.rs`
  - Covered by: `tests/unit/uint/construction/properties.rs` `random_constants_and_bool_conversions_keep_integer_values_and_bind_claims` (property)

- [x] **INV-UINT-INTO-04: the equality row fixes generated field conversion claims**
  - Kind: soundness
  - Statement: For every generated fitting alias input, the claim asserted after CircuitVar::from is exactly the integer input; incrementing that claim fails exactly its equality row.
  - Location: `src/circuit/builtins/types/uint.rs:300` (`From<Uint> for CircuitVar`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/conversions.rs`
  - Covered by: `tests/unit/uint/conversions.rs` `random_conversion_roundtrips_hold_and_false_claims_are_rejected` (property)

- [x] **INV-UINT-WIDEN-04: the equality rule fixes generated widened claims**
  - Kind: soundness
  - Statement: For every generated fitting input in all ten widening alias pairs, the widened claim is exactly the input integer; incrementing it fails exactly the named equality rule.
  - Location: `src/circuit/builtins/types/uint.rs:326` (`conversions!`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/conversions.rs`
  - Covered by: `tests/unit/uint/conversions.rs` `random_conversion_roundtrips_hold_and_false_claims_are_rejected` (property)

- [x] **INV-UINT-ASSERT-LT-06: generated assertion candidates match host comparisons**
  - Kind: soundness
  - Statement: For every generated u64 pair and forced equal and strictly ordered companion pairs, a coordinated assert_less_than witness satisfies all exported rows exactly when x<y; every rejected native case names the supplied rule.
  - Location: `src/circuit/builtins/types/uint.rs:156` (`assert_less_than`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_assertions_match_host_relations_with_forced_equal_and_unequal_pairs` (property)

- [x] **INV-UINT-ASSERT-LE-06: generated assertion candidates match host comparisons**
  - Kind: soundness
  - Statement: For every generated u64 pair and forced equal and strictly ordered companion pairs, a coordinated assert_less_or_equal witness satisfies all exported rows exactly when x<=y; every rejected native case names the supplied rule.
  - Location: `src/circuit/builtins/types/uint.rs:146` (`assert_less_or_equal`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_assertions_match_host_relations_with_forced_equal_and_unequal_pairs` (property)

- [x] **INV-UINT-ASSERT-EQ-06: generated assertion candidates match host comparisons**
  - Kind: soundness
  - Statement: For every generated u64 pair and forced equal and strictly ordered companion pairs, a coordinated assert_equal witness satisfies all exported rows exactly when x=y; every rejected native case names the supplied rule.
  - Location: `src/circuit/builtins/types/uint.rs:195` (`assert_equal`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_assertions_match_host_relations_with_forced_equal_and_unequal_pairs` (property)

- [x] **INV-UINT-ASSERT-NE-06: generated assertion candidates match host comparisons**
  - Kind: soundness
  - Statement: For every generated u64 pair and forced equal and strictly ordered companion pairs, a coordinated assert_not_equal witness satisfies all exported rows exactly when x!=y; every rejected native case names the supplied rule.
  - Location: `src/circuit/builtins/types/uint.rs:204` (`assert_not_equal`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_assertions_match_host_relations_with_forced_equal_and_unequal_pairs` (property)

- [x] **INV-UINT-TRAIT-ASSERT-EQ-06: generated assertion candidates match host comparisons**
  - Kind: soundness
  - Statement: For every generated u64 pair and forced equal and strictly ordered companion pairs, a coordinated Assert::assert_equal witness satisfies all exported rows exactly when x=y; every rejected native case names the supplied rule.
  - Location: `src/circuit/builtins/types/uint.rs:370` (`Assert::assert_equal`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_assertions_match_host_relations_with_forced_equal_and_unequal_pairs` (property)

- [x] **INV-UINT-TRAIT-ASSERT-NE-06: generated assertion candidates match host comparisons**
  - Kind: soundness
  - Statement: For every generated u64 pair and forced equal and strictly ordered companion pairs, a coordinated Assert::assert_not_equal witness satisfies all exported rows exactly when x!=y; every rejected native case names the supplied rule.
  - Location: `src/circuit/builtins/types/uint.rs:387` (`Assert::assert_not_equal`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_assertions_match_host_relations_with_forced_equal_and_unequal_pairs` (property)

- [x] **INV-UINT-IF-06: generated conditional equality enforces enabled comparisons**
  - Kind: soundness
  - Statement: For every generated operand pair, forced equal/unequal companions and both conditions, the coordinated conditional assertion witness satisfies all rows exactly when the condition is false or the operands are equal.
  - Location: `src/circuit/builtins/types/uint.rs:375` (`Assert::assert_equal_if`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_assertions_match_host_relations_with_forced_equal_and_unequal_pairs` (property)

- [x] **INV-UINT-ASSERT-ZERO-06: generated zero assertions enforce zero**
  - Kind: soundness
  - Statement: For every generated u64 value and forced zero/nonzero companions, the coordinated assert_zero witness satisfies every row exactly when the host integer is zero.
  - Location: `src/circuit/builtins/types/uint.rs:223` (`assert_zero`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_zero_checks_bind_the_predicate_and_enforce_both_zero_assertions` (property)

- [x] **INV-UINT-ASSERT-NONZERO-06: generated nonzero assertions enforce nonzero**
  - Kind: soundness
  - Statement: For every generated u64 value and forced zero/nonzero companions, the coordinated assert_not_zero witness including its inverse hint satisfies every row exactly when the host integer is nonzero.
  - Location: `src/circuit/builtins/types/uint.rs:228` (`assert_not_zero`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_zero_checks_bind_the_predicate_and_enforce_both_zero_assertions` (property)

- [x] **INV-UINT-ZERO-06: the equality rule fixes generated is_zero results**
  - Kind: soundness
  - Statement: For every generated u64 value and forced zero/nonzero companions, the is_zero result is exactly the host zero predicate; flipping its claim fails exactly the named native and proving equality rule.
  - Location: `src/circuit/builtins/types/uint.rs:218` (`is_zero`)
  - Severity: Critical
  - Suggested test: property; `tests/unit/uint/relations/properties.rs`
  - Covered by: `tests/unit/uint/relations/properties.rs` `random_zero_checks_bind_the_predicate_and_enforce_both_zero_assertions` (property)
