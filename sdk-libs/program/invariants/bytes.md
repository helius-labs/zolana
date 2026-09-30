# Bytes and hash_bytes Invariants

ID prefixes: `INV-BYTES`, `INV-HASH-BYTES`. Tests live in `tests/unit/bytes/`.
The public hash entry point is `Bytes<N>::hash_bytes()`: its input bytes are already
range-checked and its length is fixed by N. Shared exporter/statement invariants
live in `cross-cutting.md`.

Source references use `src/circuit/builtins/types/bytes.rs`,
`src/circuit/builtins/gadgets/hash_bytes.rs`, and `src/conversion/bytes.rs`.
No SPEC_DIVERGENCE was found against `../spec.md`.

Split and pack errors keep the conversion caller's location when they pass through the
bit-decomposition helper. The tests check the exact caller file and line of value-overflow
and unsupported-width errors for both owned and borrowed split forms.

Picus `Unknown` does not prove determinism. The bounded checks below leave
the corresponding invariants unticked; their tests reject `Unsafe` and print
both verdicts. No test is ignored. The hash function is defined for a fixed
byte length: leading zero bytes can alias across different lengths, as in the
native reference's documented contract.

## Constants, byte access and allocation (`constant`, `default`, `bytes`)

- [x] **INV-BYTES-ALLOC-01: Byte order**
  - Kind: semantics
  - Statement: For every listed constant byte array, `bytes()` returns exactly its byte field constants in input order.
  - Location: `src/circuit/builtins/types/bytes.rs:22-34` (`constant`, `bytes`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/convert/native.rs`.
  - Covered by: `tests/unit/bytes/convert/native.rs::constant_bytes_are_one_constant_per_byte_in_order`.

- [x] **INV-BYTES-ALLOC-02: Default zeros**
  - Kind: semantics
  - Statement: For every tested width 0, 3 and 32, every default byte is exactly constant zero.
  - Location: `src/circuit/builtins/types/bytes.rs:95-98` (`default`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/convert/native.rs`.
  - Covered by: `tests/unit/bytes/convert/native.rs::default_bytes_are_constant_zeros`.

- [x] **INV-BYTES-ALLOC-03: Native byte allocation**
  - Kind: semantics
  - Statement: For every allocation edge vector, native allocation returns exactly one constant per input byte.
  - Location: `src/conversion/bytes.rs:14-31` (`instantiate`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/convert/native.rs`.
  - Covered by: `tests/unit/bytes/convert/native.rs::a_byte_proof_input_instantiates_to_one_constant_per_byte_natively`.

- [x] **INV-BYTES-ALLOC-04: Byte golden rows**
  - Kind: constraint
  - Statement: For every byte in the one-byte and two-byte fixtures, exactly eight boolean rows and one recomposition row constrain its value.
  - Location: `src/conversion/bytes.rs:14-31` (`instantiate`).
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::a_byte_proof_input_exports_exactly_eight_boolean_rows_and_one_recomposition_row`.

- [x] **INV-BYTES-ALLOC-05: Byte cost**
  - Kind: constraint
  - Statement: For every tested width N in {0,1,2,31,32}, byte allocation exports exactly 9N rows and 9N private variables.
  - Location: `src/conversion/bytes.rs:14-31` (`instantiate`).
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::every_byte_proof_input_costs_exactly_nine_constraints_and_nine_variables`.

- [x] **INV-BYTES-ALLOC-06: Constant frame**
  - Kind: constraint
  - Statement: For the constant construction, split and pack fixture, the number of constraints is exactly zero and the number of variables is exactly one constant wire.
  - Location: `src/circuit/builtins/types/bytes.rs:22-98` (`constant`, `try_from`, `default`).
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::constant_bytes_add_no_constraint_and_no_variable`.

- [x] **INV-BYTES-ALLOC-07: Byte completeness**
  - Kind: completeness
  - Statement: Every listed valid byte array satisfies every exported byte-allocation row.
  - Location: `src/conversion/bytes.rs:14-31` (`instantiate`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::every_valid_byte_proof_input_satisfies_every_row`.

- [x] **INV-BYTES-ALLOC-08: Byte range soundness**
  - Kind: soundness
  - Statement: Every listed value of 256 or greater leaves a byte-range row unsatisfied, including attacks that alter a bit to make recomposition hold.
  - Location: `src/conversion/bytes.rs:14-31` (`instantiate`).
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::a_byte_witness_of_256_or_more_leaves_a_row_of_its_range_check_unsatisfied`.

- [x] **INV-BYTES-ALLOC-09: Byte tamper diagnostic**
  - Kind: error
  - Statement: Every listed tampered byte or bit is refused with exactly its byte-allocation rule.
  - Location: `src/conversion/bytes.rs:14-31` (`instantiate`).
  - Error: `ProverErrorKind::ProofInputsBreakRule`.
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::a_tampered_byte_or_bit_breaks_the_byte_proof_input_rule`.

- [x] **INV-BYTES-ALLOC-10: No free byte variables**
  - Kind: soundness
  - Statement: For every allocation edge vector, the private-variable report contains exactly no free or tolerated variables.
  - Location: `src/conversion/bytes.rs:14-31` (`instantiate`).
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::no_byte_or_bit_of_a_byte_proof_input_is_free`.

- [x] **INV-BYTES-ALLOC-11: Byte reference**
  - Kind: equivalence
  - Statement: For every listed out-of-range byte witness, both the SDK rows and circomlib Num2Bits(8) refuse the witness.
  - Location: `src/conversion/bytes.rs:14-31` (`instantiate`).
  - Severity: High
  - Suggested test: external; `tests/unit/bytes/convert/external.rs`.
  - Covered by: `tests/unit/bytes/convert/external.rs::a_byte_of_256_or_more_is_refused_by_the_sdk_rows_and_by_circomlib_num2bits`.

- [ ] **INV-BYTES-ALLOC-12: Byte decomposition determinism**
  - Kind: soundness
  - Statement: Every bit of the two-byte allocation fixture is fixed by the byte inputs.
  - Location: `src/conversion/bytes.rs:14-31` (`instantiate`).
  - Severity: Critical
  - Suggested test: external; `tests/unit/bytes/convert/picus.rs`.
  - Partial coverage: SDK Picus returns Unknown at the 15-second limit; uniqueness of all bits is not proved. Test: `tests/unit/bytes/convert/picus.rs::picus_checks_byte_allocation_with_a_bounded_timeout`.

- [x] **INV-BYTES-ALLOC-13: Allocation shape**
  - Kind: shape
  - Statement: Every honest allocation edge vector has exactly identical setup and proving matrices.
  - Location: `src/conversion/bytes.rs:14-31` (`instantiate`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::every_valid_byte_proof_input_satisfies_every_row`.

- [x] **INV-BYTES-ALLOC-14: Allocation witness interop**
  - Kind: interop
  - Statement: snarkjs accepts the honest byte-allocation witness and refuses a byte wire changed to 256.
  - Location: `src/conversion/bytes.rs:14-31` (`instantiate`).
  - Severity: Medium
  - Suggested test: external; `tests/unit/bytes/convert/external.rs`.
  - Covered by: `tests/unit/bytes/convert/external.rs::snarkjs_accepts_every_honest_conversion_and_rejects_a_tampered_one`.

## Splitting a field (`TryFrom<CircuitVar>`, owned and borrowed)

- [x] **INV-BYTES-SPLIT-01: Big-endian split**
  - Kind: semantics
  - Statement: For every valid edge vector, both conversion forms return exactly the listed big-endian bytes.
  - Location: `src/circuit/builtins/types/bytes.rs:47-72` (`try_from`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/convert/native.rs`.
  - Covered by: `tests/unit/bytes/convert/native.rs::a_split_constant_is_its_big_endian_bytes_in_every_form`.

- [x] **INV-BYTES-SPLIT-02: Split golden rows**
  - Kind: constraint
  - Statement: The exports at N=0,1,2 contain exactly 8N boolean rows, one value recomposition row and N byte-claim rows in the hand-derived order.
  - Location: `src/circuit/builtins/types/bytes.rs:51-62` (`try_from`).
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::a_split_exports_its_bits_then_the_value_row_then_one_row_per_byte_most_significant_first`.

- [x] **INV-BYTES-SPLIT-03: Split cost**
  - Kind: constraint
  - Statement: For every tested split width N in {0,1,2,31}, the fixture exports exactly 9N+1 constraints and 9N+2 variables.
  - Location: `src/circuit/builtins/types/bytes.rs:51-62` (`try_from`).
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::a_split_into_n_bytes_costs_exactly_9n_plus_1_constraints`.

- [x] **INV-BYTES-SPLIT-04: Operand form identity**
  - Kind: constraint
  - Statement: For every edge-vector width, both split operand forms export byte-identical R1CS.
  - Location: `src/circuit/builtins/types/bytes.rs:47-72` (`try_from`).
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::both_split_forms_and_both_pack_forms_export_byte_identical_r1cs`.

- [x] **INV-BYTES-SPLIT-05: Split witness layout**
  - Kind: constraint
  - Statement: For every two-byte split operand form, the exported assignment is exactly [1,value,claimed byte 0,claimed byte 1,value bits least significant first].
  - Location: `src/circuit/builtins/types/bytes.rs:51-62` (`try_from`).
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::the_split_assignment_is_the_value_the_claimed_bytes_then_the_value_bits`.

- [x] **INV-BYTES-SPLIT-06: Split completeness**
  - Kind: completeness
  - Statement: Every valid split edge vector satisfies every exported row in both operand forms.
  - Location: `src/circuit/builtins/types/bytes.rs:47-72` (`try_from`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::every_valid_split_and_pack_satisfies_every_row`.

- [x] **INV-BYTES-SPLIT-07: Wrong byte claim**
  - Kind: soundness
  - Statement: Every listed wrong split leaves exactly its first wrong byte-claim row as the first unsatisfied row.
  - Location: `src/circuit/builtins/types/bytes.rs:51-62` (`try_from`).
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::every_wrong_split_claim_leaves_its_first_wrong_byte_row_unsatisfied`.

- [x] **INV-BYTES-SPLIT-08: Oversized value row**
  - Kind: soundness
  - Statement: Every listed oversized field value leaves its split value-recomposition row unsatisfied.
  - Location: `src/circuit/builtins/types/bytes.rs:51-62` (`try_from`).
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::a_value_too_large_for_its_bytes_leaves_the_unlabelled_value_row_unsatisfied`.

- [x] **INV-BYTES-SPLIT-09: All supported widths**
  - Kind: shape
  - Statement: For every width N from 0 through 31, the honest round-trip fixture has exactly identical setup and proving matrices.
  - Location: `src/circuit/builtins/types/bytes.rs:47-93` (`try_from`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::every_supported_byte_width_round_trips_with_the_same_setup_and_proving_shape`.

- [x] **INV-BYTES-SPLIT-10: Oversized native value**
  - Kind: error
  - Statement: Every listed native value too large for N bytes returns exactly CircuitError.ValueTooLarge.
  - Location: `src/circuit/builtins/types/bytes.rs:52` (`try_from`).
  - Error: `CircuitErrorKind::ValueTooLarge`.
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/convert/native.rs`.
  - Covered by: `tests/unit/bytes/convert/native.rs::a_constant_too_large_for_its_bytes_fails_to_split_with_value_too_large`.

- [x] **INV-BYTES-SPLIT-11: Unsupported split width**
  - Kind: error
  - Statement: Every owned or borrowed split into 32 bytes returns exactly CircuitError.BitWidthTooLarge.
  - Location: `src/circuit/builtins/types/bytes.rs:52` (`try_from`).
  - Error: `CircuitErrorKind::BitWidthTooLarge`.
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/convert/native.rs`.
  - Covered by: `tests/unit/bytes/convert/native.rs::splitting_into_32_bytes_fails_with_bit_width_too_large`.

- [x] **INV-BYTES-SPLIT-12: Unsupported setup width**
  - Kind: error
  - Statement: Every 32-byte split or pack fixture refuses R1CS export with exactly CircuitError.BitWidthTooLarge.
  - Location: `src/circuit/builtins/types/bytes.rs:52,79-80` (`try_from`).
  - Error: `CircuitErrorKind::BitWidthTooLarge`.
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::a_32_byte_split_or_pack_fails_to_export_with_bit_width_too_large`.

- [x] **INV-BYTES-SPLIT-13: Split refusal location**
  - Kind: error
  - Statement: Every listed split refusal reports the fixture caller file; both owned and borrowed direct conversions report exactly the caller file and line for ValueTooLarge and BitWidthTooLarge.
  - Location: `src/circuit/builtins/types/bytes.rs:52` (`try_from`).
  - Error: `CircuitErrorKind::ValueTooLarge / CircuitErrorKind::BitWidthTooLarge`.
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/convert/native.rs`.
  - Covered by: `tests/unit/bytes/convert/native.rs::a_split_refusal_is_located_at_the_caller`.

- [x] **INV-BYTES-SPLIT-14: Split relation**
  - Kind: equivalence
  - Statement: For every listed two-byte split case, the SDK and the circomlib Num2Bits reference accept exactly when the claimed big-endian bytes match.
  - Location: `src/circuit/builtins/types/bytes.rs:47-72` (`try_from`).
  - Severity: High
  - Suggested test: external; `tests/unit/bytes/convert/external.rs`.
  - Covered by: `tests/unit/bytes/convert/external.rs::a_split_is_relation_equivalent_to_num2bits_and_big_endian_bytes`.

- [x] **INV-BYTES-SPLIT-15: Conversion interop**
  - Kind: interop
  - Statement: For every tested allocation, split and pack export, snarkjs accepts the honest witness and refuses the specified tampered witness.
  - Location: `src/circuit/builtins/types/bytes.rs:47-93` (`try_from`).
  - Severity: Medium
  - Suggested test: external; `tests/unit/bytes/convert/external.rs`.
  - Covered by: `tests/unit/bytes/convert/external.rs::snarkjs_accepts_every_honest_conversion_and_rejects_a_tampered_one`.

- [x] **INV-BYTES-SPLIT-16: Random split soundness**
  - Kind: soundness
  - Statement: For every generated 31-byte input, changing one claimed split byte is refused.
  - Location: `src/circuit/builtins/types/bytes.rs:47-72` (`try_from`).
  - Severity: Critical
  - Suggested test: property (proptest); `tests/unit/bytes/convert/properties.rs`.
  - Covered by: `tests/unit/bytes/convert/properties.rs::random_31_byte_pack_and_split_agree_and_reject_changed_claims`.

- [ ] **INV-BYTES-SPLIT-17: Split determinism**
  - Kind: soundness
  - Statement: Every claimed split byte is fixed by the input field value.
  - Location: `src/circuit/builtins/types/bytes.rs:47-72` (`try_from`).
  - Severity: Critical
  - Suggested test: external; `tests/unit/bytes/convert/picus.rs`.
  - Partial coverage: SDK Picus returns Unknown at 15 seconds; circom returned Safe in the first run but can also return Unknown under concurrent tool load. SDK uniqueness is not proved. Test: `tests/unit/bytes/convert/picus.rs::picus_checks_split_determinism_with_a_bounded_timeout`.

## Packing bytes (`TryFrom<Bytes>`, owned and borrowed)

- [x] **INV-BYTES-PACK-01: Big-endian packing**
  - Kind: semantics
  - Statement: For every valid edge vector, both packing forms return exactly the listed big-endian field value.
  - Location: `src/circuit/builtins/types/bytes.rs:74-93` (`try_from`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/convert/native.rs`.
  - Covered by: `tests/unit/bytes/convert/native.rs::packed_constant_bytes_are_their_big_endian_value_in_every_form`.

- [x] **INV-BYTES-PACK-02: Packing golden rows**
  - Kind: constraint
  - Statement: For N=0,1,2 the packing fixture exports exactly the hand-derived byte range rows followed by one big-endian packed-value row.
  - Location: `src/circuit/builtins/types/bytes.rs:78-83` (`try_from`).
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::a_pack_exports_the_byte_range_checks_then_exactly_one_packed_row`.

- [x] **INV-BYTES-PACK-03: Packing frame**
  - Kind: constraint
  - Statement: For every tested width N in {0,1,2,31}, packing adds exactly no rows or variables beyond the byte allocation and one output-claim row.
  - Location: `src/circuit/builtins/types/bytes.rs:78-83` (`try_from`).
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::packing_adds_no_constraint_and_no_variable_beyond_the_byte_checks`.

- [x] **INV-BYTES-PACK-04: Packing completeness**
  - Kind: completeness
  - Statement: Every valid packing edge vector satisfies every exported row in both operand forms.
  - Location: `src/circuit/builtins/types/bytes.rs:74-93` (`try_from`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::every_valid_split_and_pack_satisfies_every_row`.

- [x] **INV-BYTES-PACK-05: Packing wrong claim**
  - Kind: soundness
  - Statement: Every listed wrong packed output leaves exactly the packed-claim row unsatisfied.
  - Location: `src/circuit/builtins/types/bytes.rs:78-83` (`try_from`).
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::every_wrong_packed_claim_leaves_exactly_the_packed_row_unsatisfied`.

- [x] **INV-BYTES-PACK-06: Packing aliases refused**
  - Kind: soundness
  - Statement: The byte pair [0,258] claiming 258 is refused by exactly the second byte range check despite satisfying the packing equation.
  - Location: `src/circuit/builtins/types/bytes.rs:78-83` (`try_from`).
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::only_the_byte_range_checks_refuse_bytes_that_pack_to_the_same_value`.

- [x] **INV-BYTES-PACK-07: Packing unsupported width**
  - Kind: error
  - Statement: Every native 32-byte packing form returns exactly CircuitError.BitWidthTooLarge located at the caller.
  - Location: `src/circuit/builtins/types/bytes.rs:79-80` (`try_from`).
  - Error: `CircuitErrorKind::BitWidthTooLarge`.
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/convert/native.rs`.
  - Covered by: `tests/unit/bytes/convert/native.rs::packing_32_bytes_fails_at_the_caller_with_bit_width_too_large`.

- [x] **INV-BYTES-PACK-08: Packing relation**
  - Kind: equivalence
  - Statement: For every listed two-byte packing case, the SDK and the checked-byte circom reference accept exactly the same relation.
  - Location: `src/circuit/builtins/types/bytes.rs:74-93` (`try_from`).
  - Severity: High
  - Suggested test: external; `tests/unit/bytes/convert/external.rs`.
  - Covered by: `tests/unit/bytes/convert/external.rs::a_pack_is_relation_equivalent_to_checked_bytes_and_a_big_endian_sum`.

- [x] **INV-BYTES-PACK-09: Conversion reference sizes**
  - Kind: constraint
  - Statement: The SDK and circom allocation/split/pack fixture constraint and variable counts are exactly the pinned pairs.
  - Location: `src/circuit/builtins/types/bytes.rs:47-93` (`try_from`).
  - Severity: Medium
  - Suggested test: external; `tests/unit/bytes/convert/external.rs`.
  - Covered by: `tests/unit/bytes/convert/external.rs::the_sdk_and_circom_sizes_are_pinned`.

- [x] **INV-BYTES-PACK-10: Packing proof interop**
  - Kind: interop
  - Statement: snarkjs Groth16 verifies the 31-byte packing export with exactly zero public inputs.
  - Location: `src/circuit/builtins/types/bytes.rs:74-93` (`try_from`).
  - Severity: Medium
  - Suggested test: external; `tests/unit/bytes/convert/external.rs`.
  - Covered by: `tests/unit/bytes/convert/external.rs::snarkjs_proves_and_verifies_a_31_byte_pack`.

- [x] **INV-BYTES-PACK-11: Random packing**
  - Kind: soundness
  - Statement: For every generated 31-byte array, incrementing the packed output is refused.
  - Location: `src/circuit/builtins/types/bytes.rs:74-93` (`try_from`).
  - Severity: Critical
  - Suggested test: property (proptest); `tests/unit/bytes/convert/properties.rs`.
  - Covered by: `tests/unit/bytes/convert/properties.rs::random_31_byte_pack_and_split_agree_and_reject_changed_claims`.

- [x] **INV-BYTES-PACK-12: No free conversion variables**
  - Kind: soundness
  - Statement: For every listed conversion edge vector, the free-variable report contains exactly no free or tolerated variables.
  - Location: `src/circuit/builtins/types/bytes.rs:47-93` (`try_from`).
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::no_private_variable_of_a_split_or_pack_is_free`.

- [ ] **INV-BYTES-PACK-13: Packing determinism**
  - Kind: soundness
  - Statement: Every packed output is fixed by its byte inputs.
  - Location: `src/circuit/builtins/types/bytes.rs:74-93` (`try_from`).
  - Severity: Critical
  - Suggested test: external; `tests/unit/bytes/convert/picus.rs`.
  - Partial coverage: SDK Picus returns Unknown at 15 seconds; circom returned Safe in the first run but can also return Unknown under concurrent tool load. SDK uniqueness is not proved. Test: `tests/unit/bytes/convert/picus.rs::picus_checks_packing_determinism_with_a_bounded_timeout`.

- [x] **INV-BYTES-PACK-14: Packing shape**
  - Kind: shape
  - Statement: For every width N from 0 through 31, the honest packing fixture has exactly identical setup and proving matrices.
  - Location: `src/circuit/builtins/types/bytes.rs:74-93` (`try_from`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/convert/r1cs.rs`.
  - Covered by: `tests/unit/bytes/convert/r1cs.rs::every_supported_byte_width_round_trips_with_the_same_setup_and_proving_shape`.

## Byte assertions (`is_equal`, `assert_equal`, `assert_equal_if`, `assert_not_equal`)

- [x] **INV-BYTES-ASSERT-01: assert_equal**
  - Kind: semantics
  - Statement: For every listed vector across widths 0,1,31,32,63, `assert_equal` accepts exactly when both arrays are equal.
  - Location: `src/circuit/builtins/types/bytes.rs:101-118` (`impl Assert`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/ops/native.rs`.
  - Covered by: `tests/unit/bytes/ops/native.rs::byte_assertions_and_selection_match_array_semantics_across_chunk_boundaries`.

- [x] **INV-BYTES-ASSERT-02: assert_equal_if**
  - Kind: semantics
  - Statement: For every listed vector across widths 0,1,31,32,63, `assert_equal_if` accepts exactly when the condition is false or both arrays are equal.
  - Location: `src/circuit/builtins/types/bytes.rs:101-118` (`impl Assert`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/ops/native.rs`.
  - Covered by: `tests/unit/bytes/ops/native.rs::byte_assertions_and_selection_match_array_semantics_across_chunk_boundaries`.

- [x] **INV-BYTES-ASSERT-03: assert_not_equal**
  - Kind: semantics
  - Statement: For every listed vector across widths 0,1,31,32,63, `assert_not_equal` accepts exactly when the arrays differ in at least one byte.
  - Location: `src/circuit/builtins/types/bytes.rs:101-118` (`impl Assert`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/ops/native.rs`.
  - Covered by: `tests/unit/bytes/ops/native.rs::byte_assertions_and_selection_match_array_semantics_across_chunk_boundaries`.

- [x] **INV-BYTES-ASSERT-04: is_equal**
  - Kind: semantics
  - Statement: For every listed vector across widths 0,1,31,32,63, `is_equal` accepts exactly when its Boolean output claim equals array equality.
  - Location: `src/circuit/builtins/types/bytes.rs:101-118` (`impl Assert`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/ops/native.rs`.
  - Covered by: `tests/unit/bytes/ops/native.rs::byte_assertions_and_selection_match_array_semantics_across_chunk_boundaries`.

- [x] **INV-BYTES-ASSERT-05: Empty inequality refused**
  - Kind: error
  - Statement: Every tested empty-array inequality returns exactly its named RuleBroken error.
  - Location: `src/circuit/builtins/types/bytes.rs:101-118` (`impl Assert`).
  - Error: `CircuitErrorKind::RuleBroken`.
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/ops/native.rs`.
  - Covered by: `tests/unit/bytes/ops/native.rs::empty_arrays_are_equal_and_cannot_satisfy_not_equal`.

- [x] **INV-BYTES-ASSERT-06: Assertion golden rows**
  - Kind: constraint
  - Statement: The one-byte equality fixture exports exactly eighteen range rows followed by one byte-equality row.
  - Location: `src/circuit/builtins/types/bytes.rs:106-108` (`assert_equal`).
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/ops/r1cs.rs`.
  - Covered by: `tests/unit/bytes/ops/r1cs.rs::one_byte_equality_has_range_checks_then_one_equality_row`.

- [x] **INV-BYTES-ASSERT-07: Assertion pins**
  - Kind: constraint
  - Statement: Every 32-byte assertion fixture exports exactly the pinned constraint/variable counts and SHA-256 R1CS digest.
  - Location: `src/circuit/builtins/types/bytes.rs:101-118` (`impl Assert`).
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/ops/r1cs.rs`.
  - Covered by: `tests/unit/bytes/ops/r1cs.rs::operation_counts_and_digests_are_pinned`.

- [x] **INV-BYTES-ASSERT-08: Assertion completeness and shape**
  - Kind: shape
  - Statement: Every honest assertion fixture across widths 0,1,31,32,63 has exactly identical setup and proving rows.
  - Location: `src/circuit/builtins/types/bytes.rs:101-118` (`impl Assert`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/ops/r1cs.rs`.
  - Covered by: `tests/unit/bytes/ops/r1cs.rs::honest_assertions_and_select_have_stable_shape_and_no_unexpected_free_variables`.

- [x] **INV-BYTES-ASSERT-09: Equality chunk soundness**
  - Kind: soundness
  - Statement: For every tested byte index 0,30,31, changing a right byte and its bits together leaves an enabled equality relation unsatisfied.
  - Location: `src/circuit/builtins/types/bytes.rs:106-117` (`assert_equal`, `assert_equal_if`).
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/bytes/ops/r1cs.rs`.
  - Covered by: `tests/unit/bytes/ops/r1cs.rs::changed_equality_operands_with_honest_range_bits_break_the_relation`.

- [x] **INV-BYTES-ASSERT-10: Inequality soundness**
  - Kind: soundness
  - Statement: Changing all right bytes and bits of the honest inequality witness to equal the left leaves some exported row unsatisfied.
  - Location: `src/circuit/builtins/types/bytes.rs:101-118` (`impl Assert`).
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/bytes/ops/r1cs.rs`.
  - Covered by: `tests/unit/bytes/ops/r1cs.rs::making_inequality_operands_equal_with_valid_byte_bits_is_unsatisfied`.

- [x] **INV-BYTES-ASSERT-11: Equality output soundness**
  - Kind: soundness
  - Statement: For each Boolean equality result, flipping its claimed value is refused by a proving row.
  - Location: `src/circuit/builtins/types/bytes.rs:102-104` (`is_equal`).
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/bytes/ops/r1cs.rs`.
  - Covered by: `tests/unit/bytes/ops/r1cs.rs::every_selected_byte_and_the_equality_claim_are_constrained`.

- [x] **INV-BYTES-ASSERT-12: Assertion reference relation**
  - Kind: equivalence
  - Statement: For every listed assertion case changing either packed chunk, the SDK and the circom references accept exactly the same relation.
  - Location: `src/circuit/builtins/types/bytes.rs:101-118` (`impl Assert`).
  - Severity: High
  - Suggested test: external; `tests/unit/bytes/ops/external.rs`.
  - Covered by: `tests/unit/bytes/ops/external.rs::equality_and_inequality_match_circomlib_across_the_chunk_boundary`.

- [x] **INV-BYTES-ASSERT-13: Random assertions**
  - Kind: soundness
  - Statement: Every generated assertion case is accepted exactly when its array relation holds.
  - Location: `src/circuit/builtins/types/bytes.rs:101-118` (`impl Assert`).
  - Severity: Critical
  - Suggested test: property (proptest); `tests/unit/bytes/ops/properties.rs`.
  - Covered by: `tests/unit/bytes/ops/properties.rs::random_byte_arrays_obey_assert_and_select_relations`.

- [x] **INV-BYTES-ASSERT-14: Constant assertion frame**
  - Kind: constraint
  - Statement: The all-constant assertion fixture exports exactly zero rows and one constant wire.
  - Location: `src/circuit/builtins/types/bytes.rs:101-118` (`impl Assert`).
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/ops/r1cs.rs`.
  - Covered by: `tests/unit/bytes/ops/r1cs.rs::constant_assertions_and_selection_add_no_constraint_or_variable`.

- [ ] **INV-BYTES-ASSERT-15: Equality determinism**
  - Kind: soundness
  - Statement: Every equality result is fixed by its two byte arrays.
  - Location: `src/circuit/builtins/types/bytes.rs:102-104` (`is_equal`).
  - Severity: Critical
  - Suggested test: external; `tests/unit/bytes/ops/picus.rs`.
  - Partial coverage: Both SDK and circom equality Picus return Unknown at 10 seconds; result uniqueness remains unproved. Test: `tests/unit/bytes/ops/picus.rs::picus_checks_equality_and_selection_with_bounded_timeouts`.

- [x] **INV-BYTES-ASSERT-16: Assertion completeness**
  - Kind: completeness
  - Statement: Every honest assertion fixture at the tested widths satisfies every exported row.
  - Location: `src/circuit/builtins/types/bytes.rs:101-118` (`impl Assert`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/ops/r1cs.rs`.
  - Covered by: `tests/unit/bytes/ops/r1cs.rs::honest_assertions_and_select_have_stable_shape_and_no_unexpected_free_variables`.

- [x] **INV-BYTES-ASSERT-17: Only inverse hints tolerated**
  - Kind: soundness
  - Statement: Every honest assertion fixture has no free private variable; every tolerated variable is labelled exactly as an equality inverse hint.
  - Location: `src/circuit/builtins/types/bytes.rs:101-118` (`impl Assert`).
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/bytes/ops/r1cs.rs`.
  - Covered by: `tests/unit/bytes/ops/r1cs.rs::honest_assertions_and_select_have_stable_shape_and_no_unexpected_free_variables`.

- [x] **INV-BYTES-ASSERT-18: Named assertion refusals**
  - Kind: error
  - Statement: Every listed invalid byte assertion returns exactly its method-specific named RuleBroken error.
  - Location: `src/circuit/builtins/types/bytes.rs:101-118` (`impl Assert`).
  - Error: `CircuitErrorKind::RuleBroken`.
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/ops/native.rs`.
  - Covered by: `tests/unit/bytes/ops/native.rs::byte_assertions_and_selection_match_array_semantics_across_chunk_boundaries`.

- [x] **INV-BYTES-ASSERT-19: Assertion witness interop**
  - Kind: interop
  - Statement: For every byte assertion method, snarkjs accepts its honest witness and refuses its specified altered relation.
  - Location: `src/circuit/builtins/types/bytes.rs:101-118` (`impl Assert`).
  - Severity: Medium
  - Suggested test: external; `tests/unit/bytes/ops/external.rs`.
  - Covered by: `tests/unit/bytes/ops/external.rs::snarkjs_accepts_assertion_witnesses_and_refuses_broken_relations`.

## Byte selection (`Select::select`, `Bool::select`)

- [x] **INV-BYTES-SELECT-01: Selected branch semantics**
  - Kind: semantics
  - Statement: For every listed byte-array vector and Boolean condition, selection returns exactly the named branch.
  - Location: `src/circuit/builtins/types/bytes.rs:120-126` (`select`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/ops/native.rs`.
  - Covered by: `tests/unit/bytes/ops/native.rs::byte_assertions_and_selection_match_array_semantics_across_chunk_boundaries`.

- [x] **INV-BYTES-SELECT-02: Selection frame**
  - Kind: constraint
  - Statement: Constant selection adds exactly no constraints or private variables.
  - Location: `src/circuit/builtins/types/bytes.rs:121-125` (`select`).
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/ops/r1cs.rs`.
  - Covered by: `tests/unit/bytes/ops/r1cs.rs::constant_assertions_and_selection_add_no_constraint_or_variable`.

- [x] **INV-BYTES-SELECT-03: Selection pins**
  - Kind: constraint
  - Statement: The 32-byte select fixture exports exactly 641 constraints, 642 variables and its pinned SHA-256 digest.
  - Location: `src/circuit/builtins/types/bytes.rs:121-125` (`select`).
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/ops/r1cs.rs`.
  - Covered by: `tests/unit/bytes/ops/r1cs.rs::operation_counts_and_digests_are_pinned`.

- [x] **INV-BYTES-SELECT-04: Selection shape**
  - Kind: shape
  - Statement: For every honest select fixture at widths 0,1,31,32,63, setup and proving matrices are exactly identical.
  - Location: `src/circuit/builtins/types/bytes.rs:121-125` (`select`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/ops/r1cs.rs`.
  - Covered by: `tests/unit/bytes/ops/r1cs.rs::honest_assertions_and_select_have_stable_shape_and_no_unexpected_free_variables`.

- [x] **INV-BYTES-SELECT-05: Selection soundness**
  - Kind: soundness
  - Statement: For every selected byte position of a 32-byte fixture in either branch, changing that output is refused by the exported and proving rows.
  - Location: `src/circuit/builtins/types/bytes.rs:121-125` (`select`).
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/bytes/ops/r1cs.rs`.
  - Covered by: `tests/unit/bytes/ops/r1cs.rs::every_selected_byte_and_the_equality_claim_are_constrained`.

- [x] **INV-BYTES-SELECT-06: Selection reference**
  - Kind: equivalence
  - Statement: For every branch and every selected byte position, the SDK and circomlib Mux1 reference accept exactly the same honest or altered-output relation.
  - Location: `src/circuit/builtins/types/bytes.rs:121-125` (`select`).
  - Severity: High
  - Suggested test: external; `tests/unit/bytes/ops/external.rs`.
  - Covered by: `tests/unit/bytes/ops/external.rs::selection_matches_circomlib_mux1_and_refuses_every_changed_byte`.

- [x] **INV-BYTES-SELECT-07: Selection interop**
  - Kind: interop
  - Statement: snarkjs verifies a 32-byte select Groth16 proof with exactly zero public inputs.
  - Location: `src/circuit/builtins/types/bytes.rs:121-125` (`select`).
  - Severity: Medium
  - Suggested test: external; `tests/unit/bytes/ops/external.rs`.
  - Covered by: `tests/unit/bytes/ops/external.rs::snarkjs_checks_and_proves_byte_selection`.

- [x] **INV-BYTES-SELECT-08: Random selection**
  - Kind: soundness
  - Statement: For every random 32-byte select fixture, changing a chosen output byte is refused.
  - Location: `src/circuit/builtins/types/bytes.rs:121-125` (`select`).
  - Severity: Critical
  - Suggested test: property (proptest); `tests/unit/bytes/ops/properties.rs`.
  - Covered by: `tests/unit/bytes/ops/properties.rs::random_byte_arrays_obey_assert_and_select_relations`.

- [ ] **INV-BYTES-SELECT-09: Selection determinism**
  - Kind: soundness
  - Statement: Every selected byte is fixed by the condition and branch byte arrays.
  - Location: `src/circuit/builtins/types/bytes.rs:121-125` (`select`).
  - Severity: Critical
  - Suggested test: external; `tests/unit/bytes/ops/picus.rs`.
  - Partial coverage: SDK selection Picus returns Unknown at 10 seconds; circom returns Safe. SDK selected-byte uniqueness remains unproved. Test: `tests/unit/bytes/ops/picus.rs::picus_checks_equality_and_selection_with_bounded_timeouts`.

- [x] **INV-BYTES-SELECT-10: Selection completeness**
  - Kind: completeness
  - Statement: Every honest selected-byte fixture at the tested widths satisfies every exported row.
  - Location: `src/circuit/builtins/types/bytes.rs:121-125` (`select`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/ops/r1cs.rs`.
  - Covered by: `tests/unit/bytes/ops/r1cs.rs::honest_assertions_and_select_have_stable_shape_and_no_unexpected_free_variables`.

- [x] **INV-BYTES-SELECT-11: Named selection refusal**
  - Kind: error
  - Statement: Every listed wrong selected byte returns exactly the named selection RuleBroken error natively.
  - Location: `src/circuit/builtins/types/bytes.rs:121-125` (`select`).
  - Error: `CircuitErrorKind::RuleBroken`.
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/ops/native.rs`.
  - Covered by: `tests/unit/bytes/ops/native.rs::byte_assertions_and_selection_match_array_semantics_across_chunk_boundaries`.

## Byte hashing (`Bytes<N>::hash_bytes`)

- [x] **INV-HASH-BYTES-01: Native chunk-boundary hashes**
  - Kind: native equivalence
  - Statement: Every hardcoded hash vector at widths 0,1,31,32,62,63 returns exactly the native zolana_hasher::primitives::hash_bytes result through Bytes<N>::hash_bytes, both for constants and for checked proof inputs.
  - Location: `src/circuit/builtins/gadgets/hash_bytes.rs:12-25` (`hash_bytes`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/hash/native.rs`.
  - Covered by: `tests/unit/bytes/hash/native.rs::hardcoded_chunk_boundaries_match_native_hash_bytes_and_refuse_wrong_hashes`.

- [x] **INV-HASH-BYTES-02: Fixed-width semantics**
  - Kind: semantics
  - Statement: Every tested leading-zero alias across lengths returns exactly the same one-chunk packed value.
  - Location: `src/circuit/builtins/gadgets/hash_bytes.rs:27-36` (`packed`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/hash/native.rs`.
  - Covered by: `tests/unit/bytes/hash/native.rs::zero_chunks_and_leading_zeros_follow_fixed_width_packing`.

- [x] **INV-HASH-BYTES-03: Checked big-endian packing**
  - Kind: semantics
  - Statement: For the two-byte inputs [1,2] and [1,0], Bytes<2>::hash_bytes returns exactly its big-endian value, 258 and 256 respectively.
  - Location: `src/circuit/builtins/gadgets/hash_bytes.rs:27-36` (`packed`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/hash/native.rs`.
  - Covered by: `tests/unit/bytes/hash/native.rs::checked_single_chunk_bytes_hash_to_their_big_endian_value`.

- [x] **INV-HASH-BYTES-04: Coordinated byte aliases are refused**
  - Kind: soundness
  - Statement: For every forged pair [0,258] or [0,256] retaining the corresponding honest hash claim and low eight bits of the second byte, recomputing the first-byte bits to zero leaves exactly the second-byte recomposition row unsatisfied despite satisfying the hash equation.
  - Location: `src/conversion/bytes.rs:13-30` (`instantiate`); `src/circuit/builtins/types/bytes.rs:42-44` (`hash_bytes`).
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/bytes/hash/r1cs.rs`.
  - Covered by: `tests/unit/bytes/hash/r1cs.rs::byte_range_checks_reject_coordinated_aliases_that_preserve_the_hash`.

- [x] **INV-HASH-BYTES-05: Small hash golden rows**
  - Kind: constraint
  - Statement: For every tested width N in {0,1,2}, the checked hash fixture exports exactly nine range-check rows per byte followed by one hand-derived big-endian hash-claim row.
  - Location: `src/circuit/builtins/gadgets/hash_bytes.rs:12-36` (`hash_bytes`, `packed`).
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/hash/r1cs.rs`.
  - Covered by: `tests/unit/bytes/hash/r1cs.rs::empty_and_single_chunk_hashes_have_exact_byte_and_packing_rows`.

- [x] **INV-HASH-BYTES-06: Hash pins**
  - Kind: constraint
  - Statement: The checked 31-byte, 32-byte and 63-byte hash exports equal exactly their pinned sizes and SHA-256 digests.
  - Location: `src/circuit/builtins/gadgets/hash_bytes.rs:12-36` (`hash_bytes`, `packed`).
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/hash/r1cs.rs`.
  - Covered by: `tests/unit/bytes/hash/r1cs.rs::hash_counts_and_large_exports_are_pinned`.

- [x] **INV-HASH-BYTES-07: Hash shape**
  - Kind: shape
  - Statement: At every tested chunk boundary, every honest hash fixture has exactly identical setup and proving matrices.
  - Location: `src/circuit/builtins/gadgets/hash_bytes.rs:12-25` (`hash_bytes`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/hash/r1cs.rs`.
  - Covered by: `tests/unit/bytes/hash/r1cs.rs::every_chunk_boundary_has_identical_setup_and_proving_rows_and_rejects_tampering`.

- [x] **INV-HASH-BYTES-08: Hash completeness**
  - Kind: completeness
  - Statement: At every tested chunk boundary, the native reference output satisfies every SDK exported hash row.
  - Location: `src/circuit/builtins/gadgets/hash_bytes.rs:12-25` (`hash_bytes`).
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/bytes/hash/r1cs.rs`.
  - Covered by: `tests/unit/bytes/hash/r1cs.rs::every_chunk_boundary_has_identical_setup_and_proving_rows_and_rejects_tampering`.

- [x] **INV-HASH-BYTES-09: Hash output soundness**
  - Kind: soundness
  - Statement: For every tested chunk boundary, incrementing the hash output is refused with exactly the named hash rule.
  - Location: `src/circuit/builtins/gadgets/hash_bytes.rs:12-25` (`hash_bytes`).
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/bytes/hash/r1cs.rs`.
  - Covered by: `tests/unit/bytes/hash/r1cs.rs::every_chunk_boundary_has_identical_setup_and_proving_rows_and_rejects_tampering`.

- [x] **INV-HASH-BYTES-10: Hash preimage soundness**
  - Kind: soundness
  - Statement: For every byte position of every tested chunk-boundary fixture of the checked Bytes<N> hash, changing that preimage wire leaves a proving row unsatisfied.
  - Location: `src/circuit/builtins/gadgets/hash_bytes.rs:12-25` (`hash_bytes`).
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/bytes/hash/r1cs.rs`.
  - Covered by: `tests/unit/bytes/hash/r1cs.rs::every_chunk_boundary_has_identical_setup_and_proving_rows_and_rejects_tampering`.

- [x] **INV-HASH-BYTES-11: Hash native refusal**
  - Kind: error
  - Statement: Every hardcoded hash edge vector with its claimed output incremented returns exactly the named RuleBroken error.
  - Location: `src/circuit/builtins/gadgets/hash_bytes.rs:12-25` (`hash_bytes`).
  - Error: `CircuitErrorKind::RuleBroken`.
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/bytes/hash/native.rs`.
  - Covered by: `tests/unit/bytes/hash/native.rs::hardcoded_chunk_boundaries_match_native_hash_bytes_and_refuse_wrong_hashes`.

- [x] **INV-HASH-BYTES-12: Hash circomlib reference**
  - Kind: equivalence
  - Statement: For every tested two-chunk and three-chunk hash claim, the SDK and the Num2Bits plus Poseidon(2) circom reference accept exactly the same relation.
  - Location: `src/circuit/builtins/gadgets/hash_bytes.rs:12-25` (`hash_bytes`).
  - Severity: High
  - Suggested test: external; `tests/unit/bytes/hash/external.rs`.
  - Covered by: `tests/unit/bytes/hash/external.rs::hash_bytes_matches_circomlib_poseidon_at_two_and_three_chunks`.

- [x] **INV-HASH-BYTES-13: Hash proof interop**
  - Kind: interop
  - Statement: snarkjs verifies the two-chunk hash Groth16 proof with exactly zero public inputs.
  - Location: `src/circuit/builtins/gadgets/hash_bytes.rs:12-25` (`hash_bytes`).
  - Severity: Medium
  - Suggested test: external; `tests/unit/bytes/hash/external.rs`.
  - Covered by: `tests/unit/bytes/hash/external.rs::snarkjs_checks_tampering_and_proves_a_two_chunk_hash`.

- [x] **INV-HASH-BYTES-14: Random hash**
  - Kind: native equivalence
  - Statement: For every generated 63-byte input, the SDK hash constraints accept exactly the native reference output and refuse its increment.
  - Location: `src/circuit/builtins/gadgets/hash_bytes.rs:12-25` (`hash_bytes`).
  - Severity: High
  - Suggested test: property (proptest); `tests/unit/bytes/hash/properties.rs`.
  - Covered by: `tests/unit/bytes/hash/properties.rs::random_multichunk_hashes_match_native_and_reject_changed_outputs`.

- [ ] **INV-HASH-BYTES-15: Checked single-chunk determinism**
  - Kind: soundness
  - Statement: Every checked 31-byte hash output and its bit witnesses are fixed by the input byte values.
  - Location: `src/circuit/builtins/gadgets/hash_bytes.rs:27-36` (`packed`).
  - Severity: Critical
  - Suggested test: external; `tests/unit/bytes/hash/picus.rs`.
  - Partial coverage: The checked-byte replacement is compile-checked with a 15-second Picus limit; its test permits Unknown without claiming determinism and rejects Unsafe. No Safe verdict for this replacement has been established in the API migration. Test: `tests/unit/bytes/hash/picus.rs::picus_checks_a_checked_single_chunk_hash_with_a_bounded_timeout`.

- [ ] **INV-HASH-BYTES-16: Multi-chunk determinism**
  - Kind: soundness
  - Statement: The checked two-chunk hash is fixed by its byte inputs.
  - Location: `src/circuit/builtins/gadgets/hash_bytes.rs:12-25` (`hash_bytes`).
  - Severity: Critical
  - Suggested test: external; `tests/unit/bytes/hash/picus.rs`.
  - Partial coverage: SDK Picus returns Unknown at 15 seconds; circom Picus returns Safe. Full SDK witness uniqueness remains unproved. Test: `tests/unit/bytes/hash/picus.rs::picus_checks_two_chunk_hashes_with_a_bounded_timeout`.

## Local checklist totals

91 invariants; 84 covered; 7 partial Picus invariants.
