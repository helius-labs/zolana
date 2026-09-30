# Gadget Invariants

ID prefixes: `INV-POSEIDON`, `INV-HASH-CHAIN`, `INV-MEMBER`, `INV-INDEX`.

The `hash_bytes` invariants and tests are owned by [`bytes.md`](bytes.md), under `INV-HASH-BYTES`; they are not duplicated here. Shared exporter invariants remain in `cross-cutting.md`.

The exact matrix fixtures use private inputs only. Membership and selection intentionally permit some unused input values to vary. This is distinct from a dishonest claimed output, which must fail. Equality inverse hints at zero are explicitly tolerated multipliers; they are not claimed to have unique values.

## Poseidon (`poseidon`)

- [x] **INV-POSEIDON-01: Native hash vectors**
  - Kind: semantics
  - Statement: For every supported arity 1 through 12, every pinned vector hashes to exactly the pinned BN254 Poseidon value.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/poseidon/native.rs`
  - Covered by: `tests/unit/gadgets/poseidon/native.rs::the_native_hash_is_the_pinned_hash_and_zolana_hashers_at_every_arity`.

- [x] **INV-POSEIDON-02: Native Poseidon agreement**
  - Kind: native equivalence
  - Statement: For every generated input vector of length 1 through 12, the circuit value is exactly `zolana_hasher::Poseidon::hashv` for canonical big-endian field bytes.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: High
  - Suggested test: property (proptest); `tests/unit/gadgets/poseidon/properties.rs`
  - Covered by: `tests/unit/gadgets/poseidon/properties.rs::the_native_hash_is_zolana_hashers_at_every_arity`.

- [x] **INV-POSEIDON-03: Constants stay constant**
  - Kind: semantics
  - Statement: For every pinned input vector, hashing constant inputs returns exactly a constant circuit value.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/poseidon/native.rs`
  - Covered by: `tests/unit/gadgets/poseidon/native.rs::a_hash_of_constants_is_a_constant`.

- [x] **INV-POSEIDON-04: Unsupported arities**
  - Kind: error
  - Statement: For every tested unsupported input count, hashing returns exactly `UnsupportedHashInputCount`.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/poseidon/native.rs`
  - Error: `CircuitErrorKind::UnsupportedHashInputCount`
  - Covered by: `tests/unit/gadgets/poseidon/native.rs::every_arity_outside_one_to_twelve_is_refused_like_zolana_hashers`.

- [x] **INV-POSEIDON-05: S-box row formula**
  - Kind: constraint
  - Statement: For every arity n in 1..=12, the claim fixture has exactly 3*(8*(n+1)+partial_rounds[n-1]-1)+1 rows, with exactly one variable for each nonconstant S-box multiplication, n inputs, one claim and constant one.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/poseidon/r1cs.rs`
  - Covered by: `tests/unit/gadgets/poseidon/r1cs.rs::every_arity_exports_three_rows_per_variable_sbox_plus_the_claim_row`.

- [x] **INV-POSEIDON-06: Every arity digest**
  - Kind: constraint
  - Statement: For every arity 1 through 12, the R1CS byte digest is exactly the separately pinned SHA-256 value.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/poseidon/r1cs.rs`
  - Covered by: `tests/unit/gadgets/poseidon/r1cs.rs::every_arity_exports_the_pinned_r1cs_digest`.

- [x] **INV-POSEIDON-07: Constant hash frame**
  - Kind: constraint
  - Statement: For the constant preimage [1,2], hashing adds exactly zero rows and zero witnesses before its one output-claim row; no public input is allocated.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/poseidon/r1cs.rs`
  - Covered by: `tests/unit/gadgets/poseidon/r1cs.rs::a_hash_of_constants_adds_no_row_and_no_variable`.

- [x] **INV-POSEIDON-08: Honest hash satisfies every row**
  - Kind: completeness
  - Statement: For every pinned supported vector, no exported row is unsatisfied.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/poseidon/r1cs.rs`
  - Covered by: `tests/unit/gadgets/poseidon/r1cs.rs::every_valid_vector_satisfies_every_row_and_a_hash_plus_one_breaks_the_claim_row`.

- [x] **INV-POSEIDON-09: Wrong hash is refused**
  - Kind: soundness
  - Statement: For every pinned vector, changing its output to output+1 makes exactly the last claim row the first unsatisfied row.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/gadgets/poseidon/r1cs.rs`
  - Covered by: `tests/unit/gadgets/poseidon/r1cs.rs::every_valid_vector_satisfies_every_row_and_a_hash_plus_one_breaks_the_claim_row`.

- [x] **INV-POSEIDON-10: Hash and S-box tampering**
  - Kind: soundness
  - Statement: For every pinned vector, changing the hash or the first S-box witness is refused by the proving rows with exactly the expected row label.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/gadgets/poseidon/r1cs.rs`
  - Covered by: `tests/unit/gadgets/poseidon/r1cs.rs::the_proving_rows_accept_the_honest_hash_and_refuse_a_tampered_hash_or_sbox`.

- [x] **INV-POSEIDON-11: No free private variables**
  - Kind: soundness
  - Statement: For every supported arity, the counting-input fixture reports exactly zero free or tolerated private variables.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/gadgets/poseidon/r1cs.rs`
  - Covered by: `tests/unit/gadgets/poseidon/r1cs.rs::no_private_variable_is_free_at_any_arity`.

- [x] **INV-POSEIDON-12: Setup and proving matrices**
  - Kind: shape
  - Statement: For every pinned vector, `check_constraints` returns exactly the pinned row count after comparing all placeholder and proving rows.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/poseidon/r1cs.rs`
  - Covered by: `tests/unit/gadgets/poseidon/r1cs.rs::every_valid_vector_checks_exactly_the_placeholders_rows`.

- [x] **INV-POSEIDON-13: Unsupported setup fails**
  - Kind: error
  - Statement: For each arity 0 and 13, neither R1CS export nor shape checking succeeds; each error is exactly `UnsupportedHashInputCount`.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/poseidon/r1cs.rs`
  - Error: `CircuitErrorKind::UnsupportedHashInputCount`
  - Covered by: `tests/unit/gadgets/poseidon/r1cs.rs::a_fixture_of_an_unsupported_arity_neither_exports_nor_checks`.

- [x] **INV-POSEIDON-14: circomlib relation at all arities**
  - Kind: equivalence
  - Statement: For every honest or dishonest case at every supported arity, native SDK evaluation, SDK rows, circom witness calculation and circom rows accept exactly the same relation.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: High
  - Suggested test: external; `tests/unit/gadgets/poseidon/external.rs`
  - Covered by: `tests/unit/gadgets/poseidon/external.rs::circomlib_poseidon_accepts_exactly_the_sdks_claims_at_every_arity`.

- [x] **INV-POSEIDON-15: circomlib cost pins**
  - Kind: equivalence
  - Statement: For every supported arity, both constraint counts are exactly pinned, and circomlib has exactly three more quadratic S-box rows than the SDK.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: High
  - Suggested test: external; `tests/unit/gadgets/poseidon/external.rs`
  - Covered by: `tests/unit/gadgets/poseidon/external.rs::the_sizes_are_pinned_and_circomlib_has_exactly_three_more_sbox_rows_at_every_arity`.

- [x] **INV-POSEIDON-16: snarkjs witness checking**
  - Kind: interop
  - Statement: For every supported arity, snarkjs accepts the honest SDK witness and refuses the witness with the hash increased by one.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/gadgets/poseidon/external.rs`
  - Covered by: `tests/unit/gadgets/poseidon/external.rs::snarkjs_accepts_the_sdk_pair_and_rejects_a_tampered_hash_at_every_arity`.

- [x] **INV-POSEIDON-17: Groth16 proof verification**
  - Kind: interop
  - Statement: For the two-input counting fixture, snarkjs setup, prove and verify return exactly success with no public inputs.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/gadgets/poseidon/external.rs`
  - Covered by: `tests/unit/gadgets/poseidon/external.rs::snarkjs_proves_and_verifies_the_two_input_hash`.

- [x] **INV-POSEIDON-18: Generated dishonest hashes**
  - Kind: soundness
  - Statement: For every generated supported vector and nonzero offset, a hash changed by that offset is refused natively and at exactly the last proving row.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: Critical
  - Suggested test: property (proptest); `tests/unit/gadgets/poseidon/properties.rs`
  - Covered by: `tests/unit/gadgets/poseidon/properties.rs::the_honest_hash_checks_and_a_wrong_hash_is_refused_natively_and_in_r1cs`.

- [ ] **INV-POSEIDON-19: Picus hash determinism**
  - Kind: equivalence
  - Statement: For every supported arity, Picus proves all claimed hash outputs fixed by their inputs in both SDK and circomlib.
  - Location: `src/circuit/builtins/gadgets/poseidon.rs:10-66` (`poseidon`, `parameters`)
  - Severity: High
  - Suggested test: external; `tests/unit/gadgets/poseidon/picus.rs`
  - Partial coverage: `tests/unit/gadgets/poseidon/picus.rs::picus_checks_hash_determinism_at_every_arity_with_a_bounded_timeout`; the first run returned Safe for every arity on both exports, but SDK arity ten returned Unknown at the 30-second limit under concurrent suite load. Every verdict is recorded; Unsafe fails the test, while Unknown is not counted as proof of determinism.

## Hash chain (`nonzero_hash_chain`)

- [x] **INV-HASH-CHAIN-01: Nonzero fold**
  - Kind: semantics
  - Statement: For every pinned vector, the native result is exactly the protocol's nonzero hash chain: zero elements are skipped, the first nonzero element is the chain as it is, every later nonzero element folds in as Poseidon(chain,value), and a vector without a nonzero element chains to zero; an independent reference of that definition over `zolana_hasher`'s Poseidon returns the same chain, every Poseidon value a vector names is exactly that hash, and every vector of `test-vectors/nonzero_hash_chain.json` chains natively to exactly its output.
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/hash_chain/native.rs`
  - Covered by: `tests/unit/gadgets/hash_chain/native.rs::the_native_chain_is_the_pinned_chain_and_the_reference_chain`; `tests/unit/gadgets/hash_chain/native.rs::the_pinned_hashes_are_the_poseidon_hashes_they_name`; `tests/unit/gadgets/hash_chain/native.rs::the_native_chain_and_the_reference_chain_reproduce_every_shared_vector`.

- [x] **INV-HASH-CHAIN-02: Constant chain**
  - Kind: semantics
  - Statement: For every pinned vector, a chain over constant values is exactly a constant circuit value.
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/hash_chain/native.rs`
  - Covered by: `tests/unit/gadgets/hash_chain/native.rs::a_chain_of_constants_is_a_constant`.

- [x] **INV-HASH-CHAIN-03: Length cost and digests**
  - Kind: constraint
  - Statement: For every length n in 1..=4 the fixture has exactly 246*n-242 rows and 247*n-241 variables, while length zero has one row and two variables: the first value meets the constant zero chain and costs its zero test and one select (3 rows), every later value costs its zero test, the chain's zero test, one Poseidon(chain,value) of 240 rows and two selects (246 rows), the claim adds one row, and every row but the claim allocates one variable next to the constant one, the values and the claimed chain; every export has exactly its pinned SHA-256 digest.
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/hash_chain/r1cs.rs`
  - Covered by: `tests/unit/gadgets/hash_chain/r1cs.rs::every_length_exports_the_derived_size_and_the_pinned_digest`.

- [x] **INV-HASH-CHAIN-04: Empty chain golden row**
  - Kind: constraint
  - Statement: For the empty vector, the exported relation has exactly one linear row enforcing chain=0 with no public inputs or gadget witnesses.
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/hash_chain/r1cs.rs`
  - Covered by: `tests/unit/gadgets/hash_chain/r1cs.rs::the_empty_chain_exports_exactly_the_claim_that_the_chain_is_zero`.

- [x] **INV-HASH-CHAIN-05: Constants frame**
  - Kind: constraint
  - Statement: For the constant vector [0,1,2], computing the chain adds exactly zero rows and zero witnesses before the output-claim row, which compares the claim with the constant Poseidon(1,2).
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/hash_chain/r1cs.rs`
  - Covered by: `tests/unit/gadgets/hash_chain/r1cs.rs::a_chain_of_constants_adds_no_row_and_no_variable`.

- [x] **INV-HASH-CHAIN-06: Honest chains satisfy rows**
  - Kind: completeness
  - Statement: For every pinned vector, the exported honest witness satisfies every row.
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/hash_chain/r1cs.rs`
  - Covered by: `tests/unit/gadgets/hash_chain/r1cs.rs::every_valid_vector_satisfies_every_row_and_a_chain_plus_one_breaks_the_claim_row`.

- [x] **INV-HASH-CHAIN-07: Dishonest chain claim**
  - Kind: soundness
  - Statement: For every pinned invalid claim, including the chains of the left fold from zero ([1] claimed Poseidon(0,1) and [1,2] claimed Poseidon(Poseidon(0,1),2)), exactly the output-claim row is the first unsatisfied exported row.
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/gadgets/hash_chain/r1cs.rs`
  - Covered by: `tests/unit/gadgets/hash_chain/r1cs.rs::every_invalid_claim_breaks_the_claim_row`.

- [x] **INV-HASH-CHAIN-08: Zero-test tampering**
  - Kind: soundness
  - Statement: For every nonempty valid vector, the honest chain is accepted, the chain plus one is refused by exactly the output-claim row, and flipping the bit of any value's zero test, or of the chain's zero test at any value after the first, is refused by exactly the first row of that zero test.
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/gadgets/hash_chain/r1cs.rs`
  - Covered by: `tests/unit/gadgets/hash_chain/r1cs.rs::the_proving_rows_refuse_a_tampered_chain_and_every_flipped_zero_test`.

- [x] **INV-HASH-CHAIN-09: Only inverse hints are free**
  - Kind: soundness
  - Statement: For every pinned chain, no constrained private variable is free; exactly the inverse hint of each zero value's zero test, and of each chain zero test that meets a zero chain (a value after the first whose earlier values chain to zero), is tolerated.
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/gadgets/hash_chain/r1cs.rs`
  - Covered by: `tests/unit/gadgets/hash_chain/r1cs.rs::no_private_variable_is_free_and_only_the_hints_of_zero_values_and_zero_chains_are_tolerated`.

- [x] **INV-HASH-CHAIN-10: Constant placeholder shape**
  - Kind: shape
  - Statement: For every pinned vector of each length 0..=4, proving rows are exactly the placeholder rows.
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/hash_chain/r1cs.rs`
  - Covered by: `tests/unit/gadgets/hash_chain/r1cs.rs::every_valid_vector_checks_exactly_the_placeholders_rows`.

- [x] **INV-HASH-CHAIN-11: Wrong native chain rule**
  - Kind: error
  - Statement: For every wrong pinned chain and every honest chain changed by one, native evaluation returns exactly the fixture RuleBroken diagnostic.
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/hash_chain/native.rs`
  - Error: `CircuitErrorKind::RuleBroken`
  - Covered by: `tests/unit/gadgets/hash_chain/native.rs::every_wrong_chain_breaks_exactly_the_fixture_rule_natively`.

- [x] **INV-HASH-CHAIN-12: circom hash-chain relation**
  - Kind: equivalence
  - Statement: For every tested honest or dishonest vector padded to length three, SDK and a circom reference over circomlib Poseidon, which keeps the chain for a zero value and otherwise takes the value when the chain is zero and Poseidon(chain,value) when it is not, accept exactly the same relation.
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: High
  - Suggested test: external; `tests/unit/gadgets/hash_chain/external.rs`
  - Covered by: `tests/unit/gadgets/hash_chain/external.rs::the_circom_chain_over_circomlib_accepts_exactly_the_sdks_claims`.

- [x] **INV-HASH-CHAIN-13: Chain cost pins**
  - Kind: equivalence
  - Statement: For the three-value fixture, SDK constraints/variables are exactly 496/500 and circom constraints/variables are exactly 2330/2334.
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: High
  - Suggested test: external; `tests/unit/gadgets/hash_chain/external.rs`
  - Covered by: `tests/unit/gadgets/hash_chain/external.rs::the_sizes_are_pinned_against_the_circom_chain`.

- [x] **INV-HASH-CHAIN-14: Chain witness checking**
  - Kind: interop
  - Statement: For the three-value counting fixture, snarkjs accepts exactly the honest witness and refuses the changed chain.
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/gadgets/hash_chain/external.rs`
  - Covered by: `tests/unit/gadgets/hash_chain/external.rs::snarkjs_accepts_the_sdk_pair_and_rejects_a_tampered_chain`.

- [x] **INV-HASH-CHAIN-15: Chain Groth16 verification**
  - Kind: interop
  - Statement: For the [5,0,7] fixture, snarkjs verifies the SDK proof with exactly no public inputs.
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/gadgets/hash_chain/external.rs`
  - Covered by: `tests/unit/gadgets/hash_chain/external.rs::snarkjs_proves_and_verifies_a_chain_that_skips_a_zero`.

- [x] **INV-HASH-CHAIN-16: Random chains and wrong claims**
  - Kind: soundness
  - Statement: For every generated vector and nonzero wrong-output offset, the honest chain checks while the wrong native and proving claims are refused.
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: Critical
  - Suggested test: property (proptest); `tests/unit/gadgets/hash_chain/properties.rs`
  - Covered by: `tests/unit/gadgets/hash_chain/properties.rs::the_honest_chain_checks_and_a_wrong_chain_is_refused_natively_and_in_r1cs`.

- [ ] **INV-HASH-CHAIN-17: Picus chain determinism**
  - Kind: equivalence
  - Statement: For each chain length one and three, Picus proves the output fixed by its values in SDK and circom.
  - Location: `src/circuit/builtins/gadgets/hash_chain.rs:9-27` (`nonzero_hash_chain`)
  - Severity: High
  - Suggested test: external; `tests/unit/gadgets/hash_chain/picus.rs`
  - Partial coverage: `tests/unit/gadgets/hash_chain/picus.rs::picus_checks_chain_determinism_with_a_bounded_timeout`; Each process has a 30-second limit. Unknown is recorded without claiming determinism; Unsafe fails the test.

## Membership query (`is_in`)

- [x] **INV-MEMBER-01: Set membership flag**
  - Kind: semantics
  - Statement: For every pinned vector including duplicates and field endpoints, `is_in` is exactly the flag from native set membership.
  - Location: `src/circuit/builtins/gadgets/membership.rs:7-23` (`is_in`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/native.rs`
  - Covered by: `tests/unit/gadgets/membership/native.rs::every_value_is_in_exactly_the_sets_that_hold_it_natively`.

- [x] **INV-MEMBER-02: Empty set**
  - Kind: semantics
  - Statement: For every tested value, membership in the empty set is exactly false.
  - Location: `src/circuit/builtins/gadgets/membership.rs:7-23` (`is_in`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/native.rs`
  - Covered by: `tests/unit/gadgets/membership/native.rs::nothing_is_in_the_empty_set`.

- [x] **INV-MEMBER-03: Membership golden rows**
  - Kind: constraint
  - Statement: For the three-member fixture, the export is exactly the two product rows, two zero-test rows and one claim row, over ten variables and no public inputs.
  - Location: `src/circuit/builtins/gadgets/membership.rs:7-23` (`is_in`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/r1cs.rs`
  - Covered by: `tests/unit/gadgets/membership/r1cs.rs::membership_exports_exactly_the_distance_product_zero_test_and_claim`.

- [x] **INV-MEMBER-04: Membership cost**
  - Kind: constraint
  - Statement: For each n in {1,2,3,8}, the membership fixture has exactly n+2 rows and 2*n+4 variables.
  - Location: `src/circuit/builtins/gadgets/membership.rs:7-23` (`is_in`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/r1cs.rs`
  - Covered by: `tests/unit/gadgets/membership/r1cs.rs::counts_grow_by_one_row_and_two_variables_per_member`.

- [x] **INV-MEMBER-05: Honest membership rows**
  - Kind: completeness
  - Statement: For every pinned vector, no row is unsatisfied by its honest membership witness.
  - Location: `src/circuit/builtins/gadgets/membership.rs:7-23` (`is_in`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/r1cs.rs`
  - Covered by: `tests/unit/gadgets/membership/r1cs.rs::every_vector_checks_the_placeholder_and_refuses_a_wrong_or_nonboolean_flag`.

- [x] **INV-MEMBER-06: Changed membership flag**
  - Kind: soundness
  - Statement: For every pinned vector, its flipped flag or nonboolean flag 2 is refused at exactly claim row four.
  - Location: `src/circuit/builtins/gadgets/membership.rs:7-23` (`is_in`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/r1cs.rs`
  - Covered by: `tests/unit/gadgets/membership/r1cs.rs::every_vector_checks_the_placeholder_and_refuses_a_wrong_or_nonboolean_flag`.

- [x] **INV-MEMBER-07: Free-variable classification**
  - Kind: soundness
  - Statement: For every pinned vector, exactly the enumerated unused set inputs are free, and exactly the zero-product inverse hint is tolerated when the value is a member.
  - Location: `src/circuit/builtins/gadgets/membership.rs:7-23` (`is_in`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/r1cs.rs`
  - Covered by: `tests/unit/gadgets/membership/r1cs.rs::only_nonbinding_set_inputs_and_equality_inverse_hints_can_be_free`.

- [x] **INV-MEMBER-08: Membership setup shape**
  - Kind: shape
  - Statement: For every pinned vector, `check_constraints` confirms exactly the five placeholder rows.
  - Location: `src/circuit/builtins/gadgets/membership.rs:7-23` (`is_in`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/r1cs.rs`
  - Covered by: `tests/unit/gadgets/membership/r1cs.rs::every_vector_checks_the_placeholder_and_refuses_a_wrong_or_nonboolean_flag`.

- [x] **INV-MEMBER-09: Wrong membership native rule**
  - Kind: error
  - Statement: For every flipped membership claim, native evaluation returns exactly the named flag RuleBroken diagnostic.
  - Location: `src/circuit/builtins/gadgets/membership.rs:7-23` (`is_in`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/native.rs`
  - Error: `CircuitErrorKind::RuleBroken`
  - Covered by: `tests/unit/gadgets/membership/native.rs::every_value_is_in_exactly_the_sets_that_hold_it_natively`.

- [x] **INV-MEMBER-10: circomlib membership relation**
  - Kind: equivalence
  - Statement: For every pinned value and both Boolean claims, SDK membership and the circomlib IsEqual reference accept exactly the same relation.
  - Location: `src/circuit/builtins/gadgets/membership.rs:7-23` (`is_in`)
  - Severity: High
  - Suggested test: external; `tests/unit/gadgets/membership/external.rs`
  - Covered by: `tests/unit/gadgets/membership/external.rs::circomlib_membership_accepts_exactly_the_sdk_flags`.

- [x] **INV-MEMBER-11: Membership proof interoperability**
  - Kind: interop
  - Statement: For the 5-in-{3,5,7} fixture, snarkjs accepts its witness, rejects its flipped flag, and verifies its Groth16 proof with no public inputs.
  - Location: `src/circuit/builtins/gadgets/membership.rs:7-23` (`is_in`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/gadgets/membership/external.rs`
  - Covered by: `tests/unit/gadgets/membership/external.rs::snarkjs_checks_honest_and_tampered_membership_and_proves_both_operations`.

- [x] **INV-MEMBER-12: Generated membership**
  - Kind: native equivalence
  - Statement: For every generated set and member or outsider, the circuit flag is exactly Rust slice `contains`.
  - Location: `src/circuit/builtins/gadgets/membership.rs:7-23` (`is_in`)
  - Severity: High
  - Suggested test: property (proptest); `tests/unit/gadgets/membership/properties.rs`
  - Covered by: `tests/unit/gadgets/membership/properties.rs::membership_matches_slice_contains_for_random_sets`.

- [x] **INV-MEMBER-13: Picus membership determinism**
  - Kind: equivalence
  - Statement: For the three-member relation, Picus returns exactly Safe for the SDK and independent circomlib claimed flag.
  - Location: `src/circuit/builtins/gadgets/membership.rs:7-23` (`is_in`)
  - Severity: High
  - Suggested test: external; `tests/unit/gadgets/membership/picus.rs`
  - Covered by: `tests/unit/gadgets/membership/picus.rs::picus_proves_membership_flags_deterministic_in_both_relations`.

- [x] **INV-MEMBER-26: Membership circom count pins**
  - Kind: constraint
  - Statement: For the three-member query, SDK constraints/variables are exactly 5/10 and the independent circomlib reference is exactly 23/28.
  - Location: `src/circuit/builtins/gadgets/membership.rs:7-23` (`is_in`).
  - Severity: Medium
  - Suggested test: positive; `tests/unit/gadgets/membership/external.rs`
  - Covered by: `tests/unit/gadgets/membership/external.rs::membership_and_assertion_sizes_are_pinned_against_circom`.

- [x] **INV-MEMBER-28: Constant membership frame**
  - Kind: constraint
  - Statement: For the constant query 5 in {3,5}, the only allocated variable and row are exactly the caller-supplied flag claim.
  - Location: `src/circuit/builtins/gadgets/membership.rs:7-23` (`is_in`).
  - Severity: Medium
  - Suggested test: positive; `tests/unit/gadgets/membership/r1cs.rs`
  - Covered by: `tests/unit/gadgets/membership/r1cs.rs::constant_membership_allocates_only_its_claim`.

## Membership assertion (`assert_in`)

- [x] **INV-MEMBER-14: Native membership assertion**
  - Kind: semantics
  - Statement: For every pinned vector, native assertion succeeds exactly when the set contains the value.
  - Location: `src/circuit/builtins/gadgets/membership.rs:12-23` (`assert_in`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/native.rs`
  - Covered by: `tests/unit/gadgets/membership/native.rs::assert_in_holds_natively_exactly_for_a_member`.

- [x] **INV-MEMBER-15: Assertion golden rows**
  - Kind: constraint
  - Statement: For the three-member fixture, the exported relation is exactly two distance-product rows and a final zero row, over seven variables and no public inputs.
  - Location: `src/circuit/builtins/gadgets/membership.rs:12-23` (`assert_in`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/r1cs.rs`
  - Covered by: `tests/unit/gadgets/membership/r1cs.rs::assertion_exports_exactly_the_distance_product_and_zero_row`.

- [x] **INV-MEMBER-16: Constant members frame**
  - Kind: constraint
  - Statement: For a variable value and the constant set {3,5}, exactly two rows over three variables are exported; constants allocate no inputs.
  - Location: `src/circuit/builtins/gadgets/membership.rs:12-23` (`assert_in`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/r1cs.rs`
  - Covered by: `tests/unit/gadgets/membership/r1cs.rs::constant_members_add_no_input_variables_and_empty_membership_is_false`.

- [x] **INV-MEMBER-17: Member satisfies assertion rows**
  - Kind: completeness
  - Statement: For every pinned member vector, the honest assertion witness satisfies every exported row.
  - Location: `src/circuit/builtins/gadgets/membership.rs:12-23` (`assert_in`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/r1cs.rs`
  - Covered by: `tests/unit/gadgets/membership/r1cs.rs::every_vector_checks_the_placeholder_and_refuses_a_wrong_or_nonboolean_flag`.

- [x] **INV-MEMBER-18: Outsider is refused**
  - Kind: soundness
  - Statement: For every pinned outsider, its fully recomputed product witness is refused at exactly the final assertion row two; changing an honest member witness to the outsider also breaks a proving row.
  - Location: `src/circuit/builtins/gadgets/membership.rs:12-23` (`assert_in`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/r1cs.rs`
  - Covered by: `tests/unit/gadgets/membership/r1cs.rs::every_vector_checks_the_placeholder_and_refuses_a_wrong_or_nonboolean_flag`.

- [x] **INV-MEMBER-19: Assertion setup shape**
  - Kind: shape
  - Statement: For every pinned member vector, the proving rows are exactly the three placeholder rows.
  - Location: `src/circuit/builtins/gadgets/membership.rs:12-23` (`assert_in`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/r1cs.rs`
  - Covered by: `tests/unit/gadgets/membership/r1cs.rs::every_vector_checks_the_placeholder_and_refuses_a_wrong_or_nonboolean_flag`.

- [x] **INV-MEMBER-20: Outsider native error**
  - Kind: error
  - Statement: For every pinned outsider, `assert_in` returns exactly RuleBroken with the caller-supplied membership rule.
  - Location: `src/circuit/builtins/gadgets/membership.rs:12-23` (`assert_in`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/native.rs`
  - Error: `CircuitErrorKind::RuleBroken`
  - Covered by: `tests/unit/gadgets/membership/native.rs::assert_in_holds_natively_exactly_for_a_member`.

- [x] **INV-MEMBER-21: Empty assertion cannot export**
  - Kind: error
  - Statement: For every value, asserting membership in an empty set has an unsatisfiable constant assertion; setup export returns exactly RuleBroken.
  - Location: `src/circuit/builtins/gadgets/membership.rs:12-23` (`assert_in`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/membership/r1cs.rs`
  - Error: `CircuitErrorKind::RuleBroken`
  - Covered by: `tests/unit/gadgets/membership/r1cs.rs::constant_members_add_no_input_variables_and_empty_membership_is_false`.

- [x] **INV-MEMBER-22: Assertion circom relation**
  - Kind: equivalence
  - Statement: For every pinned member and outsider, SDK assertion and the independent circom product relation accept exactly the same cases.
  - Location: `src/circuit/builtins/gadgets/membership.rs:12-23` (`assert_in`)
  - Severity: High
  - Suggested test: external; `tests/unit/gadgets/membership/external.rs`
  - Covered by: `tests/unit/gadgets/membership/external.rs::the_circom_product_accepts_exactly_the_sdk_members`.

- [x] **INV-MEMBER-23: Assertion proof interoperability**
  - Kind: interop
  - Statement: For the 5-in-{3,5,7} fixture, snarkjs accepts its witness, refuses its changed value and verifies its proof.
  - Location: `src/circuit/builtins/gadgets/membership.rs:12-23` (`assert_in`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/gadgets/membership/external.rs`
  - Covered by: `tests/unit/gadgets/membership/external.rs::snarkjs_checks_honest_and_tampered_membership_and_proves_both_operations`.

- [x] **INV-MEMBER-24: Generated assertion**
  - Kind: soundness
  - Statement: For every generated set and member or outsider, native assertion succeeds exactly when Rust slice contains succeeds.
  - Location: `src/circuit/builtins/gadgets/membership.rs:12-23` (`assert_in`)
  - Severity: Critical
  - Suggested test: property (proptest); `tests/unit/gadgets/membership/properties.rs`
  - Covered by: `tests/unit/gadgets/membership/properties.rs::membership_matches_slice_contains_for_random_sets`.

- [x] **INV-MEMBER-25: Assertion intentionally has multiple members**
  - Kind: equivalence
  - Statement: For the three-member assertion with value promoted to an output, Picus returns exactly Unsafe in SDK and circom because several members can satisfy the relation.
  - Location: `src/circuit/builtins/gadgets/membership.rs:12-23` (`assert_in`)
  - Severity: High
  - Suggested test: external; `tests/unit/gadgets/membership/picus.rs`
  - Covered by: `tests/unit/gadgets/membership/picus.rs::picus_finds_multiple_members_can_satisfy_assert_in`.

- [x] **INV-MEMBER-27: Assertion circom count pins**
  - Kind: constraint
  - Statement: For the three-member assertion, SDK and circom constraints/variables are both exactly 3/7.
  - Location: `src/circuit/builtins/gadgets/membership.rs:12-23` (`assert_in`).
  - Severity: Medium
  - Suggested test: positive; `tests/unit/gadgets/membership/external.rs`
  - Covered by: `tests/unit/gadgets/membership/external.rs::membership_and_assertion_sizes_are_pinned_against_circom`.

## One-hot indexing (`one_hot`)

- [x] **INV-INDEX-01: Exact decoded flag**
  - Kind: semantics
  - Statement: For every index in 0..3, exactly its flag is one and every other flag is zero.
  - Location: `src/circuit/builtins/gadgets/index.rs:10-25` (`one_hot`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/index/native.rs`
  - Covered by: `tests/unit/gadgets/index/native.rs::every_valid_index_decodes_and_selects_exactly_its_item`.

- [x] **INV-INDEX-02: Singleton decoder golden rows**
  - Kind: constraint
  - Statement: For the singleton fixture, the export has exactly the two zero-test rows, one in-bounds row and one claimed-flag row over five variables.
  - Location: `src/circuit/builtins/gadgets/index.rs:10-25` (`one_hot`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/index/r1cs.rs`
  - Covered by: `tests/unit/gadgets/index/r1cs.rs::singleton_decode_exports_the_zero_test_bound_and_claim_rows`.

- [x] **INV-INDEX-03: Decoder count and digest**
  - Kind: constraint
  - Statement: For every tested n in {1,3,8}, exactly 3*n+1 rows and 3*n+2 variables are exported; the three-item digest is exactly pinned.
  - Location: `src/circuit/builtins/gadgets/index.rs:10-25` (`one_hot`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/index/r1cs.rs`
  - Covered by: `tests/unit/gadgets/index/r1cs.rs::indexing_sizes_and_three_item_digests_are_pinned`.

- [x] **INV-INDEX-04: Every valid index satisfies rows**
  - Kind: completeness
  - Statement: For every valid three-item index, the honest decoded witness satisfies every row.
  - Location: `src/circuit/builtins/gadgets/index.rs:10-25` (`one_hot`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/index/r1cs.rs`
  - Covered by: `tests/unit/gadgets/index/r1cs.rs::all_valid_indices_check_the_placeholder_and_bind_each_flag_and_selection`.

- [x] **INV-INDEX-05: Every flag is bound**
  - Kind: soundness
  - Statement: For every valid index and each flag position, adding one to that flag is refused at exactly its claim row.
  - Location: `src/circuit/builtins/gadgets/index.rs:10-25` (`one_hot`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/gadgets/index/r1cs.rs`
  - Covered by: `tests/unit/gadgets/index/r1cs.rs::all_valid_indices_check_the_placeholder_and_bind_each_flag_and_selection`.

- [x] **INV-INDEX-06: Out-of-bounds cannot satisfy**
  - Kind: soundness
  - Statement: For every tested invalid index including 3,4,2^64,p-1, the fully recomputed equality witnesses are refused at exactly the in-bounds row six; single-index tampering also breaks a proving row.
  - Location: `src/circuit/builtins/gadgets/index.rs:10-25` (`one_hot`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/gadgets/index/r1cs.rs`
  - Covered by: `tests/unit/gadgets/index/r1cs.rs::out_of_bounds_indices_cannot_satisfy_the_exported_or_proving_rows`.

- [x] **INV-INDEX-07: Decoder free-variable report**
  - Kind: soundness
  - Statement: For every three-item index, exactly zero private variables are free; only the equality inverse hint for the selected position is tolerated.
  - Location: `src/circuit/builtins/gadgets/index.rs:10-25` (`one_hot`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/gadgets/index/r1cs.rs`
  - Covered by: `tests/unit/gadgets/index/r1cs.rs::decoder_flags_are_bound_and_only_the_matching_inverse_hint_is_tolerated`.

- [x] **INV-INDEX-08: Decoder setup rows**
  - Kind: shape
  - Statement: For every valid index, placeholder and proving matrices have exactly the same ten rows.
  - Location: `src/circuit/builtins/gadgets/index.rs:10-25` (`one_hot`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/index/r1cs.rs`
  - Covered by: `tests/unit/gadgets/index/r1cs.rs::all_valid_indices_check_the_placeholder_and_bind_each_flag_and_selection`.

- [x] **INV-INDEX-09: Invalid index diagnostic**
  - Kind: error
  - Statement: For every tested out-of-bounds field index and the empty array, native decoding returns exactly IndexOutOfBounds.
  - Location: `src/circuit/builtins/gadgets/index.rs:10-25` (`one_hot`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/index/native.rs`
  - Error: `CircuitErrorKind::IndexOutOfBounds`
  - Covered by: `tests/unit/gadgets/index/native.rs::every_out_of_bounds_index_has_the_named_error`.

- [x] **INV-INDEX-10: circomlib Decoder relation**
  - Kind: equivalence
  - Statement: For every honest case, every changed flag and every invalid index, SDK and circomlib Decoder with success=1 accept exactly the same relation.
  - Location: `src/circuit/builtins/gadgets/index.rs:10-25` (`one_hot`)
  - Severity: High
  - Suggested test: external; `tests/unit/gadgets/index/external.rs`
  - Covered by: `tests/unit/gadgets/index/external.rs::circomlib_decoder_accepts_exactly_the_sdk_indices_and_flags`.

- [x] **INV-INDEX-11: Decoder proof interoperability**
  - Kind: interop
  - Statement: For index one, snarkjs accepts the honest decoded witness, rejects its changed flag and verifies its proof.
  - Location: `src/circuit/builtins/gadgets/index.rs:10-25` (`one_hot`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/gadgets/index/external.rs`
  - Covered by: `tests/unit/gadgets/index/external.rs::snarkjs_checks_honest_and_tampered_indices_and_proves_both_operations`.

- [x] **INV-INDEX-12: Generated flag tampering**
  - Kind: soundness
  - Statement: For every generated valid index, changing the selected flag to 2 is refused by the proving rows.
  - Location: `src/circuit/builtins/gadgets/index.rs:10-25` (`one_hot`)
  - Severity: Critical
  - Suggested test: property (proptest); `tests/unit/gadgets/index/properties.rs`
  - Covered by: `tests/unit/gadgets/index/properties.rs::random_items_select_the_index_and_refuse_every_changed_claim`.

- [x] **INV-INDEX-13: Picus decoded flags**
  - Kind: equivalence
  - Statement: For the three-item decoder, Picus returns exactly Safe for all three flags as outputs in SDK and circomlib.
  - Location: `src/circuit/builtins/gadgets/index.rs:10-25` (`one_hot`)
  - Severity: High
  - Suggested test: external; `tests/unit/gadgets/index/picus.rs`
  - Covered by: `tests/unit/gadgets/index/picus.rs::picus_proves_flags_and_selection_fixed_by_the_index_and_items`.

- [x] **INV-INDEX-26: Decoder circom count pins**
  - Kind: constraint
  - Statement: For the three-item decoder, SDK constraints/variables are exactly 10/11 and circomlib constraints/variables are exactly 10/10.
  - Location: `src/circuit/builtins/gadgets/index.rs:10-25` (`one_hot`).
  - Severity: Medium
  - Suggested test: positive; `tests/unit/gadgets/index/external.rs`
  - Covered by: `tests/unit/gadgets/index/external.rs::indexing_sizes_are_pinned_against_circomlib`.

- [x] **INV-INDEX-28: Constant indexing frame**
  - Kind: constraint
  - Statement: For constant index one and items [3,5,7], no row or witness is allocated before the three flag claims and one selected-value claim.
  - Location: `src/circuit/builtins/gadgets/index.rs:10-40` (`one_hot, select_index`).
  - Severity: Medium
  - Suggested test: positive; `tests/unit/gadgets/index/r1cs.rs`
  - Covered by: `tests/unit/gadgets/index/r1cs.rs::constant_indexing_adds_no_rows_or_witnesses_before_the_claims`.

## Indexed selection (`select_index`)

- [x] **INV-INDEX-14: Exact selected item**
  - Kind: semantics
  - Statement: For every valid index and pinned item array including duplicates, zeros and p-1, native selection is exactly the indexed item.
  - Location: `src/circuit/builtins/gadgets/index.rs:29-40` (`select_index`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/index/native.rs`
  - Covered by: `tests/unit/gadgets/index/native.rs::every_valid_index_decodes_and_selects_exactly_its_item`.

- [x] **INV-INDEX-15: Singleton selection golden rows**
  - Kind: constraint
  - Statement: For the singleton selection, the export is exactly the zero-test, bound and equality rows over six variables; selection allocates no additional witness.
  - Location: `src/circuit/builtins/gadgets/index.rs:29-40` (`select_index`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/index/r1cs.rs`
  - Covered by: `tests/unit/gadgets/index/r1cs.rs::singleton_selection_exports_no_selection_witness`.

- [x] **INV-INDEX-16: Selection count and digest**
  - Kind: constraint
  - Statement: For every tested n in {1,3,8}, exactly 3*n+1 rows and 4*n+2 variables are exported; the three-item digest is exactly pinned.
  - Location: `src/circuit/builtins/gadgets/index.rs:29-40` (`select_index`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/index/r1cs.rs`
  - Covered by: `tests/unit/gadgets/index/r1cs.rs::indexing_sizes_and_three_item_digests_are_pinned`.

- [x] **INV-INDEX-17: Honest selection rows**
  - Kind: completeness
  - Statement: For every pinned array and valid index, the honest selected witness satisfies every exported row.
  - Location: `src/circuit/builtins/gadgets/index.rs:29-40` (`select_index`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/index/r1cs.rs`
  - Covered by: `tests/unit/gadgets/index/r1cs.rs::all_valid_indices_check_the_placeholder_and_bind_each_flag_and_selection`.

- [x] **INV-INDEX-18: Changed selection refused**
  - Kind: soundness
  - Statement: For every pinned array and valid index, adding one to the claimed result is refused at exactly row nine.
  - Location: `src/circuit/builtins/gadgets/index.rs:29-40` (`select_index`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/gadgets/index/r1cs.rs`
  - Covered by: `tests/unit/gadgets/index/r1cs.rs::all_valid_indices_check_the_placeholder_and_bind_each_flag_and_selection`.

- [x] **INV-INDEX-19: Unused selection inputs**
  - Kind: soundness
  - Statement: For each index in the three-distinct-item fixture, exactly the enumerated unselected items that do not fix an intermediate witness are reported free.
  - Location: `src/circuit/builtins/gadgets/index.rs:29-40` (`select_index`)
  - Severity: Critical
  - Suggested test: positive/negative; `tests/unit/gadgets/index/r1cs.rs`
  - Covered by: `tests/unit/gadgets/index/r1cs.rs::selection_reports_unused_inputs_without_claiming_joint_uniqueness`.

- [x] **INV-INDEX-20: Selection setup rows**
  - Kind: shape
  - Statement: For every pinned array and valid index, proving matrices are exactly the ten placeholder rows.
  - Location: `src/circuit/builtins/gadgets/index.rs:29-40` (`select_index`)
  - Severity: High
  - Suggested test: positive/negative; `tests/unit/gadgets/index/r1cs.rs`
  - Covered by: `tests/unit/gadgets/index/r1cs.rs::all_valid_indices_check_the_placeholder_and_bind_each_flag_and_selection`.

- [x] **INV-INDEX-21: Selection index error**
  - Kind: error
  - Statement: For every tested out-of-bounds index and an empty array, native selection returns exactly IndexOutOfBounds.
  - Location: `src/circuit/builtins/gadgets/index.rs:29-40` (`select_index`)
  - Severity: Medium
  - Suggested test: positive/negative; `tests/unit/gadgets/index/native.rs`
  - Error: `CircuitErrorKind::IndexOutOfBounds`
  - Covered by: `tests/unit/gadgets/index/native.rs::every_out_of_bounds_index_has_the_named_error`.

- [x] **INV-INDEX-22: circomlib Multiplexer relation**
  - Kind: equivalence
  - Statement: For every honest case, changed output and out-of-bounds index, SDK and circomlib Multiplexer accept exactly the same relation.
  - Location: `src/circuit/builtins/gadgets/index.rs:29-40` (`select_index`)
  - Severity: High
  - Suggested test: external; `tests/unit/gadgets/index/external.rs`
  - Covered by: `tests/unit/gadgets/index/external.rs::circomlib_multiplexer_accepts_exactly_the_sdk_indices_and_selections`.

- [x] **INV-INDEX-23: Selection proof interoperability**
  - Kind: interop
  - Statement: For the endpoint array at index two, snarkjs accepts the honest selection, refuses a changed output and verifies its proof.
  - Location: `src/circuit/builtins/gadgets/index.rs:29-40` (`select_index`)
  - Severity: Medium
  - Suggested test: external; `tests/unit/gadgets/index/external.rs`
  - Covered by: `tests/unit/gadgets/index/external.rs::snarkjs_checks_honest_and_tampered_indices_and_proves_both_operations`.

- [x] **INV-INDEX-24: Random output tampering**
  - Kind: soundness
  - Statement: For every generated array, valid index and nonzero offset, native selection and proving rows refuse a claim changed by that offset.
  - Location: `src/circuit/builtins/gadgets/index.rs:29-40` (`select_index`)
  - Severity: Critical
  - Suggested test: property (proptest); `tests/unit/gadgets/index/properties.rs`
  - Covered by: `tests/unit/gadgets/index/properties.rs::random_items_select_the_index_and_refuse_every_changed_claim`.

- [x] **INV-INDEX-25: Picus selected output**
  - Kind: equivalence
  - Statement: For three items, Picus returns exactly Safe for the selected output in both SDK and circomlib.
  - Location: `src/circuit/builtins/gadgets/index.rs:29-40` (`select_index`)
  - Severity: High
  - Suggested test: external; `tests/unit/gadgets/index/picus.rs`
  - Covered by: `tests/unit/gadgets/index/picus.rs::picus_proves_flags_and_selection_fixed_by_the_index_and_items`.

- [x] **INV-INDEX-27: Multiplexer circom count pins**
  - Kind: constraint
  - Statement: For three-item selection, SDK constraints/variables are exactly 10/14 and circomlib constraints/variables are exactly 23/26.
  - Location: `src/circuit/builtins/gadgets/index.rs:29-40` (`select_index`).
  - Severity: Medium
  - Suggested test: positive; `tests/unit/gadgets/index/external.rs`
  - Covered by: `tests/unit/gadgets/index/external.rs::indexing_sizes_are_pinned_against_circomlib`.

## Specification and limits

No SPEC_DIVERGENCE was found for these gadget semantics. The DSL specification names membership and indexing but does not prescribe their constraint counts; the exact costs above come from the source and exported matrices.

A single-variable perturbation report does not establish uniqueness when several values can move together. In particular, `assert_in` constrains membership rather than selecting a unique set member. Its Picus Unsafe result is expected when the queried value is made an output; it is not a dishonest-membership acceptance.

The Picus Poseidon and hash-chain invariants remain partial: at the 30-second limit the one-value chain returned Safe on the SDK relation and Unknown on circom, and the three-value chain returned Unknown on both. All standalone Poseidon arities returned Safe in the first run; a later concurrent run timed out on SDK arity ten. The external relation tests, output tampering, native references, pinned matrices and proof verification remain independently asserted.
