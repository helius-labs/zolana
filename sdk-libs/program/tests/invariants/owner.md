# UtxoOwner Invariants

Covers `SigningPubkey` and `UtxoOwner` of `sdk-libs/keypair/src/circuit/owner.rs`: `identity`, `hash`, the
tag check, `DataHash`, the accessors, and their `Assert` and `Select` impls, against the
native `zolana-keypair` owner hash (`ShieldedAddress::owner_hash`,
`PublicKey::owner_proof_input_hash`) and `zolana-hasher` (`hash_bytes`, `Poseidon`,
`solana_owner_identity`). Invariants every type shares live in
`cross-cutting.md`. ID prefix: `INV-OWNER`; the tests live in `tests/unit/protocol/owner/`.

Owners instantiate through `sdk-libs/keypair/src/circuit/conversion.rs`: a `ShieldedAddress` through
`client::UtxoOwner::try_from` (`sdk-libs/keypair/src/circuit/owner_input.rs`), a `client::UtxoOwner` preimage directly. Both
allocate the tag ("an owner tag", wire 1 when the owner is the first input), the 32 key
bytes (9 range-check rows each), the rule row "the owner tag is not S", and the nullifier key as one field ("a
32-byte proof input", no row). The fixtures in `tests/unit/protocol/owner/fixtures.rs`:
`OwnerHash` (address) and `PreimageHash` (preimage) assert `owner.hash() == hash` with "the
owner hash is Poseidon(identity, nullifier_pk)", `Identity` asserts `key().identity()` with
"the identity is hash_bytes(tag || key)", `OwnerDataHash` goes through `DataHash::hash`,
`HashedTwice` hashes an owner and its clone and reads the clone's identity, and the
`Key*`/`UtxoOwner*` fixtures compare two preimages with "the owners are equal" and "the claim is
whether the owners are equal" or select between them. The keys are Ed25519 and PDA
owners from seeds 7 and 42 (`keys.rs`); the preimage pairs change exactly one of key byte 0,
key byte 31 and the nullifier key of a Solana-tagged base. S is the only valid tag, so no
valid pair differs in the tag.

## SigningPubkey and UtxoOwner (`identity`, `hash`, the tag check, `DataHash`, accessors)

### Native equivalence
- [x] **INV-OWNER-01: every address hashes to its native owner hash**
  - Covered by: `tests/unit/protocol/owner/native.rs` `every_key_hashes_to_the_native_owner_hash_for_every_curve`; `tests/unit/protocol/owner/properties.rs` `every_random_key_hashes_to_its_native_owner_hash_natively_and_in_r1cs` (property)
  - Kind: native equivalence
  - Statement: for every Ed25519 and PDA key and every random Ed25519 or PDA key, the native value of `UtxoOwner::hash` of the instantiated `ShieldedAddress` is exactly `ShieldedAddress::owner_hash()`.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:114-119` (`fn hash`), `sdk-libs/keypair/src/circuit/conversion.rs:12-22`, `sdk-libs/keypair/src/circuit/owner_input.rs:33-62`
  - Severity: Critical
  - Suggested test: positive + property; `tests/unit/protocol/owner/native.rs`, `tests/unit/protocol/owner/properties.rs`

- [x] **INV-OWNER-02: every address's identity is its native owner proof input hash**
  - Covered by: `tests/unit/protocol/owner/native.rs` `every_key_hashes_to_the_native_owner_hash_for_every_curve`
  - Kind: native equivalence
  - Statement: for every Ed25519 and PDA key, the native value of `SigningPubkey::identity` is exactly `signing_pubkey.owner_proof_input_hash()`.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:56-58` (`fn identity`), `sdk-libs/keypair/src/circuit/owner.rs:73-78` (`fn tagged`)
  - Severity: Critical
  - Suggested test: positive; `tests/unit/protocol/owner/native.rs`

- [x] **INV-OWNER-03: the R1CS claim wire of every honest owner hash assignment is the native hash**
  - Covered by: `tests/unit/protocol/owner/r1cs.rs` `every_key_satisfies_every_row_with_its_native_hash_on_the_claim_wire`
  - Kind: native equivalence
  - Statement: for every key, wire 1 of the exported `OwnerHash` assignment is exactly `owner_hash()`.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:114-119` (`fn hash`)
  - Severity: Critical
  - Suggested test: positive; `tests/unit/protocol/owner/r1cs.rs`

### Semantics
- [x] **INV-OWNER-04: the identity is hash_bytes of the tag byte then the key**
  - Covered by: `tests/unit/protocol/owner/native.rs` `the_identity_is_hash_bytes_of_the_tag_then_the_key`
  - Kind: semantics
  - Statement: for every key, `owner_proof_input_hash()` is exactly `hash_bytes(tag || key)` over the 33-byte preimage, and exactly `solana_owner_identity(key)`.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:56-58`, `sdk-libs/keypair/src/circuit/owner.rs:73-78`
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/owner/native.rs`

- [x] **INV-OWNER-05: the owner hash is Poseidon of the identity and the nullifier key**
  - Covered by: `tests/unit/protocol/owner/native.rs` `every_key_holds_natively_with_its_native_hash_and_identity`; `tests/unit/protocol/owner/properties.rs` `every_preimage_hashes_to_poseidon_of_its_identity_and_nullifier_key` (property)
  - Kind: semantics
  - Statement: for every key and every random preimage with tag S, native `PreimageHash` holds exactly with `Poseidon(hash_bytes(tag || key), nullifier_pk)`, and so do `OwnerHash` and `Identity` with the native values.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:114-119` (`fn hash`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/protocol/owner/native.rs`, `tests/unit/protocol/owner/properties.rs`

- [x] **INV-OWNER-06: every single preimage field changes the owner hash**
  - Covered by: `tests/unit/protocol/owner/native.rs` `every_single_preimage_field_change_moves_the_hash_to_the_native_hash_of_the_change`
  - Kind: semantics
  - Statement: for each change of exactly one of key byte 0, key byte 31 and the nullifier key, the owner hash is exactly the native hash of the changed preimage and differs from the base's.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:114-119`
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/owner/native.rs`

- [x] **INV-OWNER-07: an Ed25519 key and a PDA with the same bytes share the identity**
  - Covered by: `tests/unit/protocol/owner/native.rs` `an_ed25519_key_and_a_pda_with_the_same_bytes_share_the_identity`
  - Kind: semantics
  - Statement: an Ed25519 key and a PDA over the same 32 bytes have exactly the same circuit and native identity.
  - Location: `sdk-libs/keypair/src/circuit/owner_input.rs:33-54` (`Curve::Ed25519 | Curve::Pda => SOLANA_OWNER_TAG`)
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/owner/native.rs`

- [x] **INV-OWNER-08: the accessors and FromCircuit read the preimage**
  - Covered by: `tests/unit/protocol/owner/native.rs` `the_key_tag_and_nullifier_key_accessors_read_the_preimage`
  - Kind: semantics
  - Statement: for every key, `key().tag()` is exactly S, `nullifier_pk()` is exactly the address's nullifier key, and `client::UtxoOwner::from_circuit` returns exactly the preimage `client::UtxoOwner::try_from(&address)`.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:48-50`, `sdk-libs/keypair/src/circuit/owner.rs:106-112`, `sdk-libs/keypair/src/circuit/conversion.rs:32-40`
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/owner/native.rs`

- [x] **INV-OWNER-09: the data hash of an owner is its owner hash**
  - Covered by: `tests/unit/protocol/owner/native.rs` `the_data_hash_of_an_owner_is_its_owner_hash`; `tests/unit/protocol/owner/native.rs` `every_key_holds_natively_with_its_native_hash_and_identity`
  - Kind: semantics
  - Statement: for every key, `DataHash::hash` of the owner is exactly `owner_hash()`, and native `OwnerDataHash` holds with it.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:147-151` (`impl DataHash for UtxoOwner`)
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/owner/native.rs`

- [x] **INV-OWNER-10: the placeholders are Solana-tagged owners**
  - Covered by: `tests/unit/protocol/owner/native.rs` `the_placeholders_are_a_solana_tagged_owner`
  - Kind: semantics
  - Statement: `ShieldedAddress::placeholder()` is an Ed25519 address, `client::UtxoOwner::placeholder()` is exactly `{ tag: S, key: [0; 32], nullifier_pk: [0; 32] }`, and native `PreimageHash` holds for it.
  - Location: `sdk-libs/keypair/src/circuit/conversion.rs:63-79`
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/owner/native.rs`

### Error
- [x] **INV-OWNER-11: a hash or identity of another key breaks exactly the fixture rule natively**
  - Covered by: `tests/unit/protocol/owner/native.rs` `a_hash_or_identity_of_another_key_breaks_exactly_the_fixture_rule`; `tests/unit/protocol/owner/properties.rs` `every_preimage_hashes_to_poseidon_of_its_identity_and_nullifier_key` (property)
  - Kind: error
  - Statement: for every key, native `OwnerHash` with the next key's hash returns exactly `RuleBroken("the owner hash is Poseidon(identity, nullifier_pk)")` and native `Identity` with the next key's identity exactly `RuleBroken("the identity is hash_bytes(tag || key)")`, both located in `fixtures.rs`; a random other nullifier key's hash is refused the same way.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:56-58`, `sdk-libs/keypair/src/circuit/owner.rs:114-119`
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: negative + property; `tests/unit/protocol/owner/native.rs`, `tests/unit/protocol/owner/properties.rs`

- [x] **INV-OWNER-12: every tag other than S is refused by exactly the tag rule natively**
  - Covered by: `tests/unit/protocol/owner/native.rs` `every_tag_other_than_s_is_refused_by_exactly_the_tag_rule`; `tests/unit/protocol/owner/properties.rs` `a_random_tag_is_accepted_exactly_when_it_is_s` (property)
  - Kind: error
  - Statement: for every tag in 0..=255, native `PreimageHash` returns exactly `Ok(())` for S and exactly `RuleBroken("the owner tag is not S")` located in `sdk-libs/keypair/src/circuit/conversion.rs` for every other tag.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:28-46` (`SigningPubkey::new`), `sdk-libs/keypair/src/circuit/conversion.rs:42-61` (`fn owner`, `skip_tag_check = FALSE`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/protocol/owner/native.rs`, `tests/unit/protocol/owner/properties.rs`

- [x] **INV-OWNER-13: an address the native owner hash refuses is an invalid owner**
  - Covered by: `tests/unit/protocol/owner/native.rs` `an_address_the_native_owner_hash_refuses_is_refused_as_an_invalid_owner`
  - Kind: error
  - Statement: an address whose signing key is `PublicKey::zeroed()` (signature-type prefix 0, which no curve uses) and one whose nullifier key is 32 bytes of 255 are refused by `owner_hash()` with exactly "invalid signature-type prefix: 0" and "poseidon hash failed (code 8002)", by native instantiation with exactly `CircuitError.InvalidOwner` and "invalid proof input: " plus that message, and by `check_constraints(OwnerHash)` with exactly `CircuitError.InvalidOwner`.
  - Location: `sdk-libs/keypair/src/circuit/conversion.rs:12-22` (`fn instantiate` for `ShieldedAddress`)
  - Error: `CircuitErrorKind::InvalidOwner`
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/owner/native.rs`

- [x] **INV-OWNER-14: a preimage nullifier key of at least p is refused before it reaches the circuit**
  - Covered by: `tests/unit/protocol/owner/native.rs` `a_nullifier_key_of_at_least_p_is_refused_before_it_reaches_the_circuit`
  - Kind: error
  - Statement: a `client::UtxoOwner` whose nullifier key is the big-endian bytes of p or 32 bytes of 255 is refused by native instantiation with exactly `CircuitError.BytesTooLarge` and "32-byte input is too large for a circuit value", and by `check_constraints(PreimageHash)` with exactly `CircuitError.BytesTooLarge`.
  - Location: `sdk-libs/keypair/src/circuit/conversion.rs:42-61` (`fn owner`), `zk/dsl/src/conversion/var.rs:13-20` (`fn field`), `zk/dsl/src/conversion/var.rs:148-157` (`impl ProofInput for [u8; 32]`)
  - Error: `CircuitErrorKind::BytesTooLarge`
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/owner/native.rs`

### Constraint
- [x] **INV-OWNER-15: the owner hash fixtures have pinned sizes and digest**
  - Covered by: `tests/unit/protocol/owner/r1cs.rs` `the_owner_hash_fixtures_have_pinned_sizes_and_digest`
  - Kind: constraint
  - Statement: the `OwnerHash` export has exactly 770 constraints and 772 variables with sha256 `307d10b31e158f405f5394c3597e43b17027e67c7c499fddc105ccfa883d773a`, `Identity` exactly 530 and 532, and the `PreimageHash` export is byte-identical to `OwnerHash`'s.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:56-58`, `sdk-libs/keypair/src/circuit/owner.rs:114-119`
  - Severity: Medium
  - Suggested test: positive; `tests/unit/protocol/owner/r1cs.rs`

- [x] **INV-OWNER-16: the tag check costs one rule row**
  - Covered by: `tests/unit/protocol/owner/r1cs.rs` `the_tag_check_costs_one_rule_row`
  - Kind: constraint
  - Statement: the `Instantiated` export has exactly 288 + 1 constraints and 288 + 3 variables; the rule "the owner tag is not S" spans exactly row 288; tampering the tag wire alone breaks exactly that row.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:28-46` (`SigningPubkey::new`)
  - Severity: Medium
  - Suggested test: positive + negative; `tests/unit/protocol/owner/r1cs.rs`

- [x] **INV-OWNER-17: an owner and its clones share one hash and one identity**
  - Covered by: `tests/unit/protocol/owner/r1cs.rs` `an_owner_and_its_clone_share_one_hash_and_identity_so_each_further_claim_costs_one_row`
  - Kind: constraint
  - Statement: the `HashedTwice` export, which hashes an owner and its clone and reads the clone's identity, has exactly the constraint count of `OwnerHash` plus 2 and its variable count plus 1 (the `identity` input), and `check_constraints` returns exactly `Ok(772)`.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:56-58`, `sdk-libs/keypair/src/circuit/owner.rs:114-119`, `zk/dsl/src/circuit/builtins/field/var.rs:116-125` (`fn cached`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/protocol/owner/r1cs.rs`

### Completeness
- [x] **INV-OWNER-18: every key satisfies every row of the owner hash and identity fixtures**
  - Covered by: `tests/unit/protocol/owner/r1cs.rs` `every_key_satisfies_every_row_with_its_native_hash_on_the_claim_wire`; `tests/unit/protocol/owner/properties.rs` `every_random_key_hashes_to_its_native_owner_hash_natively_and_in_r1cs` (property)
  - Kind: completeness
  - Statement: for every key and every random key, the honest `OwnerHash` assignment leaves no exported row unsatisfied, and `check_constraints` returns exactly `Ok(770)` for `OwnerHash` and `Ok(530)` for `Identity`.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:56-58`, `sdk-libs/keypair/src/circuit/owner.rs:114-119`
  - Severity: Critical
  - Suggested test: positive + property; `tests/unit/protocol/owner/r1cs.rs`, `tests/unit/protocol/owner/properties.rs`

### Soundness
- [x] **INV-OWNER-19: a claimed hash or identity of another key breaks exactly the claim row**
  - Covered by: `tests/unit/protocol/owner/r1cs.rs` `a_claimed_hash_or_identity_of_another_key_breaks_exactly_the_claim_row`; `tests/unit/protocol/owner/properties.rs` `every_preimage_hashes_to_poseidon_of_its_identity_and_nullifier_key` (property)
  - Kind: soundness
  - Statement: for every key, `check_tampered` with wire 1 set to the next key's value returns exactly `ProofInputsBreakRule` at row 769 with the hash rule for `OwnerHash` and at row 529 with the identity rule for `Identity`; a random other nullifier key's hash leaves exactly row 769 unsatisfied in the `PreimageHash` export.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:56-58`, `sdk-libs/keypair/src/circuit/owner.rs:114-119`
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/protocol/owner/r1cs.rs`, `tests/unit/protocol/owner/properties.rs`

- [x] **INV-OWNER-20: no private variable of the owner hash fixture is free**
  - Covered by: `tests/unit/protocol/owner/r1cs.rs` `no_private_variable_of_the_owner_hash_fixture_is_free`
  - Kind: soundness
  - Statement: for every key, `check_private_variables(OwnerHash)` reports exactly 770 constraints, 771 private variables, no free and no tolerated variable.
  - Location: `sdk-libs/keypair/src/circuit/conversion.rs:42-61`, `sdk-libs/keypair/src/circuit/owner.rs:114-119`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/owner/r1cs.rs`

- [x] **INV-OWNER-21: the tag row accepts exactly S**
  - Covered by: `tests/unit/protocol/owner/r1cs.rs` `the_tag_row_accepts_exactly_s_and_names_the_tag_rule`
  - Kind: soundness
  - Statement: in the `Instantiated` export (tag wire 1, rule row 288), for every tag in 0..=255, the first unsatisfied row is exactly 288 when the tag is not S and none otherwise.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:28-46` (`SigningPubkey::new`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/owner/r1cs.rs`

- [ ] **INV-OWNER-22: Picus finds the owner hash fixed by the preimage**
  - Partial coverage: `tests/unit/protocol/owner/picus.rs` `picus_finds_no_second_owner_hash_for_one_preimage` runs Picus (cvc5) on the `OwnerHash` Picus export with the claim promoted, bounded at 60 s, and asserts only that it finds no counterexample: the run ends `Unknown`. The hash-free `Instantiated`, `KeyEqual` and `KeyIsEqual` exports also end `Unknown` at 150 s (the 288 byte range-check rows exceed the bound), so determinism is not proven; INV-OWNER-20 is the hermetic substitute.
  - Kind: soundness
  - Statement: Picus reports the `OwnerHash` Picus export with wire 1 promoted exactly `Safe`.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:114-119`
  - Severity: Medium
  - Suggested test: external (Picus); `tests/unit/protocol/owner/picus.rs`

### Shape
- [x] **INV-OWNER-23: a PDA key synthesizes the Ed25519 placeholder's rows**
  - Covered by: `tests/unit/protocol/owner/r1cs.rs` `every_key_satisfies_every_row_with_its_native_hash_on_the_claim_wire`
  - Kind: shape
  - Statement: for every Ed25519 and PDA key, `check_constraints(OwnerHash)` returns exactly `Ok(770)`: setup from the Ed25519 `ShieldedAddress` placeholder and proving build the same matrices.
  - Location: `sdk-libs/keypair/src/circuit/conversion.rs:12-22`, `sdk-libs/keypair/src/circuit/conversion.rs:63-69`
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/owner/r1cs.rs`

### Interop
- [x] **INV-OWNER-24: snarkjs accepts every honest owner hash witness and rejects a wrong claim**
  - Covered by: `tests/unit/protocol/owner/external.rs` `snarkjs_accepts_every_key_and_rejects_a_claimed_hash_of_another_key`
  - Kind: interop
  - Statement: for every key, `snarkjs wtns check` on the `OwnerHash` export returns exactly `WITNESS IS CORRECT` for the honest assignment and `WITNESS IS NOT CORRECT` with wire 1 set to the next key's hash.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:114-119`
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/protocol/owner/external.rs`

- [x] **INV-OWNER-25: snarkjs proves and verifies the owner hash circuit for a PDA key**
  - Covered by: `tests/unit/protocol/owner/external.rs` `snarkjs_proves_and_verifies_the_owner_hash_circuit_for_a_pda_key`
  - Kind: interop
  - Statement: snarkjs Groth16 setup, prove and verify on the `OwnerHash` export and a PDA key's assignment verifies with exactly the public signals `[]`.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:114-119`
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/protocol/owner/external.rs`

## Assert (`is_equal`, `assert_equal`, `assert_equal_if` on `SigningPubkey` and `UtxoOwner`)

### Semantics
- [x] **INV-OWNER-26: key equality ignores the nullifier key and owner equality does not**
  - Covered by: `tests/unit/protocol/owner/native.rs` `key_equality_ignores_the_nullifier_key_and_owner_equality_does_not`
  - Kind: semantics
  - Statement: native `KeyEqual` and `OwnerEqual` return exactly `Ok(())` for the same preimage; a changed key byte 0 or key byte 31 makes both return exactly `RuleBroken("the owners are equal")`; a changed nullifier key leaves `KeyEqual` at `Ok(())` and makes `OwnerEqual` return exactly that error.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:153-175`, `sdk-libs/keypair/src/circuit/owner.rs:187-210`
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/protocol/owner/native.rs`

- [x] **INV-OWNER-27: is_equal claims hold exactly for equal keys and owners**
  - Covered by: `tests/unit/protocol/owner/native.rs` `is_equal_claims_hold_exactly_for_equal_keys_and_owners`
  - Kind: semantics
  - Statement: for every preimage pair, native `KeyIsEqual` holds exactly for the claim "tag and key equal" and `OwnerIsEqual` exactly for "the preimages are equal"; the opposite claim returns exactly `RuleBroken("the claim is whether the owners are equal")`.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:154-156`, `sdk-libs/keypair/src/circuit/owner.rs:188-193`
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/protocol/owner/native.rs`

- [x] **INV-OWNER-28: native assert_equal_if checks exactly when the condition holds**
  - Covered by: `tests/unit/protocol/owner/native.rs` `assert_equal_if_checks_exactly_when_the_condition_holds`
  - Kind: semantics
  - Statement: for every preimage pair, native `KeyEqualIf` and `OwnerEqualIf` with the condition false return exactly `Ok(())`; with it true they return `Ok(())` exactly when the keys (respectively the preimages) are equal and `RuleBroken("the owners are equal")` otherwise.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:162-175`, `sdk-libs/keypair/src/circuit/owner.rs:200-210`
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/protocol/owner/native.rs`

### Constraint
- [x] **INV-OWNER-29: key equality costs two rows and owner equality three**
  - Covered by: `tests/unit/protocol/owner/r1cs.rs` `owner_equality_rows_refuse_every_single_field_change`
  - Kind: constraint
  - Statement: `Pair` has exactly 2 * (288 + 1) = 578 constraints and 581 variables; `KeyEqual` exactly 578 + 2 (one row per packed chunk of `tag || key`) and `OwnerEqual` exactly 578 + 3 (plus the nullifier key), both with 581 variables.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:158-160`, `sdk-libs/keypair/src/circuit/owner.rs:195-198`
  - Severity: Medium
  - Suggested test: positive; `tests/unit/protocol/owner/r1cs.rs`

### Soundness
- [x] **INV-OWNER-30: owner equality rows refuse every single field change**
  - Covered by: `tests/unit/protocol/owner/r1cs.rs` `owner_equality_rows_refuse_every_single_field_change`
  - Kind: soundness
  - Statement: on the `Pair` assignment, the first unsatisfied `KeyEqual` and `OwnerEqual` row is none for the same preimage, exactly 578 for a changed key byte 0, exactly 579 for key byte 31; for a changed nullifier key it is none for `KeyEqual` and exactly 580 for `OwnerEqual`.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:158-160`, `sdk-libs/keypair/src/circuit/owner.rs:195-198`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/owner/r1cs.rs`

- [x] **INV-OWNER-31: a flipped equality claim breaks exactly the claim row**
  - Covered by: `tests/unit/protocol/owner/r1cs.rs` `a_flipped_equality_claim_breaks_exactly_the_claim_row`
  - Kind: soundness
  - Statement: for every preimage pair, flipping the claim wire of `KeyIsEqual` and `OwnerIsEqual` makes `check_tampered` return exactly `ProofInputsBreakRule` at each export's last row with "the claim is whether the owners are equal".
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:154-156`, `sdk-libs/keypair/src/circuit/owner.rs:188-193`
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/owner/r1cs.rs`

- [x] **INV-OWNER-32: assert_equal_if refuses a changed field once the condition is set**
  - Covered by: `tests/unit/protocol/owner/r1cs.rs` `assert_equal_if_refuses_a_changed_field_once_the_condition_is_set`
  - Kind: soundness
  - Statement: for each single-field change with the condition false, setting the condition wire to 1 makes `check_tampered` return exactly `ProofInputsBreakRule` with "the owners are equal" at row 579 (key byte 0) or 580 (key byte 31) for both fixtures; for the nullifier key `KeyEqualIf` returns `Ok(())` and `OwnerEqualIf` breaks exactly row 581.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:162-175`, `sdk-libs/keypair/src/circuit/owner.rs:200-210`
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/owner/r1cs.rs`

## Select (`SigningPubkey::select`, `UtxoOwner::select`)

### Semantics
- [x] **INV-OWNER-33: select takes every field of the chosen owner**
  - Covered by: `tests/unit/protocol/owner/native.rs` `select_takes_every_field_of_the_chosen_owner`
  - Kind: semantics
  - Statement: for every preimage pair in both orders and both conditions, native `KeySelected` holds exactly with the chosen preimage's identity and `OwnerSelected` with its owner hash.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:177-185`, `sdk-libs/keypair/src/circuit/owner.rs:212-219`
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/owner/native.rs`

- [x] **INV-OWNER-34: select is not the unchosen owner**
  - Covered by: `tests/unit/protocol/owner/native.rs` `select_is_not_the_other_owner`
  - Kind: semantics
  - Statement: native `KeySelected` claiming the unchosen key's identity returns exactly `RuleBroken("the identity is hash_bytes(tag || key)")`, and `OwnerSelected` claiming the unchosen nullifier key's hash exactly `RuleBroken("the owner hash is Poseidon(identity, nullifier_pk)")`.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:177-185`, `sdk-libs/keypair/src/circuit/owner.rs:212-219`
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/owner/native.rs`

### Constraint
- [x] **INV-OWNER-35: the select fixtures have pinned sizes**
  - Covered by: `tests/unit/protocol/owner/r1cs.rs` `select_rows_hold_for_both_conditions_and_a_flipped_condition_breaks_one`
  - Kind: constraint
  - Statement: the `KeySelected` export has exactly 853 constraints and 856 variables and `OwnerSelected` exactly 1094 and 1097: one select row for the tag, one per key byte, and for `UtxoOwner` one for the nullifier key, before the hashing.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:177-185`, `sdk-libs/keypair/src/circuit/owner.rs:212-219`
  - Severity: Medium
  - Suggested test: positive; `tests/unit/protocol/owner/r1cs.rs`

### Completeness
- [x] **INV-OWNER-36: both conditions satisfy every select row**
  - Covered by: `tests/unit/protocol/owner/r1cs.rs` `select_rows_hold_for_both_conditions_and_a_flipped_condition_breaks_one`
  - Kind: completeness
  - Statement: for every single-field change and both conditions, `check_constraints` returns exactly `Ok(853)` for `KeySelected` and `Ok(1094)` for `OwnerSelected` with the chosen preimage's value.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:177-185`, `sdk-libs/keypair/src/circuit/owner.rs:212-219`
  - Severity: Critical
  - Suggested test: positive; `tests/unit/protocol/owner/r1cs.rs`

### Soundness
- [x] **INV-OWNER-37: a flipped condition breaks the select row of the changed field**
  - Covered by: `tests/unit/protocol/owner/r1cs.rs` `select_rows_hold_for_both_conditions_and_a_flipped_condition_breaks_one`
  - Kind: soundness
  - Statement: for both conditions, flipping the condition wire leaves exactly row 580 (key byte 0) or 611 (key byte 31) as the first unsatisfied row of both fixtures; for a changed nullifier key `KeySelected` stays satisfied and `OwnerSelected` breaks exactly row 612.
  - Location: `sdk-libs/keypair/src/circuit/owner.rs:177-185`, `sdk-libs/keypair/src/circuit/owner.rs:212-219`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/owner/r1cs.rs`

## Summary

- Total: 37 (Critical 13, High 18, Medium 6); covered 36, partial 1 (INV-OWNER-22, Picus
  `Unknown` within its bound); findings: none.
- The tag check's skip branch (`skip_tag_check` true for a dummy `WalletUtxo`) is covered in
  `utxo.md` (INV-UTXO-22).
- No circom reference: the Equivalence column is native equivalence against `zolana-keypair`
  (INV-OWNER-01..03).
