# Utxo Invariants

Covers `src/circuit/protocol/utxo/`, against the native `zolana-keypair` and
`zolana-transaction` values. Invariants every type shares live in `cross-cutting.md`. ID
prefixes: `INV-UTXO`, `INV-LEDGER`, `INV-TOKEN`, `INV-DATA`; the tests live in
`tests/unit/protocol/{utxo,ledger,token,data}/`. No invariant is extracted yet: run
[`PROMPT.md`](PROMPT.md) for this area.

## Utxo (`hash`, the nullifier, `SpentInput`, `dummy`)

`INV-UTXO`

Covers `Utxo` of `src/circuit/protocol/utxo/input.rs` as `WalletUtxo` instantiates it
(`src/conversion/utxo.rs`), against the native `zolana-transaction` commitment
(`ProofInputUtxo::hash`, `utxo::Utxo::hash`, `SppProofOutputUtxo::hash`, `WalletUtxo::utxo_hash`)
and nullifier (`utxo::Utxo::nullifier`); the tests live in `tests/unit/protocol/utxo/`. The
fixtures in `tests/unit/protocol/utxo/fixtures.rs`: `UtxoHash` asserts `utxo.hash() == hash`
with "the utxo hash is the native commitment" (wire 1 is `hash`), `Carried` asserts the
utxo's `nullifier`, `latest_tree_id` and `has_latest_tree_id` equal claimed inputs (wires 1 to
3) with "the utxo carries the claimed spend values", and `Instantiated` only instantiates.
The preimages (`vectors.rs`) are an Ed25519 SOL token of 1, a P256 USDC token of 2^64 - 1, a
PDA SOL token of 0, an Ed25519 data UTXO in a ring (data hash, ring data hash and ring
program id set), a P256 token in tree 2^16 - 1 reporting latest tree 4, and a PDA data UTXO
with blinding and data hash p - 1; the dummy is `SppProofInputUtxo::dummy_with_blinding` in
tree 3. `SpentInput` and `Utxo::spent` are crate-private and built only by the `TokenUtxo`
and `DataUtxo` spends (`INV-TOKEN`, `INV-DATA`, W8); the three fields they carry from the
`Utxo` are covered here (INV-UTXO-05, -08, -20, -21).

### Native equivalence
- [x] **INV-UTXO-01: every preimage hashes to its native commitment**
  - Covered by: `tests/unit/protocol/utxo/native.rs` `every_preimage_hashes_to_the_native_utxo_commitment`; `tests/unit/protocol/utxo/properties.rs` `every_random_preimage_hashes_to_its_native_commitment_natively_and_in_r1cs` (property)
  - Kind: native equivalence
  - Statement: for every preimage and every random Ed25519 preimage (random mint, amount, blinding, data hash, ring and tree id), the native value of `Utxo::hash` of the instantiated `WalletUtxo` is exactly `ProofInputUtxo::hash` of its proof input fields and exactly `utxo::Utxo::hash`, the wallet's `utxo_hash`.
  - Location: `src/circuit/protocol/utxo/input.rs:59-91` (`fn hash`, `fn hash_with`), `src/conversion/utxo.rs:15-107`
  - Severity: Critical
  - Suggested test: positive + property; `tests/unit/protocol/utxo/native.rs`, `tests/unit/protocol/utxo/properties.rs`

- [x] **INV-UTXO-02: a spent preimage hashes to its native output commitment**
  - Covered by: `tests/unit/protocol/utxo/native.rs` `every_preimage_hashes_when_spent_to_its_native_output_commitment`
  - Kind: native equivalence
  - Statement: for every preimage, the native value of `Utxo::hash` is exactly `SppProofOutputUtxo::hash(tree_id)` of the output with the same owner address, mint, amount, blinding, ring, data hash and tree id: a UTXO spends under the commitment it was created with.
  - Location: `src/circuit/protocol/utxo/input.rs:59-91`
  - Severity: Critical
  - Suggested test: positive; `tests/unit/protocol/utxo/native.rs`

- [x] **INV-UTXO-03: the circuit fields are the native proof input fields**
  - Covered by: `tests/unit/protocol/utxo/native.rs` `the_circuit_fields_are_the_native_proof_input_fields`
  - Kind: native equivalence
  - Statement: for every preimage, the native values of the domain, the tree id, the asset hash, the owner hash, the blinding, the data hash, the ring data hash and the ring program id are exactly the corresponding `ProofInputUtxo` fields.
  - Location: `src/conversion/utxo.rs:15-98` (`fn instantiate`)
  - Severity: Critical
  - Suggested test: positive; `tests/unit/protocol/utxo/native.rs`

- [x] **INV-UTXO-04: the R1CS claim wire of every honest assignment is the native commitment**
  - Covered by: `tests/unit/protocol/utxo/r1cs.rs` `every_preimage_and_a_dummy_satisfy_every_row_with_the_commitment_on_the_claim_wire`
  - Kind: native equivalence
  - Statement: for every preimage, wire 1 of the exported `UtxoHash` assignment is exactly the native commitment.
  - Location: `src/circuit/protocol/utxo/input.rs:59-91`
  - Severity: Critical
  - Suggested test: positive; `tests/unit/protocol/utxo/r1cs.rs`

- [x] **INV-UTXO-05: the carried nullifier is the wallet's native nullifier**
  - Covered by: `tests/unit/protocol/utxo/native.rs` `the_carried_nullifier_is_the_wallets_native_nullifier`
  - Kind: native equivalence
  - Statement: for every preimage, the native value of `Utxo::nullifier` is exactly the wallet's `nullifier`, `utxo::Utxo::nullifier(hash, key)`, and exactly `Poseidon(commitment, blinding, right_align(nullifier secret))`.
  - Location: `src/conversion/utxo.rs:83-88` ("utxo nullifier", `VariableRole::Carried`)
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/utxo/native.rs`

### Semantics
- [x] **INV-UTXO-06: every preimage field changes the commitment to the native commitment of the change**
  - Covered by: `tests/unit/protocol/utxo/native.rs` `every_preimage_field_change_moves_the_hash_to_the_native_commitment_of_the_change`
  - Kind: semantics
  - Statement: for the data UTXO in a ring and each change of exactly one of the domain, tree id, asset, owner, blinding, data hash, ring data hash, ring program id and amount, the circuit commitment is exactly `ProofInputUtxo::hash` of the equally changed fields and differs from the original's.
  - Location: `src/circuit/protocol/utxo/input.rs:73-91` (`fn hash_with`)
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/utxo/native.rs`

- [x] **INV-UTXO-07: every preimage holds natively with its native commitment**
  - Covered by: `tests/unit/protocol/utxo/native.rs` `every_preimage_holds_natively_with_its_native_commitment`; `tests/unit/protocol/utxo/properties.rs` `every_random_preimage_hashes_to_its_native_commitment_natively_and_in_r1cs` (property)
  - Kind: semantics
  - Statement: for every preimage and every random preimage, native `UtxoHash` with the native commitment returns exactly `Ok(())`.
  - Location: `src/circuit/protocol/utxo/input.rs:59-91`
  - Severity: High
  - Suggested test: positive + property; `tests/unit/protocol/utxo/native.rs`, `tests/unit/protocol/utxo/properties.rs`

- [x] **INV-UTXO-08: the latest tree id and its flag carry the wallet's value**
  - Covered by: `tests/unit/protocol/utxo/native.rs` `the_latest_tree_id_and_its_flag_carry_the_wallets_value`
  - Kind: semantics
  - Statement: for every preimage, native `Carried` with the wallet's nullifier, `latest_tree_id.unwrap_or(0)` and `latest_tree_id.is_some()` returns exactly `Ok(())`.
  - Location: `src/conversion/utxo.rs:89-95`
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/utxo/native.rs`

- [x] **INV-UTXO-09: the circuit dummy has the dummy domain and every other field zero or SOL**
  - Covered by: `tests/unit/protocol/utxo/native.rs` `the_circuit_dummy_has_the_dummy_domain_and_no_nullifier_key`
  - Kind: semantics
  - Statement: `Utxo::dummy()` has domain exactly `DUMMY_DOMAIN` = 1, asset hash exactly `hash_bytes([0; 32])`, and tag, nullifier key, blinding, data hash, ring data hash, ring program id, tree id, nullifier, latest tree id and flag exactly 0; `Utxo::default()` is the same with domain 0; `UTXO_DOMAIN` is 3.
  - Location: `src/circuit/protocol/utxo/input.rs:32-57` (`impl Default`, `fn dummy`)
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/utxo/native.rs`

- [x] **INV-UTXO-10: a dummy wallet UTXO instantiates with an all-zero owner preimage**
  - Covered by: `tests/unit/protocol/utxo/native.rs` `a_dummy_wallet_utxo_instantiates_with_an_all_zero_owner_preimage_and_skips_the_tag_check`
  - Kind: semantics
  - Statement: for the dummy wallet UTXO (zeroed owner), the instantiated domain is exactly `DUMMY_DOMAIN`, the tag and nullifier key exactly 0, the identity exactly `hash_bytes([0; 33])`, and the blinding and tree id exactly the wallet's; the zero tag is accepted natively.
  - Location: `src/conversion/utxo.rs:28-41` (the dummy branch), `src/conversion/owner.rs:42-61`
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/utxo/native.rs`

- [ ] **INV-UTXO-11: the hash of a dummy is the native dummy commitment**
  - Finding: `Utxo::hash` of a dummy (instantiated from `WalletUtxo::dummy` or built as `Utxo::dummy()` with the same blinding and tree id) is `Poseidon(1, tree, hash_bytes([0; 32]), 0, 0, Poseidon(0, 0), Poseidon(Poseidon(hash_bytes([0; 33]), 0), blinding))`, not the native dummy commitment `dummy_utxo_hash`, which hashes 0 for the asset and the owner hash. The SDK's own spends never use it: a `TokenUtxo` replaces a dummy input's hash with 0 (`src/circuit/protocol/utxo/token.rs:128-131`, as `../../spec.md` states: "a dummy hashes as 0") and a `DataUtxo` refuses a dummy domain; but the public method returns a value no native implementation produces. Reproduction: `tests/unit/protocol/utxo/native.rs` `the_hash_of_a_dummy_is_the_native_dummy_commitment` (`#[ignore = "FINDING: ..."]`).
  - Kind: native equivalence
  - Statement: for the dummy wallet UTXO, the native value of `Utxo::hash` is exactly the wallet's `utxo_hash` (`dummy_utxo_hash(blinding, tree_id)`).
  - Location: `src/circuit/protocol/utxo/input.rs:59-62` (`fn hash`), `src/conversion/utxo.rs:28-41`
  - Severity: Medium
  - Suggested test: positive; `tests/unit/protocol/utxo/native.rs`

### Error
- [x] **INV-UTXO-12: a claimed commitment of another preimage breaks exactly the hash rule natively**
  - Covered by: `tests/unit/protocol/utxo/native.rs` `a_claimed_commitment_of_another_preimage_breaks_exactly_the_hash_rule`; `tests/unit/protocol/utxo/properties.rs` `a_commitment_claimed_for_another_amount_is_refused_natively_and_in_r1cs` (property)
  - Kind: error
  - Statement: for every preimage with the next preimage's commitment, and for every random preimage with the commitment of another amount, native `UtxoHash` returns exactly `RuleBroken("the utxo hash is the native commitment")` located in `fixtures.rs`.
  - Location: `src/circuit/protocol/utxo/input.rs:59-91`
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: negative + property; `tests/unit/protocol/utxo/native.rs`, `tests/unit/protocol/utxo/properties.rs`

- [x] **INV-UTXO-13: a UTXO field of at least p is refused before it reaches the circuit**
  - Covered by: `tests/unit/protocol/utxo/native.rs` `a_utxo_field_of_at_least_p_is_refused_before_it_reaches_the_circuit`
  - Kind: error
  - Statement: a wallet UTXO whose blinding, data hash, ring data hash or nullifier is the big-endian bytes of p is refused by native instantiation with exactly `CircuitError.BytesTooLarge` and "utxo blinding" (respectively "utxo data hash", "utxo ring data hash", "utxo nullifier") "is too large for a circuit value", and by `check_constraints(UtxoHash)` with exactly `CircuitError.BytesTooLarge`; the native `utxo::Utxo::hash` refuses the first three with exactly "keypair error: poseidon hash failed (code 8002)" and does not read the nullifier.
  - Location: `src/conversion/utxo.rs:100-107` (`fn field`), `src/conversion/var.rs:13-20` (`fn field`)
  - Error: `CircuitErrorKind::BytesTooLarge`
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/utxo/native.rs`

- [x] **INV-UTXO-14: a carried value other than the wallet's breaks the carried rule natively**
  - Covered by: `tests/unit/protocol/utxo/native.rs` `the_latest_tree_id_and_its_flag_carry_the_wallets_value`
  - Kind: error
  - Statement: for every preimage, native `Carried` with the flag negated or the latest tree id plus 1 returns exactly `RuleBroken("the utxo carries the claimed spend values")`.
  - Location: `src/conversion/utxo.rs:83-95`
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/protocol/utxo/native.rs`

### Constraint
- [x] **INV-UTXO-15: the utxo fixtures have pinned sizes and digest and no public input**
  - Covered by: `tests/unit/protocol/utxo/r1cs.rs` `the_utxo_fixtures_have_pinned_sizes_digest_and_no_public_input`
  - Kind: constraint
  - Statement: the `UtxoHash` export has exactly 2163 constraints and 2174 variables with sha256 `f76c913eaaff70b612c7481df5c748fabf6c13703f2d96a922146a0fcb3c755a` and exactly 0 public inputs and 0 public outputs; `Carried` exactly 585 and 595; `Instantiated` exactly 581 and 592.
  - Location: `src/circuit/protocol/utxo/input.rs:59-91`, `src/conversion/utxo.rs:15-107`
  - Severity: Medium
  - Suggested test: positive; `tests/unit/protocol/utxo/r1cs.rs`

### Completeness
- [x] **INV-UTXO-16: every preimage and a dummy satisfy every row of the utxo hash fixture**
  - Covered by: `tests/unit/protocol/utxo/r1cs.rs` `every_preimage_and_a_dummy_satisfy_every_row_with_the_commitment_on_the_claim_wire`; `tests/unit/protocol/utxo/properties.rs` `every_random_preimage_hashes_to_its_native_commitment_natively_and_in_r1cs` (property)
  - Kind: completeness
  - Statement: for every preimage, every random preimage and the dummy (with the circuit's own dummy hash), the honest `UtxoHash` assignment leaves no exported row unsatisfied.
  - Location: `src/circuit/protocol/utxo/input.rs:59-91`
  - Severity: Critical
  - Suggested test: positive + property; `tests/unit/protocol/utxo/r1cs.rs`, `tests/unit/protocol/utxo/properties.rs`

### Soundness
- [x] **INV-UTXO-17: a claimed commitment of another preimage breaks exactly the hash row**
  - Covered by: `tests/unit/protocol/utxo/r1cs.rs` `a_claimed_commitment_of_another_preimage_breaks_exactly_the_hash_row`; `tests/unit/protocol/utxo/properties.rs` `a_commitment_claimed_for_another_amount_is_refused_natively_and_in_r1cs` (property)
  - Kind: soundness
  - Statement: for every preimage, wire 1 set to the next preimage's commitment leaves exactly row 2162 as the first unsatisfied row, and `check_tampered` returns exactly `ProofInputsBreakRule` at row 2162 with the hash rule; so does every random commitment of another amount in the export.
  - Location: `src/circuit/protocol/utxo/input.rs:59-91`
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/protocol/utxo/r1cs.rs`, `tests/unit/protocol/utxo/properties.rs`

- [x] **INV-UTXO-18: every changed preimage field with the original commitment breaks exactly the hash row**
  - Covered by: `tests/unit/protocol/utxo/r1cs.rs` `every_changed_preimage_field_with_the_original_commitment_breaks_exactly_the_hash_row`
  - Kind: soundness
  - Statement: for the data UTXO in a ring and each change of exactly one of the amount, blinding, data hash, ring data hash, ring program id, tree id, owner and asset, the changed preimage's commitment differs from the original's, and its honest assignment with wire 1 set to the original commitment leaves exactly row 2162 as the first unsatisfied row.
  - Location: `src/circuit/protocol/utxo/input.rs:73-91` (`fn hash_with`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/utxo/r1cs.rs`

- [x] **INV-UTXO-19: every preimage wire changed alone leaves a row unsatisfied**
  - Covered by: `tests/unit/protocol/utxo/r1cs.rs` `every_preimage_wire_changed_alone_leaves_a_row_unsatisfied`
  - Kind: soundness
  - Statement: in the data UTXO's `UtxoHash` assignment (64 byte variables), adding 1 to exactly one wire leaves exactly this first unsatisfied row: domain 0, owner tag 290, nullifier key 824, amount 1790, blinding 1544, data hash 1793, ring data hash 1301, ring program id 1304, tree id 1784, owner key byte 0 row 10, owner key byte 31 row 289, asset byte 0 row 300, asset byte 31 row 579.
  - Location: `src/conversion/utxo.rs:15-98`, `src/circuit/protocol/utxo/input.rs:73-91`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/utxo/r1cs.rs`

- [x] **INV-UTXO-20: only the carried nullifier and latest tree id are unconstrained**
  - Covered by: `tests/unit/protocol/utxo/r1cs.rs` `only_the_carried_nullifier_and_latest_tree_id_are_unconstrained`; `tests/unit/protocol/utxo/native.rs` `the_sdk_carries_a_nullifier_it_does_not_check`
  - Kind: soundness
  - Statement: `check_private_variables(UtxoHash)` reports exactly 2163 constraints, 2173 private variables, no free variable, and exactly the "utxo nullifier" and "utxo latest tree id" allocations tolerated as `VariableRole::Carried` (the SPP proof constrains them, `../../spec.md`); natively, a wallet carrying another preimage's nullifier still holds `UtxoHash` and `Carried`.
  - Location: `src/conversion/utxo.rs:83-95`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/utxo/r1cs.rs`, `tests/unit/protocol/utxo/native.rs`

- [x] **INV-UTXO-21: a claimed carried value other than the utxo's breaks the carried rule rows**
  - Covered by: `tests/unit/protocol/utxo/r1cs.rs` `a_claimed_nullifier_or_latest_tree_id_other_than_the_carried_one_breaks_the_carried_rule`
  - Kind: soundness
  - Statement: for the P256 token reporting latest tree 4, `check_constraints(Carried)` returns exactly `Ok(585)`; `check_tampered` of wire 1 (another nullifier), wire 2 (latest tree 5) and wire 3 (flag 0) returns exactly `ProofInputsBreakRule` with "the utxo carries the claimed spend values" at the rule's first, second and third row.
  - Location: `src/conversion/utxo.rs:83-95`
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/utxo/r1cs.rs`

- [x] **INV-UTXO-22: the owner tag check is skipped exactly for a dummy input**
  - Covered by: `tests/unit/protocol/utxo/r1cs.rs` `the_tag_check_is_skipped_exactly_for_a_dummy_input`; `tests/unit/protocol/utxo/native.rs` `a_dummy_wallet_utxo_instantiates_with_an_all_zero_owner_preimage_and_skips_the_tag_check`
  - Kind: soundness
  - Statement: in the `Instantiated` export (tag wire 4, product wire 293), for every tag in 0..=255 with a consistent product, a real input's assignment breaks exactly the tag rule row when the tag is neither S nor P and no row otherwise; a dummy's assignment (tag 0) breaks no row for every tag.
  - Location: `src/conversion/utxo.rs:28-41` (`dummy = domain == DUMMY_DOMAIN`), `src/circuit/protocol/owner.rs:28-46` (`assert_equal_unless`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/utxo/r1cs.rs`

- [ ] **INV-UTXO-23: Picus finds the commitment fixed by the preimage**
  - Partial coverage: `tests/unit/protocol/utxo/picus.rs` `picus_finds_no_second_utxo_commitment_for_one_preimage` runs Picus (cvc5) on the `UtxoHash` Picus export with the claim promoted, bounded at 60 s, and asserts only that it finds no counterexample: the run ends `Unknown` (the owner and asset byte range checks alone exceed the bound, see INV-OWNER-22), so determinism is not proven; INV-UTXO-19 and -20 are the hermetic substitutes.
  - Kind: soundness
  - Statement: Picus reports the `UtxoHash` Picus export with wire 1 promoted exactly `Safe`.
  - Location: `src/circuit/protocol/utxo/input.rs:59-91`
  - Severity: Medium
  - Suggested test: external (Picus); `tests/unit/protocol/utxo/picus.rs`

### Shape
- [x] **INV-UTXO-24: every preimage synthesizes the dummy placeholder's rows**
  - Covered by: `tests/unit/protocol/utxo/r1cs.rs` `every_preimage_instantiates_to_the_dummy_placeholders_shape`; `tests/unit/protocol/utxo/r1cs.rs` `every_preimage_and_a_dummy_satisfy_every_row_with_the_commitment_on_the_claim_wire`
  - Kind: shape
  - Statement: for every preimage, `check_constraints(Instantiated)` returns exactly `Ok(581)`, and for every preimage and the dummy `check_constraints(UtxoHash)` returns exactly `Ok(2163)`: setup from the `WalletUtxo::dummy(0)` placeholder and proving build the same matrices for tokens, data UTXOs, rings and every curve.
  - Location: `src/conversion/utxo.rs:109-113` (`impl Placeholder for WalletUtxo`)
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/utxo/r1cs.rs`

### Interop
- [x] **INV-UTXO-25: snarkjs accepts every honest commitment witness and rejects a wrong claim**
  - Covered by: `tests/unit/protocol/utxo/external.rs` `snarkjs_accepts_every_preimage_and_rejects_a_claimed_commitment_of_another`
  - Kind: interop
  - Statement: for every preimage, `snarkjs wtns check` on the `UtxoHash` export returns exactly `WITNESS IS CORRECT` for the honest assignment and `WITNESS IS NOT CORRECT` with wire 1 set to the next preimage's commitment.
  - Location: `src/circuit/protocol/utxo/input.rs:59-91`
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/protocol/utxo/external.rs`

- [x] **INV-UTXO-26: snarkjs proves and verifies the utxo hash circuit for a data UTXO in a ring**
  - Covered by: `tests/unit/protocol/utxo/external.rs` `snarkjs_proves_and_verifies_the_utxo_hash_circuit_for_a_data_utxo_in_a_ring`
  - Kind: interop
  - Statement: snarkjs Groth16 setup, prove and verify on the `UtxoHash` export and the data UTXO's assignment verifies with exactly the public signals `[]`.
  - Location: `src/circuit/protocol/utxo/input.rs:59-91`
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/protocol/utxo/external.rs`

INV-UTXO summary: 26 (Critical 10, High 12, Medium 4); covered 24, partial 1
(INV-UTXO-23, Picus `Unknown` within its bound), findings 1 (INV-UTXO-11).

## Balance (`transfer`, `transfer_all`, `deposit`, `withdraw`, `withdraw_all` on `TokenUtxo` and `DataUtxo`)

`INV-LEDGER`

## TokenUtxo (`new_init`, `new_mut`, `new_burn`, dummies, change)

`INV-TOKEN`

## DataUtxo (`DataUtxo`, `UtxoData`, `checked_utxo_data`)

`INV-DATA`
