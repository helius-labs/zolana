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
with blinding and data hash p - 1; dummy vectors use `SppProofInputUtxo::dummy_with_blinding`
with boundary and generated blindings/tree ids. `SpentInput` and `Utxo::spent` are crate-private and built only by the `TokenUtxo`
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
  - Statement: for the data UTXO in a ring and each change of exactly one of the domain, tree id, asset, owner, blinding, data hash, ring data hash, ring program id and amount, the circuit commitment is exactly `ProofInputUtxo::hash` of the equally changed fields and differs from the original's; changing the domain to dummy also selects zero owner/asset hashes while retaining the other fields.
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

- [x] **INV-UTXO-11: the hash of a dummy is the native dummy commitment**
  - Covered by: `tests/unit/protocol/utxo/native.rs` `the_hash_of_a_dummy_is_the_native_dummy_commitment`; `tests/unit/protocol/utxo/r1cs.rs` `dummy_commitments_bind_the_tree_and_blinding_and_reject_hashed_dummy_preimages`; `tests/unit/protocol/utxo/properties.rs` `every_random_dummy_has_its_native_commitment_and_rejects_the_unmasked_preimages` (property)
  - Kind: native equivalence
  - Statement: for every tested dummy wallet or constructed circuit dummy, including tree ids 0 and 65535, blindings 0, 1 and p-1, and generated canonical blindings/tree ids, `Utxo::hash` is exactly the native dummy commitment `Poseidon(1, tree, 0, 0, 0, Poseidon(0, 0), Poseidon(0, blinding))`. The former owner/asset-preimage commitment is rejected by the native claim rule and its exported/proving row.
  - Location: `src/circuit/protocol/utxo/input.rs:59-65` (`fn hash`), `src/conversion/utxo.rs:28-41`
  - Severity: Medium
  - Suggested test: positive + negative + property; `tests/unit/protocol/utxo/native.rs`, `tests/unit/protocol/utxo/r1cs.rs`, `tests/unit/protocol/utxo/properties.rs`

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
  - Statement: the `UtxoHash` export has exactly 2167 constraints and 2178 variables with sha256 `73266cfb46af8d8f6df5b458e37fe47823104d74d55f5719365733b9a2cf1dbe` and exactly 0 public inputs and 0 public outputs; `Carried` exactly 585 and 595; `Instantiated` exactly 581 and 592.
  - Location: `src/circuit/protocol/utxo/input.rs:59-91`, `src/conversion/utxo.rs:15-107`
  - Severity: Medium
  - Suggested test: positive; `tests/unit/protocol/utxo/r1cs.rs`

### Completeness
- [x] **INV-UTXO-16: every preimage and a dummy satisfy every row of the utxo hash fixture**
  - Covered by: `tests/unit/protocol/utxo/r1cs.rs` `every_preimage_and_a_dummy_satisfy_every_row_with_the_commitment_on_the_claim_wire`; `tests/unit/protocol/utxo/properties.rs` `every_random_preimage_hashes_to_its_native_commitment_natively_and_in_r1cs` (property)
  - Kind: completeness
  - Statement: for every preimage, every random preimage and the dummy (with its independently computed native wallet commitment), the honest `UtxoHash` assignment leaves no exported row unsatisfied.
  - Location: `src/circuit/protocol/utxo/input.rs:59-91`
  - Severity: Critical
  - Suggested test: positive + property; `tests/unit/protocol/utxo/r1cs.rs`, `tests/unit/protocol/utxo/properties.rs`

### Soundness
- [x] **INV-UTXO-17: a claimed commitment of another preimage breaks exactly the hash row**
  - Covered by: `tests/unit/protocol/utxo/r1cs.rs` `a_claimed_commitment_of_another_preimage_breaks_exactly_the_hash_row`; `tests/unit/protocol/utxo/properties.rs` `a_commitment_claimed_for_another_amount_is_refused_natively_and_in_r1cs` (property)
  - Kind: soundness
  - Statement: for every preimage, wire 1 set to the next preimage's commitment leaves exactly row 2166 as the first unsatisfied row, and `check_tampered` returns exactly `ProofInputsBreakRule` at row 2166 with the hash rule; so does every random commitment of another amount in the export.
  - Location: `src/circuit/protocol/utxo/input.rs:59-91`
  - Error: `ProverErrorKind::ProofInputsBreakRule`
  - Severity: Critical
  - Suggested test: negative + property; `tests/unit/protocol/utxo/r1cs.rs`, `tests/unit/protocol/utxo/properties.rs`

- [x] **INV-UTXO-18: every changed preimage field with the original commitment breaks exactly the hash row**
  - Covered by: `tests/unit/protocol/utxo/r1cs.rs` `every_changed_preimage_field_with_the_original_commitment_breaks_exactly_the_hash_row`
  - Kind: soundness
  - Statement: for the data UTXO in a ring and each change of exactly one of the amount, blinding, data hash, ring data hash, ring program id, tree id, owner and asset, the changed preimage's commitment differs from the original's, and its honest assignment with wire 1 set to the original commitment leaves exactly row 2166 as the first unsatisfied row.
  - Location: `src/circuit/protocol/utxo/input.rs:73-91` (`fn hash_with`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/utxo/r1cs.rs`

- [x] **INV-UTXO-19: every preimage wire changed alone leaves a row unsatisfied**
  - Covered by: `tests/unit/protocol/utxo/r1cs.rs` `every_preimage_wire_changed_alone_leaves_a_row_unsatisfied`
  - Kind: soundness
  - Statement: in the data UTXO's `UtxoHash` assignment (64 byte variables), adding 1 to exactly one wire leaves exactly this first unsatisfied row: domain 0, owner tag 290, nullifier key 826, amount 1794, blinding 1548, data hash 1797, ring data hash 1305, ring program id 1308, tree id 1788, owner key byte 0 row 10, owner key byte 31 row 289, asset byte 0 row 300, asset byte 31 row 579.
  - Location: `src/conversion/utxo.rs:15-98`, `src/circuit/protocol/utxo/input.rs:73-91`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/utxo/r1cs.rs`

- [x] **INV-UTXO-20: commitment witnesses have only documented carried fields and inverse hints unconstrained**
  - Covered by: `tests/unit/protocol/utxo/r1cs.rs` `only_the_carried_nullifier_and_latest_tree_id_are_unconstrained`; `tests/unit/protocol/utxo/r1cs.rs` `a_dummy_hash_has_no_free_wire_beyond_carried_fields_and_equality_inverse_hints`; `tests/unit/protocol/utxo/native.rs` `the_sdk_carries_a_nullifier_it_does_not_check`
  - Kind: soundness
  - Statement: `check_private_variables(UtxoHash)` reports exactly 2167 constraints, 2177 private variables, no free variable, and exactly the "utxo nullifier" and "utxo latest tree id" allocations tolerated as `VariableRole::Carried` (the SPP proof constrains them, `../../spec.md`); natively, a wallet carrying another preimage's nullifier still holds `UtxoHash` and `Carried`. For a dummy, the report likewise contains no free variable and additionally tolerates exactly the two equality inverse hints (the conversion domain check and the hash domain check).
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
  - Statement: for every preimage, `check_constraints(Instantiated)` returns exactly `Ok(581)`, and for every preimage and the dummy `check_constraints(UtxoHash)` returns exactly `Ok(2167)`: setup from the `WalletUtxo::dummy(0)` placeholder and proving build the same matrices for tokens, data UTXOs, rings and every curve.
  - Location: `src/conversion/utxo.rs:109-113` (`impl Placeholder for WalletUtxo`)
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/utxo/r1cs.rs`

### Interop
- [x] **INV-UTXO-25: snarkjs accepts every honest commitment witness and rejects a wrong claim**
  - Covered by: `tests/unit/protocol/utxo/external.rs` `snarkjs_accepts_every_preimage_and_rejects_a_claimed_commitment_of_another`; `tests/unit/protocol/utxo/external.rs` `snarkjs_proves_the_native_dummy_commitment_and_rejects_hashed_dummy_preimages`
  - Kind: interop
  - Statement: for every preimage, `snarkjs wtns check` on the `UtxoHash` export returns exactly `WITNESS IS CORRECT` for the honest assignment and `WITNESS IS NOT CORRECT` with wire 1 set to the next preimage's commitment; for the dummy it accepts the native commitment and rejects the owner/asset-preimage commitment.
  - Location: `src/circuit/protocol/utxo/input.rs:59-91`
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/protocol/utxo/external.rs`

- [x] **INV-UTXO-26: snarkjs proves and verifies the utxo hash circuit for a data UTXO in a ring**
  - Covered by: `tests/unit/protocol/utxo/external.rs` `snarkjs_proves_and_verifies_the_utxo_hash_circuit_for_a_data_utxo_in_a_ring`; `tests/unit/protocol/utxo/external.rs` `snarkjs_proves_the_native_dummy_commitment_and_rejects_hashed_dummy_preimages`
  - Kind: interop
  - Statement: snarkjs Groth16 setup, prove and verify on the `UtxoHash` export and either the data UTXO or native dummy assignment verifies with exactly the public signals `[]`.
  - Location: `src/circuit/protocol/utxo/input.rs:59-91`
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/protocol/utxo/external.rs`

INV-UTXO summary: 26 (Critical 10, High 12, Medium 4); covered 25, partial 1
(INV-UTXO-23, Picus `Unknown` within its bound), findings 0.

## Balance (`transfer`, `transfer_all`, `deposit`, `withdraw`, `withdraw_all` on `TokenUtxo` and `DataUtxo`)

Covers the `Balance` trait and its `Ledger` of `src/circuit/protocol/utxo/ledger.rs`, shared
by `TokenUtxo` and `DataUtxo`: a balance accumulator that tracks its bit width, the
destination checks, and the 64-bit bounds. The fixtures in
`tests/unit/protocol/ledger/fixtures.rs` are:

- `Ledger<SOURCE, DESTINATION, OP, OWN_ASSET>`: a new source holder (a `TokenUtxo` or a
  `DataUtxo<CounterState>`) takes one deposit, then runs `OP` (`transfer`, `transfer_all`,
  `withdraw` or `withdraw_all`) against a new destination holder built with the source's
  `asset()` or with another mint. Both final balances are asserted equal to the native ones
  with "the balances are the native balances", and `withdraw_all`'s result with
  "withdraw_all returns the native balance".
- `Deposits<K, ALL>`: K deposits into one holder, then `balance()` (or `withdraw_all`).
- `Accessors<KIND>`: `owner()` and `asset()` hashed against the native owner hash and
  `hash_bytes(mint)`.
- `Empty<OP>`: a withdrawal from a holder without a deposit.
- `IntoBurned<DESTINATION, ALL>`: a transfer into a `TokenUtxo::new_burn` or
  `DataUtxo::new_burn` of a constant input.
- `Arithmetic`: the ledger alone over a constant owner, asset and account.

The vectors (`vectors.rs`) move 4 of 10, 0 of 1, all 7 and all 2^64 - 1; withdraw 3 of 10,
all 5 and 1 of 2^64 - 1; exceed with 11 of 10, 2^64 - 1 of 1 and 2^64 - 1 of 2^64 - 2; and
deposit or withdraw 0.

### Semantics

- [x] **INV-LEDGER-01: a transfer leaves exactly the native balances for every holder pair**
  - Covered by: `tests/unit/protocol/ledger/native.rs` `every_transfer_leaves_exactly_the_native_balances_for_every_holder_pair`; `tests/unit/protocol/ledger/properties.rs` `natively_a_transfer_holds_exactly_when_it_fits_the_balance` (property)
  - Kind: semantics
  - Statement: for every transfer vector and each of the four token/data source and destination pairs, the native run returns exactly `Ok(())` with the balances deposit - amount and amount, and exactly `RuleBroken` with "the balances are the native balances" when the source balance claim is off by one; for every random deposit and amount, it holds exactly when the amount is at most the deposit.
  - Location: `src/circuit/protocol/utxo/ledger.rs:184-201` (`fn transfer`), `src/circuit/protocol/utxo/ledger.rs:81-96` (`fn debit`)
  - Severity: Critical
  - Suggested test: positive + negative + property; `tests/unit/protocol/ledger/native.rs`, `tests/unit/protocol/ledger/properties.rs`

- [x] **INV-LEDGER-02: transfer_all moves exactly the whole balance**
  - Covered by: `tests/unit/protocol/ledger/native.rs` `transfer_all_moves_exactly_the_whole_balance_for_every_holder_pair`
  - Kind: semantics
  - Statement: for the deposits 10 and 2^64 - 1 and each of the four holder pairs, `transfer_all` leaves exactly 0 in the source and the whole deposit in the destination, and an off-by-one source claim breaks exactly the balances rule.
  - Location: `src/circuit/protocol/utxo/ledger.rs:203-215` (`fn transfer_all`)
  - Severity: Critical
  - Suggested test: positive + negative; `tests/unit/protocol/ledger/native.rs`

- [x] **INV-LEDGER-03: a withdrawal leaves exactly the deposit minus the amount**
  - Covered by: `tests/unit/protocol/ledger/native.rs` `a_withdrawal_leaves_exactly_the_deposit_minus_the_amount_for_every_source`; `tests/unit/protocol/ledger/properties.rs` `natively_a_withdrawal_holds_exactly_when_it_fits_the_balance` (property)
  - Kind: semantics
  - Statement: for every withdrawal vector and both source kinds, the native run leaves exactly deposit - amount in the source and nothing in the destination, and an off-by-one claim breaks exactly the balances rule; for every random deposit and nonzero amount, it holds exactly when the amount is at most the deposit.
  - Location: `src/circuit/protocol/utxo/ledger.rs:226-236` (`fn withdraw`)
  - Severity: Critical
  - Suggested test: positive + negative + property; `tests/unit/protocol/ledger/native.rs`, `tests/unit/protocol/ledger/properties.rs`

- [x] **INV-LEDGER-04: withdraw_all returns exactly the balance and leaves zero**
  - Covered by: `tests/unit/protocol/ledger/native.rs` `withdraw_all_returns_exactly_the_balance_and_leaves_zero_for_every_source`
  - Kind: semantics
  - Statement: for the deposits 10 and 2^64 - 1 and both source kinds, `withdraw_all` returns exactly the deposit and leaves 0; a claimed result one below the deposit breaks exactly "withdraw_all returns the native balance".
  - Location: `src/circuit/protocol/utxo/ledger.rs:238-246` (`fn withdraw_all`)
  - Severity: Critical
  - Suggested test: positive + negative; `tests/unit/protocol/ledger/native.rs`

- [x] **INV-LEDGER-05: deposits add exactly their amounts**
  - Covered by: `tests/unit/protocol/ledger/native.rs` `deposits_add_exactly_their_amounts`
  - Kind: semantics
  - Statement: the balance after deposits [3], [3, 4] and [2^64 - 2, 1] is exactly 3, 7 and 2^64 - 1, withdraw_all after [2^64 - 1] returns exactly 2^64 - 1, and the claim 8 after [3, 4] breaks exactly the balances rule.
  - Location: `src/circuit/protocol/utxo/ledger.rs:217-224` (`fn deposit`)
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/protocol/ledger/native.rs`

- [x] **INV-LEDGER-06: owner() and asset() are the holder's native owner and mint**
  - Covered by: `tests/unit/protocol/ledger/native.rs` `owner_and_asset_hash_to_the_native_owner_hash_and_hash_bytes_of_the_mint`
  - Kind: native equivalence
  - Statement: for a token and a data holder over SOL and USDC, `owner().hash()` is exactly the native `owner_hash` and `asset().hash()` exactly `hash_bytes(mint)`; another owner's hash breaks exactly "the owner hash is the native one".
  - Location: `src/circuit/protocol/utxo/ledger.rs:170-177` (`fn owner`, `fn asset`)
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/protocol/ledger/native.rs`

### Constraint

- [x] **INV-LEDGER-07: every ledger fixture has exactly its pinned size and digest**
  - Covered by: `tests/unit/protocol/ledger/r1cs.rs` `every_ledger_fixture_has_exactly_the_pinned_size_and_digest`
  - Kind: constraint
  - Statement: the token-to-token fixtures have exactly 1642 (transfer), 1644 (transfer into another held asset), 1577 (transfer_all), 1643 (withdraw) and 1579 (withdraw_all) constraints, with the variable counts and R1CS sha256 digests pinned in the test.
  - Location: `src/circuit/protocol/utxo/ledger.rs`
  - Severity: High
  - Suggested test: positive (digest); `tests/unit/protocol/ledger/r1cs.rs`

- [x] **INV-LEDGER-08: token and data holders export byte-identical rows**
  - Covered by: `tests/unit/protocol/ledger/r1cs.rs` `token_and_data_holders_export_byte_identical_r1cs_for_every_operation`
  - Kind: constraint
  - Statement: for every operation, the R1CS exported for each token/data holder pair is exactly the token-to-token R1CS, and `Accessors<DATA>` exports exactly `Accessors<TOKEN>`'s: `Balance` runs the same ledger for both.
  - Location: `src/circuit/protocol/utxo/ledger.rs:162-247` (`trait HasLedger`, `trait Balance`)
  - Severity: Medium
  - Suggested test: positive; `tests/unit/protocol/ledger/r1cs.rs`

- [x] **INV-LEDGER-09: each rule owns exactly its rows**
  - Covered by: `tests/unit/protocol/ledger/r1cs.rs` `each_rule_owns_exactly_its_pinned_rows`; `tests/unit/protocol/ledger/r1cs.rs` `a_destination_built_from_the_source_asset_adds_no_asset_row_and_another_adds_exactly_two`
  - Kind: constraint
  - Statement: the nonzero rule owns one row per public transfer, a debit's exceeds rule exactly 65 rows (a 64-bit range check of the remainder) and `transfer_all` none; a destination built from the source's `asset()` adds no asset row, and one built from another mint exactly two.
  - Location: `src/circuit/protocol/utxo/ledger.rs:81-96` (`fn debit`), `src/circuit/protocol/utxo/ledger.rs:150-160` (`fn check_destination`)
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/ledger/r1cs.rs`

- [x] **INV-LEDGER-10: a balance within 64 bits needs no range check, and one beyond it exactly one**
  - Covered by: `tests/unit/protocol/ledger/r1cs.rs` `balance_is_free_within_64_bits_and_one_range_check_beyond`
  - Kind: constraint
  - Statement: after one deposit `balance()` adds no "the balance does not fit in 64 bits" row; after two deposits it adds exactly 65, and the second deposit costs exactly 1 + 65 + 65 constraints.
  - Location: `src/circuit/protocol/utxo/ledger.rs:72-79` (`fn narrow`)
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/ledger/r1cs.rs`

### Completeness

- [x] **INV-LEDGER-11: every valid vector checks exactly the pinned count for every holder**
  - Covered by: `tests/unit/protocol/ledger/r1cs.rs` `every_valid_vector_checks_exactly_the_pinned_count_for_every_holder`; `tests/unit/protocol/ledger/properties.rs` `every_fitting_transfer_checks_exactly_the_pinned_count` (property)
  - Kind: completeness
  - Statement: `check_constraints` returns exactly `Ok(1642)`, `Ok(1577)`, `Ok(1643)` and `Ok(1579)` for every transfer, transfer_all, withdrawal and withdraw_all vector and every holder pair, and `Ok(1642)` for every random fitting transfer.
  - Location: `src/prover/synthesis.rs` (`fn check`)
  - Severity: High
  - Suggested test: positive + property; `tests/unit/protocol/ledger/r1cs.rs`, `tests/unit/protocol/ledger/properties.rs`

### Soundness

- [x] **INV-LEDGER-12: a tampered witness breaks the rule that owns its row**
  - Covered by: `tests/unit/protocol/ledger/r1cs.rs` `a_tampered_witness_breaks_the_rule_that_owns_its_row`
  - Kind: soundness
  - Statement: tampering the first witness of the nonzero rule, of the transfer's and the withdrawal's exceeds rules and of the 64-bit balance check breaks exactly that rule inside its own rows, and tampering either balance claim breaks exactly the balances rule.
  - Location: `src/circuit/protocol/utxo/ledger.rs:81-96`, `src/circuit/protocol/utxo/ledger.rs:217-246`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/ledger/r1cs.rs`

- [x] **INV-LEDGER-13: a destination holding another asset breaks the asset rows**
  - Covered by: `tests/unit/protocol/ledger/r1cs.rs` `a_witness_whose_destination_holds_another_asset_breaks_the_asset_rows`; `tests/unit/protocol/ledger/native.rs` `a_destination_holding_another_asset_breaks_exactly_that_rule`
  - Kind: soundness
  - Statement: natively a transfer or transfer_all into a destination holding USDC breaks exactly "the destination holds another asset" for every holder kind; in R1CS the honest SOL assignment satisfies the other-asset export and the USDC assignment leaves exactly row 1575, the first asset row, unsatisfied.
  - Location: `src/circuit/protocol/utxo/ledger.rs:150-160` (`fn check_destination`)
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/ledger/r1cs.rs`, `tests/unit/protocol/ledger/native.rs`

- [x] **INV-LEDGER-14: the balance rows read no owner, so only the fixture's unused nullifier keys are free**
  - Covered by: `tests/unit/protocol/ledger/r1cs.rs` `balance_reads_no_owner_so_only_the_nullifier_keys_are_free`
  - Kind: soundness
  - Statement: `check_private_variables` reports exactly the owner addresses' unused nullifier keys ("a 32-byte proof input" allocations) free and nothing tolerated: two for a transfer and a withdraw_all, one for two deposits, and none for the accessors, which hash the owner.
  - Location: `src/testing.rs` (`fn check_private_variables`)
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/ledger/r1cs.rs`

- [ ] **INV-LEDGER-15: Picus proves the ledger arithmetic deterministic and both balances fixed**
  - Partial coverage: `tests/unit/protocol/ledger/picus.rs` `picus_finds_no_counterexample_for_the_ledger_arithmetic_within_its_limit` runs Picus on the constant-owner `Arithmetic` Picus export, alone and with both balance claims promoted, bounded at 30 s, and asserts only that it finds no counterexample: both runs end `Unknown`, as they do at 120 s, because Picus does not settle the 64-bit range checks of the deposit and the remainder (the bits fixtures prove widths up to 5, INV-CV-BITS-23). INV-LEDGER-12 and -14 are the hermetic substitutes.
  - Kind: soundness
  - Statement: Picus reports exactly Safe for the `Arithmetic` Picus export, and exactly Safe with both balance claims promoted to outputs.
  - Location: `src/circuit/protocol/utxo/ledger.rs:81-96`, `src/prover/snarkjs.rs` (`fn picus_r1cs`)
  - Severity: Critical
  - Suggested test: external (Picus); `tests/unit/protocol/ledger/picus.rs`

- [ ] **INV-LEDGER-16: Picus proves a whole transfer's balances fixed**
  - Partial coverage: `tests/unit/protocol/ledger/picus.rs` `picus_finds_no_counterexample_for_a_whole_transfer_within_its_limit` runs Picus on the token-to-token transfer with both balances promoted, bounded at 30 s, and asserts only that it finds no counterexample: the run ends `Unknown` (the owner and asset byte checks and the 64-bit range checks exceed the bound).
  - Kind: soundness
  - Statement: Picus reports exactly Safe for the transfer's Picus export with both balances promoted.
  - Location: `src/circuit/protocol/utxo/ledger.rs`
  - Severity: Medium
  - Suggested test: external (Picus); `tests/unit/protocol/ledger/picus.rs`

### Error

- [x] **INV-LEDGER-17: a debit beyond the balance breaks exactly its rule**
  - Covered by: `tests/unit/protocol/ledger/native.rs` `a_debit_beyond_the_balance_breaks_exactly_its_rule`; `tests/unit/protocol/ledger/properties.rs` `natively_every_other_source_balance_breaks_the_balance_rule` (property)
  - Kind: error
  - Statement: for every exceeding vector, a transfer returns exactly `RuleBroken` with "the transfer exceeds the balance" for every holder pair and a withdrawal exactly `RuleBroken` with "the withdrawal exceeds the balance" for both sources, located in the fixture's file: the 64-bit range check's `ValueTooLarge` is reported as the rule.
  - Location: `src/circuit/protocol/utxo/ledger.rs:81-96` (`fn debit`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: negative + property; `tests/unit/protocol/ledger/native.rs`, `tests/unit/protocol/ledger/properties.rs`

- [x] **INV-LEDGER-18: a public transfer of zero breaks the nonzero rule**
  - Covered by: `tests/unit/protocol/ledger/native.rs` `a_public_transfer_of_zero_breaks_the_nonzero_rule`
  - Kind: error
  - Statement: a deposit of 0 before a transfer (every holder pair), a withdrawal of 0 (both sources) and a withdraw_all of an empty holder each return exactly `RuleBroken` with "a public transfer moves a nonzero amount", located in the fixture's file.
  - Location: `src/circuit/protocol/utxo/ledger.rs:217-246`
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/ledger/native.rs`

- [x] **INV-LEDGER-19: a balance of at least 2^64 does not fit**
  - Covered by: `tests/unit/protocol/ledger/native.rs` `a_balance_of_at_least_2_pow_64_does_not_fit`
  - Kind: error
  - Statement: after the deposits [2^64 - 1, 1] and [2^64 - 1, 2^64 - 1], `balance()` and `withdraw_all` each return exactly `RuleBroken` with "the balance does not fit in 64 bits", located in the fixture's file.
  - Location: `src/circuit/protocol/utxo/ledger.rs:72-79` (`fn narrow`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/ledger/native.rs`

- [x] **INV-LEDGER-20: a transfer into a burned UTXO is a structural error before any row**
  - Covered by: `tests/unit/protocol/ledger/native.rs` `a_transfer_into_a_burned_utxo_is_a_structural_error`; `tests/unit/protocol/ledger/r1cs.rs` `a_transfer_into_a_burned_utxo_is_refused_before_any_row`
  - Kind: error
  - Statement: a transfer or transfer_all into a burned `TokenUtxo` or `DataUtxo` returns exactly `CircuitError.TransferToBurnedUtxo`, with no rule, natively, from `export_r1cs` and from `check_constraints`.
  - Location: `src/circuit/protocol/utxo/ledger.rs:150-154` (`fn check_destination`)
  - Error: `CircuitErrorKind::TransferToBurnedUtxo`
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/ledger/native.rs`, `tests/unit/protocol/ledger/r1cs.rs`

- [x] **INV-LEDGER-21: a balance summed over more than 253 bits is too wide to check**
  - Covered by: `tests/unit/protocol/ledger/native.rs` `a_balance_summed_over_more_than_253_bits_is_too_wide_to_check`; `tests/unit/protocol/ledger/r1cs.rs` `a_balance_too_wide_to_check_is_refused_before_any_row`
  - Kind: error
  - Statement: 190 deposits of 1 hold natively and check exactly 13472 constraints; 191 deposits make `balance()` and `withdraw_all` return exactly `CircuitError.BitWidthTooLarge` natively and from `export_r1cs`.
  - Location: `src/circuit/protocol/utxo/ledger.rs:62-70` (`fn bounded`)
  - Error: `CircuitErrorKind::BitWidthTooLarge`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/protocol/ledger/native.rs`, `tests/unit/protocol/ledger/r1cs.rs`

- [x] **INV-LEDGER-22: a balance too wide to check is refused at the circuit's line**
  - Covered by: `tests/unit/protocol/ledger/native.rs` `a_balance_too_wide_to_check_points_at_the_circuit_line`; `tests/unit/protocol/ledger/r1cs.rs` `oversized_accumulator_errors_keep_the_operation_location_through_the_prover`
  - Kind: error
  - Statement: after 191 deposits of 1, every tested `balance`, `withdraw_all`, `withdraw` and `transfer` operation returns exactly `CircuitError.BitWidthTooLarge { bits: 254 }` at the file and line of that operation's circuit call, natively and through R1CS export, assignment export and `check_constraints`.
  - Location: `src/circuit/protocol/utxo/ledger.rs:63-71` (`fn bounded`)
  - Error: `CircuitErrorKind::BitWidthTooLarge`
  - Severity: Low
  - Suggested test: negative; `tests/unit/protocol/ledger/native.rs`, `tests/unit/protocol/ledger/r1cs.rs`

### Interop

- [x] **INV-LEDGER-23: snarkjs accepts every honest transfer and rejects a tampered balance**
  - Covered by: `tests/unit/protocol/ledger/external.rs` `snarkjs_accepts_every_honest_ledger_pair_and_rejects_a_tampered_balance`
  - Kind: interop
  - Statement: for every transfer vector, `snarkjs wtns check` accepts the token-to-token transfer R1CS with the honest assignment and rejects it with the source balance claim increased by 1.
  - Location: `src/prover/snarkjs.rs` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/protocol/ledger/external.rs`

- [x] **INV-LEDGER-24: snarkjs proves and verifies a withdrawal**
  - Covered by: `tests/unit/protocol/ledger/external.rs` `snarkjs_proves_and_verifies_a_withdrawal`
  - Kind: interop
  - Statement: snarkjs Groth16 setup, prove and verify accept the withdrawal R1CS with the assignment of 1 withdrawn from 2^64 - 1, with exactly the empty public signal list.
  - Location: `src/prover/snarkjs.rs` (`fn r1cs`, `fn wtns`)
  - Severity: High
  - Suggested test: external (snarkjs); `tests/unit/protocol/ledger/external.rs`

INV-LEDGER summary: 24 (Critical 7, High 13, Medium 3, Low 1); covered 22, partial 2
(INV-LEDGER-15 and -16, Picus `Unknown` within its bound), findings 0.

## TokenUtxo (`new_init`, `new_mut`, `new_burn`, dummies, change)

Covers `TokenUtxo` of `src/circuit/protocol/utxo/token.rs`, spent from `WalletUtxo` inputs
built by `tests/unit/protocol/transaction/wallets.rs`. `Spend<N, LAST>` in
`tests/unit/protocol/token/fixtures.rs` runs `TokenUtxo::new_mut` over N inputs and asserts:

- the balance, with "the balance is the real inputs' native total"
- the owner hash, with "the owner is the first input's native owner"
- the asset hash, with "the asset is the first input's native asset"

`LAST` rewires the last instantiated input before the spend: `UNSPENDABLE` sets its domain to
7, and `KEYED` gives it the first input's owner with its nullifier key. The vectors
(`vectors.rs`) are:

- one input: 300 SOL, 2^64 - 1 USDC, and 0 SOL
- two inputs: 300 + 200 SOL, and 2^64 - 1 USDC with a dummy
- three inputs: 7 SOL with two dummies, and 1 + 2 USDC with a dummy

The change output, `new_burn` and `new_init` in a transaction are covered with the transaction
(`INV-TX`).

### Semantics

- [x] **INV-TOKEN-01: a spend holds exactly the real inputs' total under the first input's owner and asset**
  - Covered by: `tests/unit/protocol/token/native.rs` `every_spend_holds_exactly_the_real_inputs_total_under_the_first_inputs_owner_and_asset`; `tests/unit/protocol/token/properties.rs` `natively_a_spend_holds_the_real_total_exactly_when_it_fits_64_bits` (property)
  - Kind: native equivalence
  - Statement: for every one-, two- and three-input vector, the native run returns exactly `Ok(())`: the balance is the sum of the non-dummy amounts, and the owner and asset hashes are the first input's native `owner_hash` and `hash_bytes(mint)`; for every random pair of USDC amounts it holds exactly when their sum fits in 64 bits, and every random SOL amount with two dummies holds.
  - Location: `src/circuit/protocol/utxo/token.rs:85-142` (`fn spend`)
  - Severity: Critical
  - Suggested test: positive + property; `tests/unit/protocol/token/native.rs`, `tests/unit/protocol/token/properties.rs`

- [x] **INV-TOKEN-02: a wrong total, owner or asset breaks exactly its rule**
  - Covered by: `tests/unit/protocol/token/native.rs` `a_wrong_total_owner_or_asset_breaks_exactly_its_rule`
  - Kind: semantics
  - Statement: for 300 + 200 SOL, the balance, owner hash or asset hash claim increased by 1 breaks exactly its rule natively, located in the fixture's file.
  - Location: `src/circuit/protocol/utxo/ledger.rs:170-182` (`fn owner`, `fn asset`, `fn balance`)
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/token/native.rs`

### Constraint

- [x] **INV-TOKEN-03: every spend width has exactly its pinned size and digest**
  - Covered by: `tests/unit/protocol/token/r1cs.rs` `every_spend_width_has_exactly_the_pinned_size_and_digest`
  - Kind: constraint
  - Statement: `Spend<1>`, `Spend<2>` and `Spend<3>` have exactly 2173, 3694 and 5150 constraints over 2180, 3700 and 5156 variables, with the R1CS sha256 digests pinned in the test.
  - Location: `src/circuit/protocol/utxo/token.rs:85-142` (`fn spend`)
  - Severity: High
  - Suggested test: positive (digest); `tests/unit/protocol/token/r1cs.rs`

- [x] **INV-TOKEN-04: every input rule is enforced in R1CS for every input it applies to**
  - Covered by: `tests/unit/protocol/token/r1cs.rs` `every_input_rule_owns_rows_for_every_input_it_applies_to`
  - Kind: constraint
  - Statement: in `Spend<2>`, the first-input dummy rule owns exactly one row; the ring rule owns two rows per input and the program state rule one per input; the spendable, dummy-key rules own one row, the asset rule two and the owner rule three for the second input alone; `Spend<3>` doubles the per-later-input counts.
  - Location: `src/circuit/protocol/utxo/token.rs:85-142` (`fn spend`)
  - Severity: Critical
  - Suggested test: positive; `tests/unit/protocol/token/r1cs.rs`

### Completeness

- [x] **INV-TOKEN-05: every honest spend checks exactly the pinned count**
  - Covered by: `tests/unit/protocol/token/r1cs.rs` `every_honest_spend_checks_exactly_the_pinned_count`
  - Kind: completeness
  - Statement: `check_constraints` returns exactly `Ok(2173)`, `Ok(3694)` and `Ok(5150)` for every one-, two- and three-input vector, dummies included.
  - Location: `src/prover/synthesis.rs` (`fn check`)
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/token/r1cs.rs`

### Soundness

- [x] **INV-TOKEN-06: a tampered claim breaks exactly its rule**
  - Covered by: `tests/unit/protocol/token/r1cs.rs` `a_tampered_claim_breaks_exactly_its_rule`
  - Kind: soundness
  - Statement: for 300 + 200 SOL, tampering the balance, owner hash and asset hash claims breaks exactly their own rules inside their own rows.
  - Location: `src/circuit/protocol/utxo/token.rs:85-142`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/token/r1cs.rs`

- [x] **INV-TOKEN-07: an input's amount and blinding are bound by its hash, and a dummy's amount by its select**
  - Covered by: `tests/unit/protocol/token/r1cs.rs` `a_tampered_amount_or_blinding_breaks_the_input_hash_and_a_dummys_amount_its_select`
  - Kind: soundness
  - Statement: tampering either real input's amount or blinding breaks a row of "a poseidon hash", the input's commitment, and tampering a dummy's amount breaks a row of "a token utxo's inputs", the select that zeroes it.
  - Location: `src/circuit/protocol/utxo/token.rs:101-131`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/token/r1cs.rs`

- [x] **INV-TOKEN-08: only the carried spend values are tolerated, and nothing is free**
  - Covered by: `tests/unit/protocol/token/r1cs.rs` `the_carried_nullifiers_are_tolerated_and_no_other_variable_is_free`
  - Kind: soundness
  - Statement: tampering a nullifier leaves every row satisfied (it is carried to `check`, INV-TX-09), `check_private_variables` reports no free variable and exactly 4 tolerated ones for 300 + 200 SOL and 6 with a dummy, and the balance of two inputs owns exactly one 64-bit check.
  - Location: `src/circuit/protocol/utxo/input.rs:64-71` (`fn spent`), `src/conversion/utxo.rs` (the carried allocations)
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/token/r1cs.rs`

### Error

- [x] **INV-TOKEN-09: every malformed input set breaks exactly its rule**
  - Covered by: `tests/unit/protocol/token/native.rs` `every_malformed_input_set_breaks_exactly_its_rule`
  - Kind: error
  - Statement: natively, located in the fixture's file, each of these returns exactly `RuleBroken` with its rule: no input ("a token utxo spends at least one input"), a dummy first ("the first input of a token utxo is a dummy"), a first or later input in a ring ("the utxo is in a ring"), a first or later input with program state ("the input carries program state"), a later input with domain 7 ("the utxo is not a spendable utxo"), SOL then USDC ("the inputs hold different assets"), the sender then a stranger ("the inputs belong to different owners"), and a dummy carrying the first input's owner ("a dummy input carries a nullifier key").
  - Location: `src/circuit/protocol/utxo/token.rs:85-142` (`fn spend`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/token/native.rs`

- [x] **INV-TOKEN-10: two inputs of 2^64 - 1 do not fit the balance**
  - Covered by: `tests/unit/protocol/token/native.rs` `two_inputs_of_2_pow_64_minus_1_do_not_fit_the_balance`
  - Kind: error
  - Statement: the spend of 2^64 - 1 + 2^64 - 1 USDC returns exactly `RuleBroken` with "the balance does not fit in 64 bits" from `balance()`, located in the fixture's file.
  - Location: `src/circuit/protocol/utxo/ledger.rs:72-79` (`fn narrow`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/token/native.rs`

INV-TOKEN summary: 10 (Critical 5, High 5); covered 10.

## DataUtxo (`DataUtxo`, `UtxoData`, `checked_utxo_data`)

Covers `DataUtxo`, `UtxoData` and `checked_utxo_data` of `src/circuit/protocol/utxo/data.rs`,
with the `Counter` state of `tests/unit/protocol/data/state.rs`, whose client and circuit
hashes agree, and `Skewed`, whose do not. The fixtures in `tests/unit/protocol/data/fixtures.rs`
are:

- `Held<BURN>`: `DataUtxo::new_mut` (or `new_burn`) of a counter input and its state; asserts
  the count, balance, owner hash and asset hash against the native values.
- `Fresh`: `DataUtxo::<CounterState>::new_init` of an owner and mint.
- `Encoded`: `checked_utxo_data` of a proof-input state.
- `Burned<ALL>`: a burned counter in a transaction, withdrawn whole when `ALL`.

The vectors (`vectors.rs`) hold counters at 5 with 300 SOL, at 2^64 - 1 with 2^64 - 1 USDC,
and at 0 with nothing.

### Semantics

- [x] **INV-DATA-01: a held counter keeps its native count, balance, owner and asset**
  - Covered by: `tests/unit/protocol/data/native.rs` `every_held_counter_keeps_its_native_count_balance_owner_and_asset`
  - Kind: native equivalence
  - Statement: for every held vector, both `new_mut` and `new_burn` hold natively: the dereferenced count is the state's, the balance the input's amount, and the owner and asset hashes the input's native `owner_hash` and `hash_bytes(mint)`.
  - Location: `src/circuit/protocol/utxo/data.rs:118-150` (`fn new_mut`, `fn new_burn`, `fn spend`), `src/circuit/protocol/utxo/data.rs:185-197` (`Deref`)
  - Severity: Critical
  - Suggested test: positive; `tests/unit/protocol/data/native.rs`

- [x] **INV-DATA-02: a wrong count, balance, owner or asset breaks exactly its rule**
  - Covered by: `tests/unit/protocol/data/native.rs` `a_wrong_count_balance_owner_or_asset_breaks_exactly_its_rule`
  - Kind: semantics
  - Statement: for the counter at 5, each claim increased by 1 breaks exactly its own rule natively, located in the fixture's file.
  - Location: `src/circuit/protocol/utxo/data.rs:129-150` (`fn spend`)
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/data/native.rs`

- [x] **INV-DATA-03: a new counter starts at zero under its owner and asset**
  - Covered by: `tests/unit/protocol/data/native.rs` `a_new_counter_starts_at_zero_under_its_owner_and_asset`
  - Kind: semantics
  - Statement: `new_init` over the sender with SOL and the recipient with USDC holds a count and balance of exactly 0 and the native owner and asset hashes; the recipient's address against the sender's claimed hash breaks exactly the owner rule.
  - Location: `src/circuit/protocol/utxo/data.rs:106-116` (`fn new_init`)
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/protocol/data/native.rs`

- [x] **INV-DATA-04: checked_utxo_data is the borsh encoding when both hashes agree**
  - Covered by: `tests/unit/protocol/data/native.rs` `checked_utxo_data_is_the_borsh_encoding_when_both_hashes_agree`
  - Kind: native equivalence
  - Statement: for constant counters at 5 and 2^64 - 1, `checked_utxo_data` returns exactly the borsh bytes of the client state, as `utxo_data` does; for `Skewed`, whose client hash differs, `utxo_data` still returns its borsh bytes and `checked_utxo_data` returns exactly `CircuitError.DataHashMismatch`.
  - Location: `src/circuit/protocol/utxo/data.rs:20-39` (`trait UtxoData`, `fn checked_utxo_data`)
  - Error: `CircuitErrorKind::DataHashMismatch`
  - Severity: High
  - Suggested test: positive + negative; `tests/unit/protocol/data/native.rs`

- [x] **INV-DATA-05: checked_utxo_data runs natively only**
  - Covered by: `tests/unit/protocol/data/native.rs` `checked_utxo_data_runs_natively_only`
  - Kind: error
  - Statement: `Encoded` holds natively, and its `export_r1cs` returns exactly `CircuitError.ReadsVariableValue`: the encoding reads the state's values.
  - Location: `src/circuit/protocol/utxo/data.rs:29-39` (`fn checked_utxo_data`)
  - Error: `CircuitErrorKind::ReadsVariableValue`
  - Severity: Medium
  - Suggested test: negative; `tests/unit/protocol/data/native.rs`

### Constraint

- [x] **INV-DATA-06: every data fixture has exactly its pinned size and digest, and a burn spends like a mut**
  - Covered by: `tests/unit/protocol/data/r1cs.rs` `every_data_fixture_has_exactly_the_pinned_size_and_digest_and_a_burn_spends_like_a_mut`
  - Kind: constraint
  - Statement: `Held<false>` and `Held<true>` export exactly the same R1CS of 2448 constraints, `Fresh` has exactly 1302, and `Burned<false>` and `Burned<true>` exactly 4014 and 5025, with the variable counts and digests pinned in the test.
  - Location: `src/circuit/protocol/utxo/data.rs:118-150`
  - Severity: High
  - Suggested test: positive (digest); `tests/unit/protocol/data/r1cs.rs`

- [x] **INV-DATA-07: every input rule owns its rows**
  - Covered by: `tests/unit/protocol/data/r1cs.rs` `every_input_rule_owns_its_pinned_rows`
  - Kind: constraint
  - Statement: in `Held<false>` the spendable rule owns exactly one row, the ring rule two and the state commitment rule one, and a burned counter's leftover-balance rule owns exactly one row of `Burned<false>`.
  - Location: `src/circuit/protocol/utxo/data.rs:129-150`, `src/circuit/protocol/utxo/data.rs:167-182` (`fn output`)
  - Severity: Critical
  - Suggested test: positive; `tests/unit/protocol/data/r1cs.rs`

### Completeness

- [x] **INV-DATA-08: every held counter checks exactly the pinned count**
  - Covered by: `tests/unit/protocol/data/r1cs.rs` `every_held_counter_checks_exactly_the_pinned_count`
  - Kind: completeness
  - Statement: `check_constraints` returns exactly `Ok(2448)` for every held vector.
  - Location: `src/prover/synthesis.rs` (`fn check`)
  - Severity: High
  - Suggested test: positive; `tests/unit/protocol/data/r1cs.rs`

### Soundness

- [x] **INV-DATA-09: a tampered claim or data hash breaks exactly its rule**
  - Covered by: `tests/unit/protocol/data/r1cs.rs` `a_tampered_claim_or_data_hash_breaks_exactly_its_rule`
  - Kind: soundness
  - Statement: tampering the count, balance, owner hash or asset hash claim breaks exactly its own rule, and tampering the input's data hash breaks exactly "the input does not commit to its program state".
  - Location: `src/circuit/protocol/utxo/data.rs:136-139`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/data/r1cs.rs`

- [x] **INV-DATA-10: only the carried nullifier and latest tree are tolerated**
  - Covered by: `tests/unit/protocol/data/r1cs.rs` `only_the_carried_nullifier_and_latest_tree_are_tolerated`
  - Kind: soundness
  - Statement: `check_private_variables` of the counter at 5 reports no free variable and exactly 2 tolerated ones.
  - Location: `src/circuit/protocol/utxo/input.rs:64-71` (`fn spent`)
  - Severity: High
  - Suggested test: negative; `tests/unit/protocol/data/r1cs.rs`

### Error

- [x] **INV-DATA-11: an input that does not commit to the state breaks exactly its rule**
  - Covered by: `tests/unit/protocol/data/native.rs` `an_input_that_does_not_commit_to_the_state_breaks_exactly_its_rule`
  - Kind: error
  - Statement: natively, a counter at 5 spent with the state 6 and a token input spent with a state each break exactly "the input does not commit to its program state", a ring input exactly "the utxo is in a ring", and a dummy exactly "the utxo is not a spendable utxo", located in the fixture's file.
  - Location: `src/circuit/protocol/utxo/data.rs:129-150` (`fn spend`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/data/native.rs`

- [x] **INV-DATA-12: a burned counter must leave nothing**
  - Covered by: `tests/unit/protocol/data/native.rs` `a_burned_counter_must_leave_nothing_and_withdraw_all_empties_it`; `tests/unit/protocol/data/r1cs.rs` `the_prover_refuses_a_burned_counter_that_keeps_a_balance`
  - Kind: error
  - Statement: a burned counter holding 300 returns exactly `RuleBroken` with "a burned data utxo leaves a balance" natively and from `check_constraints`; withdrawn whole it holds (`Ok(5025)`), an empty burned counter holds (`Ok(4014)`), and withdrawing all of an empty one breaks exactly the nonzero rule.
  - Location: `src/circuit/protocol/utxo/data.rs:167-182` (`fn output`)
  - Error: `CircuitErrorKind::RuleBroken`
  - Severity: Critical
  - Suggested test: negative; `tests/unit/protocol/data/native.rs`, `tests/unit/protocol/data/r1cs.rs`

INV-DATA summary: 12 (Critical 5, High 6, Medium 1); covered 12.
