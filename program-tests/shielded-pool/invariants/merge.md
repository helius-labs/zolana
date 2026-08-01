# Merge Invariants

Covers `MergeTransact` (tag 12) and `ZoneMergeTransact` (tag 13). Shared invariants
(expiry, pause, stale root, double-spend, rollback, external-hash domain separation)
live in `cross-cutting.md`.

SPEC_DIVERGENCE (resolved 2026-07-23): the spec previously described a variable input
count `N` and an oversized proof; `docs/spec.md` now matches the code: a fixed
8-in/1-out shape and a 128-byte vanilla Groth16 `a||b||c` proof with no BSB22
commitment (`program-libs/interface/src/instruction/instruction_data/merge_transact.rs:9-22`,
`docs/spec.md:1795-1836`). Post-PR164 the merge output is ciphertext-free (no
`encrypted_utxo` field and no `merge_view_tag`): the output is recovered from the
first real input and its nullifier, and padding slots publish derived dummy
nullifiers.

## MergeTransact

### Account Constraints

- [x] **INV-MERGE-01: tree account must be writable**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_a_non_writable_tree`
  - Kind: precondition
  - Statement: `merge_transact` can only succeed when the first two accounts (`input_tree` and `output_tree`) are writable.
  - Location: `programs/shielded-pool/src/instructions/merge/account.rs:21-22` (`fn validate_and_parse`)
  - Error: account-checks error
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-MERGE-02: payer must sign**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_an_unsigned_payer`
  - Kind: precondition
  - Statement: `merge_transact` can only succeed when the third account (`payer`) is a signer; no other authorization signer exists (any caller may merge an opted-in owner's notes).
  - Location: `programs/shielded-pool/src/instructions/merge/account.rs:23` (`fn validate_and_parse`)
  - Error: account-checks signer error
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-MERGE-03: user_record must be owned by the user-registry program with a valid record**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_a_user_record_not_owned_by_the_registry`
  - Kind: precondition
  - Statement: the `user_record` account must be owned by `USER_REGISTRY_PROGRAM_ID` and parse as a valid `UserRecord`; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/merge/account.rs:58-89` (`fn load_user_record`)
  - Error: `ShieldedPoolError::InvalidUserRecord = 7018`
  - Severity: Critical (owner-binding source)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-MERGE-04: merging requires the owner's opt-in**
  - Covered by: `program-tests/spp-test-validator/tests/lifecycle.rs` `merge_rejects_an_owner_that_has_not_opted_in`
  - Kind: precondition
  - Statement: `merge_transact` returns Err whenever the registry record's `merging_enabled` flag is exactly `false`.
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs:43-45` (`fn process_merge_transact_ix`)
  - Error: `ShieldedPoolError::MergeDisabled = 7017`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-MERGE-05: P256 owner rail requires a registered P256 key**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_a_p256_rail_without_a_registered_p256_owner`
  - Kind: precondition
  - Statement: when `eddsa_owner` is `false`, the registry record's `owner_p256` must be `Some`; a record without a P256 key returns Err.
  - Location: `programs/shielded-pool/src/instructions/merge/account.rs:77-79` (`fn load_user_record`)
  - Error: `ShieldedPoolError::InvalidUserRecord = 7018`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-MERGE-18: merge account layout — two trees, signer payer, system program**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `rejects_invalid_system_program_with_specific_error`
  - Kind: precondition
  - Statement: the `merge_transact` account layout is `input_tree` (writable), `output_tree` (writable), `payer` (signer), `user_record`, `system_program`; the `zone_merge_transact` layout is `input_tree`, `output_tree`, `zone_config` (signer), `payer` (signer), `system_program`; the trailing system-program account must be the system program (it is kept in the account keys so the forester-fee Transfer CPI resolves).
  - Location: `programs/shielded-pool/src/instructions/merge/account.rs:19-36` (`fn validate_and_parse`), `merge_zone/account.rs:22-39`
  - Error: `ShieldedPoolError::InvalidSystemProgram = 7028`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-MERGE-17: a merge past the dummy-input capacity threshold fails at proof verification**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_dummy_inputs_after_capacity_threshold`
  - Kind: postcondition
  - Statement: when the input tree's `allow_dummy_inputs()` is false, the on-chain public input recomputes with the flag 0 while merge proofs are always built with `allow_dummy_inputs = true`, so `merge_transact`/`zone_merge_transact` fail pairing before any queue insertion or append. (PR172 removed the explicit gate; `NullifierTreeTooFullForMerge = 7044` is a retired variant kept only for wire-code stability — no program path returns it.)
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs` (`fn process_merge_core`, `allow_dummy_inputs` leg)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: High (availability)
  - Suggested test: negative (exists; crosses the threshold by moving the nullifier queue cursor in litesvm instead of a 250-queue localnet setup); harness: litesvm

### Instruction Data Validation

- [x] **INV-MERGE-06: the 8-in/1-out shape is enforced at parse time**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_a_wrong_input_count_shape`
  - Kind: precondition
  - Statement: every payload whose `nullifiers`, `utxo_tree_root_index`, or `nullifier_tree_root_index` vector length differs from exactly 8 makes `merge_transact` return Err.
  - Location: `program-libs/interface/src/instruction/instruction_data/merge_transact.rs:106-115` (`fn validate_shape`), `programs/shielded-pool/src/instructions/merge/processor.rs:31-32`
  - Error: `ShieldedPoolError::InvalidMergeShape = 7019`
  - Severity: High
  - Suggested test: negative + fuzz; harness: mollusk unit

- [ ] **INV-MERGE-07: the output blob must be verifiably encrypted**
  - Not applicable post-PR164 (the merge output is ciphertext-free: the `encrypted_utxo` field and the `MERGE_ENCRYPTED_UTXO_*` constants were removed; the owner recovers the output from the first input and its nullifier). The covering `merge_rejects_a_wrong_encrypted_output_scheme` test was removed with the field.

### Proof Binding

- [x] **INV-MERGE-08: the proof binds the owner's registered signing key**
  - Covered by: `program-tests/spp-test-validator/tests/lifecycle.rs` `merge_rejects_a_proof_bound_to_a_foreign_user_record` (a proof bound to owner A submitted with owner B's `user_record` fails with 7008; the substitution changes the bound signing_pk_field and the event tag, both derived from the record)
  - Kind: postcondition
  - Statement: the merge public-input hash folds `signing_pk_field` derived exactly from the registry record, so a proof built for a different owner than the supplied `user_record` fails verification.
  - Location: `programs/shielded-pool/src/instructions/merge/account.rs:58-89` (`fn load_user_record`), `merge/verify.rs:84-115` (`fn public_input_hash`, `Registry` arm)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (owner substitution)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-MERGE-09: the proof binds the owner's registered viewing key**
  - Not applicable post-PR164 (the merge encryption flow was restructured: the output is ciphertext-free and recovered by the owner from the first input and its nullifier, so no viewing-key public input exists; F-06 re-reviewed 2026-07-27 and closed as MOOT -- no recipient viewing key enters any circuit KDF anymore).

- [ ] **INV-MERGE-10: the ciphertext hash is recomputed on-chain**
  - Not applicable post-PR164 (no merge ciphertext exists, so there is nothing to recompute on-chain).

- [x] **INV-MERGE-11: the merge proof is vanilla Groth16 with the variant's key**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `default_rail_merge_rejects_a_zeroed_proof_exactly` (7008), `default_rail_merge_rejects_undecompressable_proof_points_exactly` (7007)
  - Kind: precondition
  - Statement: `merge_transact` decodes the fixed 128-byte proof as `a||b||c` (no commitment) and verifies it only against `merge_8_1::VERIFYINGKEY` (default rail) or `merge_zone_8_1::VERIFYINGKEY` (zone rail); a proof whose points fail decompression returns the encoding error, a non-verifying proof returns the verification error.
  - Location: `programs/shielded-pool/src/instructions/merge/verify.rs:51-73` (`fn verify`)
  - Error: `ShieldedPoolError::InvalidTransactProofEncoding = 7007` / `TransactProofVerificationFailed = 7008`
  - Severity: Critical
  - Suggested test: negative both errors; harness: mollusk unit

- [ ] **INV-MERGE-12: registry public-input shape is the 7-element prefix plus the owner key**
  - Partial coverage: `program-tests/spp-test-validator/tests/lifecycle.rs` `eddsa_merge_covers_every_supported_input_count` (successful end-to-end verification exercises the chain; no explicit element-count/order assertion)
  - Kind: state
  - Statement: the `merge_transact` public-input hash chains the 7-element prefix (nullifier-chain, output hash, utxo-root chain, nullifier-root chain, `private_tx_hash`, `external_data_hash`, `allow_dummy_inputs`) and then folds exactly one owner-identity element, `signing_pk_field` from the registry record.
  - Location: `programs/shielded-pool/src/instructions/merge/verify.rs:84-115` (`fn public_input_hash`)
  - Severity: High
  - Suggested test: property (compare against client-side computation in `sdk-libs/keypair`); harness: `cargo test -p`

### Success Postconditions

- [ ] **INV-MERGE-13: exactly 8 nullifiers are inserted and one leaf appended**
  - Partial coverage: `program-tests/spp-test-validator/tests/lifecycle.rs` `eddsa_merge_covers_every_supported_input_count` (output appended and inputs spent; the exact +8 queue / +1 tree `next_index` deltas are not asserted)
  - Kind: postcondition
  - Statement: after a successful `merge_transact`, the nullifier queue's `next_index` is exactly its value before plus 8, and the UTXO tree's `next_index` is exactly its value before plus 1 with the appended leaf equal to `output_utxo_hash`.
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs:141-172` (`fn apply_input_tree`), `merge/processor.rs:174-189` (`fn apply_output_tree`)
  - Severity: Critical
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-MERGE-14: successful merge emits exactly one Merge GeneralEvent tagged by the owner key**
  - Partial coverage: `program-tests/spp-test-validator/tests/lifecycle.rs` `eddsa_merge_covers_every_supported_input_count` (output rediscovered by owner signing-key tag; nullifier sequence numbers, verbatim `data`, and the empty `spl_transfers` list unasserted)
  - Kind: postcondition
  - Statement: after a successful `merge_transact`, exactly one self-CPI `EmitEvent` inner instruction is recorded whose `GeneralEvent` carries the 8 nullifiers with assigned queue sequence numbers and exactly one output whose `view_tag` is the owner's signing-key tag from the registry record and whose `data` is empty (ciphertext-free output), and an empty `spl_transfers` list (no public movements).
  - Location: `programs/shielded-pool/src/instructions/merge/event.rs:15-42` (`fn build_merge_event`), `merge/account.rs:58-89`
  - Severity: Medium (owner rediscovery on sync)
  - Suggested test: positive; harness: litesvm

- [x] **INV-MERGE-19: merge collects the forester fee for 8 queued nullifiers**
  - Covered by: `program-tests/shielded-pool/tests/merge/functional.rs` `merge_collects_the_exact_forester_fee_from_the_payer` (real on-chain merge proof; tree gains exactly 160 lamports, payer loses exactly fee+160, every other account byte-identical); also `program-tests/spp-test-validator/tests/lifecycle.rs` `actor_owned_merge_covers_every_supported_input_count` and `eddsa_merge_covers_every_supported_input_count` via the shared merge action, which asserts the payer loses and the input tree gains exactly `MERGE_INPUT_COUNT` (8) × the 20-lamport per-element fee (`spp-test-validator/tests/actions/merge.rs:224-238`)
  - Kind: postcondition
  - Statement: after proof verification the payer transfers exactly `MERGE_INPUT_COUNT` (8) × `forester_fee_per_queue_element(zkp_batch_size)` lamports to the input tree via one System-Program CPI; a fee-computation overflow returns 7026; a zero fee skips the CPI; the tree must be writable and program-owned else 7001.
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs:131-136` (`fn process_merge_core`), `shared.rs:77-103` (`fn collect_forester_fee`)
  - Error: `ShieldedPoolError::InvalidForesterFee = 7026`
  - Severity: High (fund movement)
  - Suggested test: none remaining (exact deltas pinned; 7026 overflow legs covered by `program-tests/shielded-pool/tests/tree/contract.rs` `forester_fee_overflow_is_invalid_forester_fee`, `reimbursement_recipient_balance_overflow_is_invalid_forester_fee`)

### Frame Conditions

- [x] **INV-MERGE-15: merge modifies only the two tree accounts and the payer**
  - Covered by: `program-tests/spp-test-validator/tests/lifecycle.rs` `actor_owned_merge_covers_every_supported_input_count` and `eddsa_merge_covers_every_supported_input_count` via the shared merge action, which asserts the payer loses exactly the 8×20-lamport forester fee, the input tree gains exactly that amount, and the read-only user record is unchanged around every successful merge (`spp-test-validator/tests/actions/merge.rs:224-239`); the remaining instruction account is the system program, which cannot be modified by the program.
  - Kind: frame
  - Statement: after a successful `merge_transact`, every account other than the two tree accounts (`input_tree`, `output_tree`) and the `payer` has unchanged data and unchanged lamports (no settlement exists on this instruction); the only lamport movement is the forester fee (`MERGE_INPUT_COUNT` × `forester_fee_per_queue_element(zkp_batch_size)`, 160 lamports at 20/element) from the payer to the input tree; in particular the `user_record` is read-only.
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs:30-72` (`fn process_merge_transact_ix`), `merge/processor.rs:82-138` (`fn process_merge_core`, fee at 131-136)
  - Severity: High
  - Suggested test: positive; harness: mollusk unit (account snapshot compare)

### Nullifier Integrity

- [x] **INV-MERGE-16: dummy merge slots publish the derived MergeDummyNullifier**
  - Covered by: `prover/server/circuits/spp_merge/dummy_nullifier_attack_test.go` `TestMergeRejectsVictimNullifierInDummySlot`, `TestMergeAcceptsDerivedDummyNullifiers`
  - Kind: precondition
  - Statement: for every padding input slot in a merge, the published nullifier equals exactly the deterministic `MergeDummyNullifier(nullifier_secret, first_nullifier, slot_index)` derivation — seeded with the owner's nullifier secret, deliberately *not* the first input blinding (which that UTXO's sender also knows) — so a merge delegate cannot park a real wallet nullifier in a padding slot (the F-03 fix).
  - Location: `prover/server/circuits/spp_merge/shared/derivation.go:38-47` (`MergeDummyNullifier`, domain `TMDN`), dummy-slot constraints in `prover/server/circuits/spp_merge/`
  - Error: circuit constraint failure (proof cannot be constructed)
  - Severity: Critical
  - Suggested test: negative (victim's real nullifier placed in a dummy slot) + positive (derived dummies verify); harness: Go circuit tests (`go test ./circuits/spp_merge`)

## ZoneMergeTransact

### Account Constraints

- [x] **INV-ZONE-MERGE-01: zone_config must sign**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_zone_rejects_an_unsigned_zone_config`
  - Kind: precondition
  - Statement: `zone_merge_transact` can only succeed when the third account (`zone_config`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/merge_zone/account.rs:26` (`fn validate_and_parse`)
  - Error: account-checks signer error
  - Severity: Critical (zone authorization)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-MERGE-02: zone_config must be a valid SPP-owned ZoneConfig**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_zone_rejects_a_zone_config_with_a_wrong_owner`, `merge_zone_rejects_a_zone_config_with_a_wrong_discriminator`
  - Kind: precondition
  - Statement: the `zone_config` account must be owned by the shielded-pool program with `data_len` exactly 67 and discriminator 4; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/zone_config/loader.rs:14-20` (`fn load_zone_config`), `merge_zone/account.rs:27`
  - Error: `ShieldedPoolError::InvalidZoneConfig = 7014`
  - Severity: Critical
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-MERGE-03: payer must sign**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_zone_rejects_an_unsigned_payer`
  - Kind: precondition
  - Statement: `zone_merge_transact` can only succeed when the fourth account (`payer`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/merge_zone/account.rs:28` (`fn validate_and_parse`)
  - Error: account-checks signer error
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-MERGE-04: no registry opt-in is consulted**
  - Covered by: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `zone_merge_consolidates_inputs`
  - Kind: precondition
  - Statement: `zone_merge_transact` succeeds without a `user_record` account and regardless of any registry `merging_enabled` flag; authorization is exactly the zone_config signature.
  - Location: `programs/shielded-pool/src/instructions/merge_zone/processor.rs:25-70` (`fn process_merge_zone_ix`)
  - Severity: High
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

### Instruction Data Validation

- [x] **INV-ZONE-MERGE-05: shape checks equal merge_transact's**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_zone_rejects_a_wrong_input_count_shape_exactly` (7019)
  - Kind: precondition
  - Statement: `zone_merge_transact` rejects, exactly as INV-MERGE-06, every embedded merge body whose element vectors are not length 8.
  - Location: `program-libs/interface/src/instruction/instruction_data/merge_zone.rs` (`MergeZoneIxDataRef::from_bytes`), `merge_zone/processor.rs`
  - Error: `ShieldedPoolError::InvalidMergeShape = 7019`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Proof Binding

- [x] **INV-ZONE-MERGE-06: the proof binds the signing zone's program id**
  - Covered by: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `zone_merge_rejects_a_proof_bound_to_another_zone` (the same zone fixture is deployed under two program IDs; a proof built for zone A is submitted through zone B's valid signer/config and fails with 7008 while the tree remains unchanged).
  - Kind: postcondition
  - Statement: the zone-merge public-input hash folds `Poseidon(low, high)` of the signing `zone_config.program_id` as its final element; a proof built for a different zone fails verification.
  - Location: `programs/shielded-pool/src/instructions/merge_zone/processor.rs:42-52` (`fn process_merge_zone_ix`), `merge/verify.rs:101-110` (`fn public_input_hash`, `Zone` arm)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (cross-zone merge prevention)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-ZONE-MERGE-07: zone merge verifies only against merge_zone_8_1**
  - Partial coverage: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `invalid_proofs_and_disabled_authority_are_atomic` (zeroed proof -> 7008; a real `merge_8_1` proof cross-submitted to zone merge is not tested)
  - Kind: precondition
  - Statement: `zone_merge_transact` verifies only against `merge_zone_8_1::VERIFYINGKEY`; a proof for the default `merge_8_1` circuit does not verify (the two key selections are mutually exclusive by owner-binding variant).
  - Location: `programs/shielded-pool/src/instructions/merge/verify.rs:62-73` (`fn verify`, key selection and `verify_groth16` call)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-ZONE-MERGE-08: zone public-input shape is the 7-element prefix plus zone data and zone id**
  - Partial coverage: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `zone_merge_consolidates_inputs` (successful end-to-end verification exercises the chain; no explicit element-count assertion)
  - Kind: state
  - Statement: the `zone_merge_transact` public-input hash chains the 7-element prefix (as in INV-MERGE-12) and then folds `output_zone_data_hash` and `zone_program_id`; it folds no signing or viewing key field (owner identity is omitted by design).
  - Location: `programs/shielded-pool/src/instructions/merge/verify.rs:84-115` (`fn public_input_hash`, `Zone` arm)
  - Severity: High
  - Suggested test: property (client-side comparison); harness: `cargo test -p`

### Success Postconditions

- [ ] **INV-ZONE-MERGE-09: merge_view_tag is single-use**
  - Not applicable post-PR164 (the `merge_view_tag` field was removed; replay protection comes from the queued proof-bound input nullifiers themselves -- INV-ZONE-MERGE-12).

- [x] **INV-ZONE-MERGE-10: the emitted output is indexed by the first input nullifier**
  - Covered by: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `zone_merge_consolidates_inputs`
  - Kind: postcondition
  - Statement: after a successful `zone_merge_transact`, the emitted `GeneralEvent`'s single output is indexed by the first input's published nullifier (there is no instruction-supplied tag).
  - Location: `programs/shielded-pool/src/instructions/merge_zone/processor.rs:54-69` (`fn process_merge_zone_ix`), `merge/event.rs:15-42`
  - Severity: Medium
  - Suggested test: positive; harness: litesvm

- [x] **INV-ZONE-MERGE-11: external hash uses the zone-merge discriminator**
  - Covered by: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `zone_merge_rejects_a_default_merge_proof` (a valid discriminator-12 merge proof built from default-zone UTXOs is submitted unchanged through discriminator 13 and rejected atomically with 7008).
  - Kind: postcondition
  - Statement: the recomputed `external_data_hash` for `zone_merge_transact` uses `spp_instruction_discriminator` exactly 13 (`ZONE_MERGE_TRANSACT`), so a proof built for `merge_transact` (discriminator 12) with identical fields fails verification.
  - Location: `programs/shielded-pool/src/instructions/merge_zone/processor.rs:34-40` (`fn process_merge_zone_ix`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: High (cross-instruction replay)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-ZONE-MERGE-13: zone merge event publishes the output zone_data_hash**
  - Partial coverage: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `zone_merge_consolidates_inputs` (successful zone merge exercises the emit; the output `data` payload is not field-asserted)
  - Kind: postcondition
  - Statement: the emitted `GeneralEvent`'s single output carries `output_zone_data_hash` as its `data` payload (default merge: empty data), and the proof binds that same hash (INV-ZONE-MERGE-08), so a relayer cannot alter the published zone binding.
  - Location: `programs/shielded-pool/src/instructions/merge_zone/processor.rs:57-69` (`fn process_merge_zone_ix`), `merge/event.rs:15-42` (`fn build_merge_event`)
  - Severity: Medium (wallet reconstruction)
  - Suggested test: positive (assert the event output `data` equals `output_zone_data_hash`); harness: litesvm

### Nullifier Integrity

- [x] **INV-ZONE-MERGE-12: merge_zone queues exactly the proof-bound input nullifiers**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` shape tests; compile-level absence of the removed merge_view_tag field in `MergeZoneIxData` (`program-libs/interface/src/instruction/instruction_data/merge_zone.rs`)
  - Kind: postcondition
  - Statement: after a successful `zone_merge_transact`, exactly the proof's 8 input nullifiers are queued and nothing else: the single-use `merge_view_tag` field no longer exists, the emitted output is indexed by the first input nullifier, and `output_zone_data_hash` is proof-bound (eliminates the unvalidated-tag queue-poisoning class, F-02/F-09).
  - Location: `programs/shielded-pool/src/instructions/merge_zone/processor.rs:57-69` (`fn process_merge_zone_ix`), `programs/shielded-pool/src/instructions/merge/verify.rs:23-27, 102-110` (`MergeOwnerBinding::Zone`)
  - Error: `ShieldedPoolError::NullifierTreeUpdateFailed = 7002` (replay), `TransactProofVerificationFailed = 7008` (binding mismatch)
  - Severity: Critical
  - Suggested test: negative (replay) + negative (foreign-zone proof); harness: program-tests integration (`cargo test-sbf`)
