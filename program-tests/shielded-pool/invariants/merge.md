# Merge Invariants

Covers `MergeTransact` (tag 12) and `ZoneMergeTransact` (tag 13). Shared invariants
(expiry, pause, stale root, double-spend, rollback, external-hash domain separation)
live in `cross-cutting.md`.

SPEC_DIVERGENCE (resolved 2026-07-23): the spec previously described a variable input
count `N` and a 256-byte proof; `docs/spec.md` now matches the code (fixed 8-in/1-out
shape, 192-byte BSB22 proof, 110-byte `encrypted_utxo`).

## MergeTransact

### Account Constraints

- [x] **INV-MERGE-01: tree account must be writable**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_a_non_writable_tree`
  - Kind: precondition
  - Statement: `merge_transact` can only succeed when the first account (`tree`) is writable.
  - Location: `programs/shielded-pool/src/instructions/merge/account.rs:21` (`fn validate_and_parse`)
  - Error: account-checks error
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-MERGE-02: payer must sign**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_an_unsigned_payer`
  - Kind: precondition
  - Statement: `merge_transact` can only succeed when the second account (`payer`) is a signer; no other authorization signer exists (any caller may merge an opted-in owner's notes).
  - Location: `programs/shielded-pool/src/instructions/merge/account.rs:22` (`fn validate_and_parse`)
  - Error: account-checks signer error
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-MERGE-03: user_record must be owned by the user-registry program with a valid record**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_a_user_record_not_owned_by_the_registry`
  - Kind: precondition
  - Statement: the `user_record` account must be owned by `USER_REGISTRY_PROGRAM_ID` and parse as a valid `UserRecord`; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/merge/account.rs:50-62` (`fn load_user_record`)
  - Error: `ShieldedPoolError::InvalidUserRecord = 7018`
  - Severity: Critical (owner-binding source)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-MERGE-04: merging requires the owner's opt-in**
  - Covered by: `program-tests/spp-test-validator/tests/lifecycle.rs` `merge_rejects_an_owner_that_has_not_opted_in`
  - Kind: precondition
  - Statement: `merge_transact` returns Err whenever the registry record's `merging_enabled` flag is exactly `false`.
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs:44-47` (`fn process_merge_transact_ix`)
  - Error: `ShieldedPoolError::MergeDisabled = 7017`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-MERGE-05: P256 owner rail requires a registered P256 key**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_a_p256_rail_without_a_registered_p256_owner`
  - Kind: precondition
  - Statement: when `eddsa_owner` is `false`, the registry record's `owner_p256` must be `Some`; a record without a P256 key returns Err.
  - Location: `programs/shielded-pool/src/instructions/merge/account.rs:69-73` (`fn load_user_record`)
  - Error: `ShieldedPoolError::InvalidUserRecord = 7018`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Instruction Data Validation

- [x] **INV-MERGE-06: the 8-in/1-out shape is enforced at parse time**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_a_wrong_input_count_shape`
  - Kind: precondition
  - Statement: every payload whose `nullifiers`, `utxo_tree_root_index`, or `nullifier_tree_root_index` vector length differs from exactly 8, or whose `encrypted_utxo` length differs from exactly 110 bytes, makes `merge_transact` return Err.
  - Location: `program-libs/interface/src/instruction/instruction_data/merge_transact.rs:85-94` (`fn validate_shape`), `programs/shielded-pool/src/instructions/merge/processor.rs:29-31`
  - Error: `ShieldedPoolError::InvalidMergeShape = 7019`
  - Severity: High
  - Suggested test: negative + fuzz; harness: mollusk unit

- [x] **INV-MERGE-07: the output blob must be verifiably encrypted**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_a_wrong_encrypted_output_scheme`
  - Kind: precondition
  - Statement: `merge_transact` returns Err whenever the first byte of `encrypted_utxo` is not exactly `MERGE_ENCRYPTED_UTXO_TYPE_PREFIX` (2, the borsh `VerifiablyEncrypted` discriminant).
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs:32-34` (`fn process_merge_transact_ix`), `merge_transact.rs:15`
  - Error: `ShieldedPoolError::InvalidMergeOutputScheme = 7020`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Proof Binding

- [x] **INV-MERGE-08: the proof binds the owner's registered signing key**
  - Covered by: `program-tests/spp-test-validator/tests/lifecycle.rs` `merge_rejects_a_proof_bound_to_a_foreign_user_record` (a proof bound to owner A submitted with owner B's `user_record` fails with 7008; the substitution changes both the signing and viewing bound fields, so this covers INV-MERGE-08 and INV-MERGE-09 together)
  - Kind: postcondition
  - Statement: the merge public-input hash folds `signing_pk_field` derived exactly from the registry record -- `solana_pk_hash(record.owner)` when `eddsa_owner` is true, `owner_pk_field_compressed(record.owner_p256)` otherwise -- so a proof built for a different owner than the supplied `user_record` fails verification.
  - Location: `programs/shielded-pool/src/instructions/merge/account.rs:64-74` (`fn load_user_record`), `merge/verify.rs:114-129` (`fn public_input_hash`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (owner substitution)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-MERGE-09: the proof binds the owner's registered viewing key**
  - Covered by: `program-tests/spp-test-validator/tests/lifecycle.rs` `merge_rejects_a_proof_bound_to_a_foreign_user_record` (see INV-MERGE-08: the foreign `user_record` substitutes `viewing_pk_field` as well as `signing_pk_field`, so a proof whose viewing binding differs from the passed record's is rejected with 7008)
  - Kind: postcondition
  - Statement: the merge public-input hash folds `viewing_pk_field = pk_field(record.viewing_pubkey)`; a proof that encrypted the output to any other viewing key fails verification.
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs:50` (`fn process_merge_transact_ix`), `merge/verify.rs:114-129`
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (output must stay decryptable by the owner)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-MERGE-10: the ciphertext hash is recomputed on-chain**
  - Partial coverage: `program-libs/interface/src/merge_utils.rs` `ciphertext_hash_matches_circuit_vector` (the hash helper is pinned to the circuit vector; an on-chain ciphertext bit-flip -> 7008 test is missing)
  - Kind: postcondition
  - Statement: the public-input hash folds `ciphertext_hash(encrypted_utxo[39..110])` and `pack33(encrypted_utxo[6..39])` recomputed from the instruction bytes; changing any ciphertext byte after proving makes verification fail.
  - Location: `programs/shielded-pool/src/instructions/merge/verify.rs:85-99` (`fn public_input_hash`), `program-libs/interface/src/merge_utils.rs:74-78`
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical
  - Suggested test: negative (bit-flip); harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-MERGE-11: the merge proof is always BSB22-committed with the merge_8_1 key**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `default_rail_merge_rejects_a_zeroed_proof_exactly` (7008), `default_rail_merge_rejects_undecompressable_proof_points_exactly` (7007)
  - Kind: precondition
  - Statement: `merge_transact` decodes the fixed 192-byte proof as `a||b||c||commitment||commitment_pok` and verifies it only against `merge_8_1::VERIFYINGKEY`; a proof whose points fail decompression returns the encoding error, a non-verifying proof returns the verification error.
  - Location: `programs/shielded-pool/src/instructions/merge/verify.rs:52-75` (`fn verify`)
  - Error: `ShieldedPoolError::InvalidTransactProofEncoding = 7007` / `TransactProofVerificationFailed = 7008`
  - Severity: Critical
  - Suggested test: negative both errors; harness: mollusk unit

- [ ] **INV-MERGE-12: registry public-input shape is exactly 11 elements**
  - Partial coverage: `program-tests/spp-test-validator/tests/lifecycle.rs` `eddsa_merge_covers_every_supported_input_count` (successful end-to-end verification exercises the chain; no explicit element-count/order assertion)
  - Kind: state
  - Statement: the `merge_transact` public-input hash chain contains exactly 11 elements in the fixed order nullifier-chain, output hash, utxo-root chain, nullifier-root chain, private_tx_hash, external_data_hash, signing_pk_field, viewing_pk_field, tx_viewing_pk_lo, tx_viewing_pk_hi, ciphertext hash.
  - Location: `programs/shielded-pool/src/instructions/merge/verify.rs:114-129` (`fn public_input_hash`)
  - Severity: High
  - Suggested test: property (compare against client-side computation in `sdk-libs/keypair`); harness: `cargo test -p`

### Success Postconditions

- [ ] **INV-MERGE-13: exactly 8 nullifiers are inserted and one leaf appended**
  - Partial coverage: `program-tests/spp-test-validator/tests/lifecycle.rs` `eddsa_merge_covers_every_supported_input_count` (output appended and inputs spent; the exact +8 queue / +1 tree `next_index` deltas are not asserted)
  - Kind: postcondition
  - Statement: after a successful `merge_transact`, the nullifier queue's `next_index` is exactly its value before plus 8, and the UTXO tree's `next_index` is exactly its value before plus 1 with the appended leaf equal to `output_utxo_hash`.
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs:124-172` (`fn apply_tree`)
  - Severity: Critical
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-MERGE-14: successful merge emits exactly one Merge GeneralEvent tagged by the owner key**
  - Partial coverage: `program-tests/spp-test-validator/tests/lifecycle.rs` `eddsa_merge_covers_every_supported_input_count` (output rediscovered by owner signing-key tag; nullifier sequence numbers, verbatim `data`, and `deposit_withdraw = None` unasserted)
  - Kind: postcondition
  - Statement: after a successful `merge_transact`, exactly one self-CPI `EmitEvent` inner instruction is recorded whose `GeneralEvent` carries the 8 nullifiers with assigned queue sequence numbers, exactly one output whose `view_tag` is the owner's signing-key tag from the registry record (the full ed25519 key, or the P256 x-coordinate) and whose `data` is the `encrypted_utxo` bytes verbatim, and `deposit_withdraw = None`.
  - Location: `programs/shielded-pool/src/instructions/merge/event.rs:15-45` (`fn build_merge_event`), `merge/account.rs:64-74`
  - Severity: Medium (owner rediscovery on sync)
  - Suggested test: positive; harness: litesvm

### Frame Conditions

- [x] **INV-MERGE-15: merge modifies only the tree account**
  - Covered by: `program-tests/spp-test-validator/tests/lifecycle.rs` `p256_merge_covers_every_supported_input_count` and `eddsa_merge_covers_every_supported_input_count` via the shared merge action, which snapshots and compares the writable merge payer and read-only user record around every successful merge; the remaining instruction accounts are executable/sysvar accounts and cannot be modified by the program.
  - Kind: frame
  - Statement: after a successful `merge_transact`, every account other than the tree account has unchanged data and unchanged lamports (no settlement exists on this instruction); in particular the `user_record` is read-only.
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs:28-84` (`fn process_merge_transact_ix`)
  - Severity: High
  - Suggested test: positive; harness: mollusk unit (account snapshot compare)

## ZoneMergeTransact

### Account Constraints

- [x] **INV-ZONE-MERGE-01: zone_config must sign**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_zone_rejects_an_unsigned_zone_config`
  - Kind: precondition
  - Statement: `zone_merge_transact` can only succeed when the second account (`zone_config`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/merge_zone/account.rs:22` (`fn validate_and_parse`)
  - Error: account-checks signer error
  - Severity: Critical (zone authorization)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-MERGE-02: zone_config must be a valid SPP-owned ZoneConfig**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_zone_rejects_a_zone_config_with_a_wrong_owner`, `merge_zone_rejects_a_zone_config_with_a_wrong_discriminator`
  - Kind: precondition
  - Statement: the `zone_config` account must be owned by the shielded-pool program with `data_len` exactly 67 and discriminator 4; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/zone_config/loader.rs:13-28` (`fn load_zone_config`), `merge_zone/account.rs:23`
  - Error: `ShieldedPoolError::InvalidZoneConfig = 7014`
  - Severity: Critical
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-MERGE-03: payer must sign**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_zone_rejects_an_unsigned_payer`
  - Kind: precondition
  - Statement: `zone_merge_transact` can only succeed when the third account (`payer`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/merge_zone/account.rs:24` (`fn validate_and_parse`)
  - Error: account-checks signer error
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-MERGE-04: no registry opt-in is consulted**
  - Covered by: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `zone_merge_consolidates_inputs`
  - Kind: precondition
  - Statement: `zone_merge_transact` succeeds without a `user_record` account and regardless of any registry `merging_enabled` flag; authorization is exactly the zone_config signature.
  - Location: `programs/shielded-pool/src/instructions/merge_zone/processor.rs:33-80` (`fn process_merge_zone_ix`)
  - Severity: High
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

### Instruction Data Validation

- [x] **INV-ZONE-MERGE-05: shape and output-scheme checks equal merge_transact's**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_zone_rejects_a_wrong_input_count_shape_exactly` (7019), `merge_zone_rejects_a_wrong_encrypted_output_scheme_exactly` (7020)
  - Kind: precondition
  - Statement: `zone_merge_transact` rejects, exactly as INV-MERGE-06/07, every embedded merge body whose element vectors are not length 8, whose `encrypted_utxo` is not 110 bytes, or whose first blob byte is not 2.
  - Location: `program-libs/interface/src/instruction/instruction_data/merge_zone.rs:33-39` (`fn from_bytes`), `merge_zone/processor.rs:34-41`
  - Error: `ShieldedPoolError::InvalidMergeShape = 7019` / `InvalidMergeOutputScheme = 7020`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Proof Binding

- [x] **INV-ZONE-MERGE-06: the proof binds the signing zone's program id**
  - Covered by: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `zone_merge_rejects_a_proof_bound_to_another_zone` (the same zone fixture is deployed under two program IDs; a proof built for zone A is submitted through zone B's valid signer/config and fails with 7008 while the tree remains unchanged).
  - Kind: postcondition
  - Statement: the zone-merge public-input hash folds `Poseidon(low, high)` of the signing `zone_config.program_id` as its final element; a proof built for a different zone fails verification.
  - Location: `programs/shielded-pool/src/instructions/merge_zone/processor.rs:62-68` (`fn process_merge_zone_ix`), `merge/verify.rs:101-113` (`fn public_input_hash`, `Zone` arm)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (cross-zone merge prevention)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-ZONE-MERGE-07: zone merge verifies only against merge_zone_8_1**
  - Partial coverage: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `invalid_proofs_and_disabled_authority_are_atomic` (zeroed proof -> 7008; a real `merge_8_1` proof cross-submitted to zone merge is not tested)
  - Kind: precondition
  - Statement: `zone_merge_transact` verifies only against `merge_zone_8_1::VERIFYINGKEY`; a proof for the default `merge_8_1` circuit does not verify (the two key selections are mutually exclusive by owner-binding variant).
  - Location: `programs/shielded-pool/src/instructions/merge/verify.rs:70-73` (`fn verify`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-ZONE-MERGE-08: zone public-input shape is exactly 10 elements with no owner identity**
  - Partial coverage: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `zone_merge_consolidates_inputs` (successful end-to-end verification exercises the chain; no explicit element-count assertion)
  - Kind: state
  - Statement: the `zone_merge_transact` public-input hash chain contains exactly 10 elements (the shared 9-element prefix in the order nullifier-chain, output hash, utxo-root chain, nullifier-root chain, private_tx_hash, external_data_hash, tx_viewing_pk_lo, tx_viewing_pk_hi, ciphertext hash, then `zone_program_id`) and folds no signing or viewing key field.
  - Location: `programs/shielded-pool/src/instructions/merge/verify.rs:101-113` (`fn public_input_hash`)
  - Severity: High
  - Suggested test: property (client-side comparison); harness: `cargo test -p`

### Success Postconditions

- [x] **INV-ZONE-MERGE-09: merge_view_tag is single-use**
  - Covered by: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `zone_merge_view_tag_replay_is_rejected_atomically`
  - Kind: postcondition
  - Statement: after a successful `zone_merge_transact`, the `merge_view_tag` has been inserted into the nullifier queue exactly once, so the nullifier queue's `next_index` is exactly its value before plus 9 (8 nullifiers + 1 tag); a second `zone_merge_transact` reusing the same `merge_view_tag` returns Err.
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs:156-162` (`fn apply_tree`), `merge_zone/processor.rs:70-79`
  - Error: `ShieldedPoolError::NullifierTreeUpdateFailed = 7002`
  - Severity: Critical (replay protection)
  - Suggested test: negative (replay); harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-ZONE-MERGE-10: the emitted output is indexed by merge_view_tag**
  - Covered by: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `zone_merge_consolidates_inputs`
  - Kind: postcondition
  - Statement: after a successful `zone_merge_transact`, the emitted `GeneralEvent`'s single output carries `view_tag` exactly equal to the instruction's `merge_view_tag` (not an owner pubkey).
  - Location: `programs/shielded-pool/src/instructions/merge_zone/processor.rs:72-79` (`fn process_merge_zone_ix`), `merge/event.rs:28-32`
  - Severity: Medium
  - Suggested test: positive; harness: litesvm

- [x] **INV-ZONE-MERGE-11: external hash uses the zone-merge discriminator**
  - Covered by: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `zone_merge_rejects_a_default_merge_proof` (a valid discriminator-12 merge proof built from default-zone UTXOs is submitted unchanged through discriminator 13 and rejected atomically with 7008).
  - Kind: postcondition
  - Statement: the recomputed `external_data_hash` for `zone_merge_transact` uses `spp_instruction_discriminator` exactly 13 (`ZONE_MERGE_TRANSACT`), so a proof built for `merge_transact` (discriminator 12) with identical fields fails verification.
  - Location: `programs/shielded-pool/src/instructions/merge_zone/processor.rs:48-55` (`fn process_merge_zone_ix`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: High (cross-instruction replay)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)
