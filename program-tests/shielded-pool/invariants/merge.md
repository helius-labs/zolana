# Merge Invariants

Covers `MergeTransact` (tag 13) and `RingMergeTransact` (tag 16). Shared invariants
(expiry, pause, stale root, double-spend, rollback, external-hash domain separation)
live in `cross-cutting.md`.

SPEC_DIVERGENCE (resolved 2026-07-23): the spec previously described a variable input
count `N` and an oversized proof; `docs/spec.md` now matches the code: 8-, 24- and
52-in/1-out shapes and a vanilla Groth16 `a||b||c` proof with no BSB22
commitment (`program-libs/interface/src/instruction/instruction_data/merge_transact.rs`,
`docs/spec.md` "Merge Proof - Merge ZK Proof"). Post-PR164 the merge has no
`encrypted_utxo` field and no `merge_view_tag`, and padding slots publish derived
dummy nullifiers. Since the Certora M-03 fix the merge proof encrypts the output's
amount and mint for the owner and binds the ciphertext as public inputs, so the
owner rebuilds the output from the merge transaction alone, without holding any
of its inputs (INV-MERGE-29..31). The widest shape dropped from 54 to 52 inputs
so a full merge still fits one transaction with the ciphertext. The ciphertext is
now `output_encryption: MergeOutputEncryption`, a u8-tagged enum whose variant
is the scheme (PoseidonCtrV1, tag 1, keeps the former salt and ciphertext). The
registry record's `merge_encryption` replaces `merging_enabled` and must equal
that scheme on `merge_transact` (INV-MERGE-04). The ring merge proof no longer
constrains the ciphertext, and SPP does not check it on `merge_ring`
(INV-RING-MERGE-15).

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

- [x] **INV-MERGE-04: merging requires the owner's registered encryption scheme**
  - Covered by: `program-tests/spp-test-validator/tests/lifecycle.rs` `merge_rejects_an_owner_that_has_not_opted_in`, `eddsa_merge_rejects_an_owner_that_has_not_opted_in` (a `Disabled` record fails with 7017); `program-tests/user-registry/tests/wire_layout.rs` `merge_encryption_byte_reads_former_merging_flag` (bytes 0 and 1 decode as `Disabled` and `PoseidonCtrV1`, byte 2 is rejected). A mismatch between two non-`Disabled` schemes is not reachable while PoseidonCtrV1 is the only scheme.
  - Kind: precondition
  - Statement: `merge_transact` returns Err whenever the registry record's `merge_encryption` differs from the scheme of `output_encryption` (the processor maps each `MergeOutputEncryption` variant to its `MergeEncryptionScheme`). A `Disabled` record matches no variant and fails with the same error. A delegated merger therefore cannot choose the scheme. The record's scheme byte has the values of the former `merging_enabled: bool`, so existing records decode unchanged; a record with any other byte fails to decode (`InvalidUserRecord = 7018`, INV-MERGE-03).
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs:80-86` (`fn process_merge_transact_ix`), `program-libs/user-registry-interface/src/state.rs` (`MergeEncryptionScheme`)
  - Error: `ShieldedPoolError::MergeEncryptionSchemeMismatch = 7017`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [ ] **INV-MERGE-05: retired owner scheme is rejected**
  - Not applicable post-PR164, the registry record holds only the Ed25519 `owner` and merge instruction data selects no owner scheme.

- [x] **INV-MERGE-18: merge account layout — two trees, signer payer, system program**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `rejects_invalid_system_program_with_specific_error`
  - Kind: precondition
  - Statement: the `merge_transact` account layout is `input_tree` (writable), `output_tree` (writable), `payer` (signer), `user_record`, `system_program`, `program` (SPP), then one nullifier PDA per sent nullifier; the `ring_merge_transact` layout is `input_tree`, `output_tree`, `ring_config` (signer), `payer` (signer), `system_program`, `program` (SPP), then one nullifier PDA per sent nullifier; the system-program account must be the system program (it is kept in the account keys so the forester-fee Transfer CPI resolves) and the program account must be SPP (`ProgramError::IncorrectProgramId` otherwise).
  - Location: `programs/shielded-pool/src/instructions/merge/account.rs:19-36` (`fn validate_and_parse`), `merge_ring/account.rs:22-39`
  - Error: `ShieldedPoolError::InvalidSystemProgram = 7024`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-MERGE-17: a merge past the dummy-input capacity threshold fails at proof verification**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_dummy_inputs_after_capacity_threshold`
  - Kind: postcondition
  - Statement: when the input tree's `dummy_input_headroom()` is less than the merge's input count, the on-chain public input recomputes with the flag 0 while merge proofs are always built with `allow_dummy_inputs = true`, so `merge_transact`/`ring_merge_transact` fail pairing and roll back all queue insertions and appends.
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs` (`fn process_merge_core`, `allow_dummy_inputs` leg)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: High (availability)
  - Suggested test: negative (exists; crosses the threshold by moving the nullifier queue cursor in litesvm instead of a 4999-queue localnet setup); harness: litesvm

### Instruction Data Validation

- [x] **INV-MERGE-06: a supported merge shape is enforced at parse time**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_a_wrong_input_count_shape` (0 and 53 inputs), `merge_accepts_the_wide_shape_and_fails_only_on_the_proof` (52 inputs parse and reach verification), `merge_rejects_a_sent_zero_nullifier`; `program-tests/shielded-pool/tests/merge/functional.rs` `merge_with_compact_padding_spends_only_the_real_inputs`
  - Kind: precondition
  - Statement: `merge_transact` returns Err unless `nullifiers.len()` is between 1 and `MAX_MERGE_INPUTS` (52) and no sent nullifier is 0 (`ZeroInputNullifier = 7078`). `merge_circuit_width` picks the narrowest merge circuit (8, 24 or 52) that holds the sent nullifiers, and the slots past them are compact padding. The instruction carries one `utxo_tree_root_index` / `nullifier_tree_root_index` pair for every input.
  - Location: `program-libs/interface/src/instruction/instruction_data/merge_transact.rs:106-115` (`fn validate_shape`), `programs/shielded-pool/src/instructions/merge/processor.rs:31-32`
  - Error: `ShieldedPoolError::InvalidMergeShape = 7019`
  - Severity: High
  - Suggested test: negative + fuzz; harness: mollusk unit

- [ ] **INV-MERGE-07: the output blob must be verifiably encrypted**
  - Not applicable post-PR164 (the `encrypted_utxo` field and the `MERGE_ENCRYPTED_UTXO_*` constants were removed, and SPP parses no output blob). The covering `merge_rejects_a_wrong_encrypted_output_scheme` test was removed with the field. The Certora M-03 output ciphertext is a different design: the fixed-size `output_encryption` instruction field, included in the public-input hash on `merge_transact` (INV-MERGE-29, INV-MERGE-30), which the indexer wraps in `VerifiablyEncrypted` (INV-MERGE-14); on `merge_ring` it is unverified and wrapped in `Encrypted` (INV-RING-MERGE-13, INV-RING-MERGE-15).

- [x] **INV-MERGE-30: a non-canonical output ciphertext element is rejected before the proof**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_a_non_canonical_ciphertext_element` (each of the three elements set to `0xff..ff` fails with 7082 and leaves the tree unchanged)
  - Kind: precondition
  - Statement: `merge_transact` returns Err before the registry check and the proof whenever any `output_encryption` ciphertext element is not a canonical BN254 scalar (big-endian value `>= p`, `MergeOutputEncryption::is_canonical`), so no element can alias the canonical value in the public-input hash. The PoseidonCtrV1 `salt` needs no check: 16 bytes are below the modulus. `merge_ring` does not run this check: its proof does not include the ciphertext (INV-RING-MERGE-15).
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs:68-70` (`fn process_merge_transact_ix`), `program-libs/interface/src/instruction/instruction_data/merge_transact.rs` (`fn MergeOutputEncryption::is_canonical`)
  - Error: `ShieldedPoolError::NonCanonicalMergeCiphertext = 7082`
  - Severity: Medium
  - Suggested test: negative per element; harness: litesvm

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
  - Not applicable post-PR164 (the merge encryption flow was restructured: the output ciphertext is keyed by the owner's nullifier secret and the first nullifier (INV-MERGE-29), so no viewing-key public input exists; F-06 re-reviewed 2026-07-27 and closed as MOOT -- no recipient viewing key enters any circuit KDF anymore).

- [ ] **INV-MERGE-10: the ciphertext hash is recomputed on-chain**
  - Not applicable post-PR164 (no ciphertext hash exists: the Certora M-03 output ciphertext enters the `merge_transact` public-input hash element by element, INV-MERGE-29, after the canonicality check of INV-MERGE-30).

- [x] **INV-MERGE-11: the merge proof is vanilla Groth16 with the variant's key**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `default_rail_merge_rejects_a_zeroed_proof_exactly` (7008), `default_rail_merge_rejects_undecompressable_proof_points_exactly` (7007); positive side at both declared counts by `program-tests/shielded-pool/tests/merge/functional.rs` `merge_collects_the_exact_forester_fee_from_the_payer` (24 inputs) and `merge_verifies_the_wide_shape_on_chain` (52 inputs), each proving with the workspace prover and requiring the program to accept
  - Kind: precondition
  - Statement: `merge_transact` decodes the fixed 128-byte proof as `a||b||c` (no commitment) and verifies it only against the key for its owner binding and its declared input count. On the default rail the `output_encryption` scheme selects the key set first, then the width: PoseidonCtrV1 uses `merge_8_1` / `merge_24_1` / `merge_52_1`. The ring rail uses `merge_ring_8_1` / `merge_ring_24_1` / `merge_ring_52_1` regardless of `output_encryption`. Merge instruction data has no circuit selector, so a count with no key is refused rather than verified against another width's key. A proof whose points fail decompression returns the encoding error, a non-verifying proof returns the verification error.
  - Location: `programs/shielded-pool/src/instructions/merge/verify.rs:83-131` (`fn verify`, `fn verifying_key`)
  - Error: `ShieldedPoolError::InvalidTransactProofEncoding = 7007` / `TransactProofVerificationFailed = 7008`
  - Severity: Critical
  - Suggested test: negative both errors; harness: mollusk unit

- [ ] **INV-MERGE-12: registry public-input shape is the 7-element prefix plus both owner keys and the scheme's ciphertext elements**
  - Partial coverage: `program-tests/spp-test-validator/tests/lifecycle.rs` `eddsa_merge_covers_every_merge_width` (successful end-to-end verification exercises the chain; no explicit element-count/order assertion); `prover/server/circuits/spp_merge/ciphertext_test.go` `TestMergeCiphertextIsTheLastPublicInputs` pins the position of the last four elements in the circuit preimage only
  - Kind: state
  - Statement: the `merge_transact` public-input hash chains the 7-element prefix (nullifier-chain, output hash, tree-slot chain, output tree id, `private_tx_hash`, `external_data_hash`, `allow_dummy_inputs`), then folds `signing_pk_field` and `nullifier_pk` from the registry record, then the elements `MergeOutputEncryption::append_public_inputs` appends for the scheme. PoseidonCtrV1 appends the right-aligned `salt` and the three `ciphertext` elements, 13 elements in total; a scheme appends at most `MAX_MERGE_OUTPUT_ENCRYPTION_PUBLIC_INPUTS` (4) elements.
  - Location: `programs/shielded-pool/src/instructions/merge/verify.rs:148-187` (`fn public_input_hash`, `Default` arm), `program-libs/interface/src/instruction/instruction_data/merge_transact.rs` (`fn MergeOutputEncryption::append_public_inputs`)
  - Severity: High
  - Suggested test: property (compare against client-side computation in `sdk-libs/keypair`); harness: `cargo test -p`

- [x] **INV-MERGE-29: the default merge public-input hash includes the ciphertext of exactly the output's amount and mint**
  - Covered by: `prover/server/circuits/spp_merge/ciphertext_test.go` `TestMergeCiphertextIsTheLastPublicInputs`, `TestMergeCircuitRejectsTamperedCiphertext`, `TestMergeCircuitBindsTheSalt` (default rail); `program-tests/shielded-pool/tests/merge/functional.rs` `merge_rejects_a_tampered_output_ciphertext_or_salt` (a real proof with one bit flipped in each ciphertext element or in the salt fails with 7008 and leaves the tree unchanged)
  - Kind: postcondition
  - Statement: on `merge_transact` with PoseidonCtrV1 the merge public-input hash folds `salt` and the three `ciphertext` elements of `output_encryption` from instruction data, and the default circuit constrains `ciphertext[i] = plaintext[i] + Poseidon("TMOC", merge_output_key, salt, i)` with `plaintext = [output.amount, mint_chunk_0, mint_chunk_1]` and `merge_output_key = Poseidon("TMOK", nullifier_secret, first_nullifier)`; the output `asset` is derived from the same mint chunks. A merger or relayer therefore cannot publish a ciphertext that differs from the output it appended, nor change the salt, without failing verification. The ring rail has no such binding (INV-RING-MERGE-15).
  - Location: `prover/server/circuits/spp_merge/shared/derivation.go:44-71` (`MergeOutputKey`, `MergeOutputCiphertext`), `prover/server/circuits/spp_merge/default.go` (`fn Circuit.outputEncryption`), `programs/shielded-pool/src/instructions/merge/verify.rs:148-187` (`fn public_input_hash`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: High (funds lock: an unopenable output)
  - Suggested test: negative (tampered element, tampered salt); harness: Go circuit tests + program-tests integration (`cargo test-sbf`)

### Success Postconditions

- [ ] **INV-MERGE-13: one nullifier per sent input is inserted and one leaf appended**
  - Partial coverage: `program-tests/spp-test-validator/tests/lifecycle.rs` `eddsa_merge_covers_every_merge_width` (output appended and inputs spent); `program-tests/shielded-pool/tests/merge/functional.rs` `merge_with_compact_padding_spends_only_the_real_inputs` (the exact queue and tree `next_index` deltas, and no nullifier PDA for compact padding; the appended leaf value is not asserted)
  - Kind: postcondition
  - Statement: after a successful `merge_transact`, the nullifier queue's `next_index` is exactly its value before plus `nullifiers.len()` (compact padding inserts nothing), and the UTXO tree's `next_index` is exactly its value before plus 1 with the appended leaf equal to `output_utxo_hash`.
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs:141-172` (`fn apply_input_tree`), `merge/processor.rs:174-189` (`fn apply_output_tree`)
  - Severity: Critical
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-MERGE-14: successful merge emits exactly one Merge GeneralEvent tagged by the owner key**
  - Partial coverage: `program-tests/spp-test-validator/tests/lifecycle.rs` `eddsa_merge_covers_every_merge_width` (output rediscovered by owner signing-key tag; nullifier sequence numbers, verbatim `data`, and the empty `spl_transfers` list unasserted)
  - Kind: postcondition
  - Statement: after a successful `merge_transact`, exactly one self-CPI `EmitEvent` inner instruction is recorded whose `GeneralEvent` contains the sent nullifiers with assigned queue sequence numbers and exactly one output whose `view_tag` is the owner's signing-key tag from the registry record and whose rebuilt `data` is `VerifiablyEncrypted(6 || salt || ciphertext)` from the PoseidonCtrV1 `output_encryption`, and an empty `spl_transfers` list (no public movements).
  - Location: `programs/shielded-pool/src/instructions/merge/event.rs:15-42` (`fn build_merge_event`), `merge/account.rs:58-89`, `program-libs/event/src/merge_output.rs` (`fn encode_merge_output_data`), `sdk-libs/event/src/reconstruct.rs`
  - Severity: Medium (owner rediscovery on sync)
  - Suggested test: positive; harness: litesvm

- [x] **INV-MERGE-19: merge collects the tree's insertion fee for every queued nullifier and credits the fee balance**
  - Covered by: `program-tests/shielded-pool/tests/merge/functional.rs` `merge_collects_the_exact_forester_fee_from_the_payer` (real on-chain merge proof; the input tree gains exactly `nullifiers.len() * fees.fee_per_nullifier` lamports read from the tree header, its `fee_balance` grows by the same amount, the payer loses exactly the signature fee plus that amount, every other account byte-identical); also `program-tests/spp-test-validator/tests/lifecycle.rs` `actor_owned_merge_covers_every_merge_width` and `eddsa_merge_covers_every_merge_width` via the shared merge action, which asserts the payer loses and the input tree gains exactly `nullifiers.len()` × the tree's per-nullifier fee (`spp-test-validator/tests/actions/merge.rs`)
  - Kind: postcondition
  - Statement: while queueing the inputs the input tree's `fee_balance` increases by exactly `fee = nullifiers.len()` × `input_tree.fees.fee_per_nullifier` (the schedule stored in the tree header; no constant fee exists any more), and the payer then transfers exactly `fee` lamports to the input tree via one System-Program CPI before the PDAs are funded; a fee-computation overflow returns 7022; a zero fee (all-zero schedule) skips the CPI; the tree must be writable and program-owned else 7001.
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs` (`fn process_merge_core`: `credit_insertion_fee(nullifiers.len())`, `create_nullifier_pdas`), `nullifier_pda/create.rs` (`fn create_nullifier_pdas`, `fn collect_forester_fee`), `program-libs/tree/src/fees.rs` (`fn TreeAccount::credit_insertion_fee`)
  - Error: `ShieldedPoolError::InvalidForesterFee = 7022`
  - Severity: High (fund movement)
  - Suggested test: none remaining (exact deltas pinned; 7022 overflow legs covered by `program-tests/shielded-pool/tests/tree/contract.rs` `forester_fee_overflow_is_invalid_forester_fee`, `reimbursement_recipient_balance_overflow_is_invalid_forester_fee`)

### Frame Conditions

- [x] **INV-MERGE-15: merge modifies only the two tree accounts and the payer**
  - Covered by: `program-tests/shielded-pool/tests/merge/functional.rs` `merge_collects_the_exact_forester_fee_from_the_payer` (every account other than the trees and the payer byte-identical); `program-tests/spp-test-validator/tests/lifecycle.rs` `actor_owned_merge_covers_every_merge_width` and `eddsa_merge_covers_every_merge_width` via the shared merge action, which asserts the payer loses exactly one `fees.fee_per_nullifier` of the tree per sent nullifier, the input tree gains exactly that amount, and the read-only user record is unchanged around every successful merge (`spp-test-validator/tests/actions/merge.rs`); the remaining instruction account is the system program, which cannot be modified by the program.
  - Kind: frame
  - Statement: after a successful `merge_transact`, every account other than the two tree accounts (`input_tree`, `output_tree`) and the `payer` has unchanged data and unchanged lamports (no settlement exists on this instruction); the only lamport movement is the insertion fee (`nullifiers.len()` × `input_tree.fees.fee_per_nullifier`, credited to the tree's `fee_balance`; zero under the sponsored default, which skips the transfer) from the payer to the input tree; in particular the `user_record` is read-only.
  - Location: `programs/shielded-pool/src/instructions/merge/processor.rs` (`fn process_merge_transact_ix`, `fn process_merge_core`: `credit_insertion_fee`, `create_nullifier_pdas`), `nullifier_pda/create.rs` (`fn collect_forester_fee`)
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

### Owner Recovery

- [x] **INV-MERGE-31: the owner decrypts a default merge that includes a note it never saw**
  - Covered by: `sdk-libs/transaction/tests/decryption.rs` `a_merge_of_a_note_the_owner_never_saw_decrypts_with_the_whole_total` (a merge whose first input is a note the owner never received decrypts to the whole total, 807 = 777 + 30, as the owner's only spendable UTXO)
  - Kind: postcondition
  - Statement: for any accepted `merge_transact` of the owner's notes, the owner's wallet, given only the merge transaction and its own keys, derives `merge_output_key` and `merge_output_blinding` from the nullifier secret and the first nullifier, decrypts the amount and mint, rebuilds the output with `data_hash = 0` and the transaction's ring fields, and obtains a UTXO whose hash equals the published `output_utxo_hash`; it holds none of the merge's inputs to do so (Certora M-03). A decryption with an element out of range (`amount >= 2^64`, `mint_chunk_0 >= 2^248`, `mint_chunk_1 >= 2^8`) or a hash mismatch is not the owner's output. On `merge_ring` the ciphertext is unverified, so the owner may fail to decrypt the output (INV-RING-MERGE-15); the wallet's hash check rejects a wrong ciphertext.
  - Location: `sdk-libs/transaction/src/decrypt.rs:436-496` (`fn decode_merge`), `sdk-libs/transaction/src/instructions/merge/serialization.rs` (`MergeOutputPlaintext::decrypt`, `MergeOutputPlaintext::into_utxo`)
  - Severity: High (funds lock)
  - Suggested test: positive (undisclosed first input) + negative (another wallet's merge does not decrypt); harness: `cargo test -p zolana-transaction`

## RingMergeTransact

### Account Constraints

- [x] **INV-RING-MERGE-01: ring_config must sign**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_ring_rejects_an_unsigned_ring_config`
  - Kind: precondition
  - Statement: `ring_merge_transact` can only succeed when the third account (`ring_config`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/merge_ring/account.rs:26` (`fn validate_and_parse`)
  - Error: account-checks signer error
  - Severity: Critical (ring authorization)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-RING-MERGE-02: ring_config must be a valid SPP-owned RingConfig**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_ring_rejects_a_ring_config_with_a_wrong_owner`, `merge_ring_rejects_a_ring_config_with_a_wrong_discriminator`
  - Kind: precondition
  - Statement: the `ring_config` account must be owned by the shielded-pool program with `data_len` exactly 69 and discriminator 4; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/ring_config/loader.rs:14-20` (`fn load_ring_config`), `merge_ring/account.rs:27`
  - Error: `ShieldedPoolError::InvalidRingConfig = 7014`
  - Severity: Critical
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-RING-MERGE-14: a paused ring cannot merge**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_ring_rejects_a_paused_ring_config`
  - Kind: precondition
  - Statement: after signer and structural validation, `ring_merge_transact` returns `RingPaused` whenever `ring_config.paused` is nonzero and performs no state mutation.
  - Location: `programs/shielded-pool/src/instructions/ring_config/loader.rs` (`fn load_active_ring_config`), `merge_ring/account.rs` (`fn validate_and_parse`)
  - Error: `ShieldedPoolError::RingPaused = 7042`
  - Severity: Critical
  - Suggested test: negative; harness: litesvm

- [x] **INV-RING-MERGE-03: payer must sign**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_ring_rejects_an_unsigned_payer`
  - Kind: precondition
  - Statement: `ring_merge_transact` can only succeed when the fourth account (`payer`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/merge_ring/account.rs:28` (`fn validate_and_parse`)
  - Error: account-checks signer error
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-RING-MERGE-04: no registry opt-in is consulted**
  - Covered by: `program-tests/ring-test-program/tests/ring_lifecycle.rs` `ring_merge_consolidates_inputs`
  - Kind: precondition
  - Statement: `ring_merge_transact` succeeds without a `user_record` account and regardless of any registry `merge_encryption` scheme, and whatever scheme its embedded `output_encryption` names; authorization is exactly the ring_config signature.
  - Location: `programs/shielded-pool/src/instructions/merge_ring/processor.rs:25-70` (`fn process_merge_ring_ix`)
  - Severity: High
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

### Instruction Data Validation

- [x] **INV-RING-MERGE-05: shape checks equal merge_transact's**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_ring_rejects_a_wrong_input_count_shape_exactly` (7019)
  - Kind: precondition
  - Statement: `ring_merge_transact` rejects, exactly as INV-MERGE-06, every embedded merge body whose element vectors are not length 8.
  - Location: `program-libs/interface/src/instruction/instruction_data/merge_ring.rs` (`MergeRingIxDataRef::from_bytes`), `merge_ring/processor.rs`
  - Error: `ShieldedPoolError::InvalidMergeShape = 7019`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Proof Binding

- [x] **INV-RING-MERGE-06: the proof binds the signing ring's program id**
  - Covered by: `program-tests/ring-test-program/tests/ring_lifecycle.rs` `ring_merge_rejects_a_proof_bound_to_another_ring` (the same ring fixture is deployed under two program IDs; a proof built for ring A is submitted through ring B's valid signer/config and fails with 7008 while the tree remains unchanged).
  - Kind: postcondition
  - Statement: the ring-merge public-input hash folds `Poseidon(low, high)` of the signing `ring_config.program_id` as its final element; a proof built for a different ring fails verification.
  - Location: `programs/shielded-pool/src/instructions/merge_ring/processor.rs:42-52` (`fn process_merge_ring_ix`), `merge/verify.rs:101-110` (`fn public_input_hash`, `Ring` arm)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (cross-ring merge prevention)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-RING-MERGE-07: ring merge verifies only against the merge_ring keys**
  - Partial coverage: `program-tests/ring-test-program/tests/ring_lifecycle.rs` `invalid_proofs_and_disabled_authority_are_atomic` (zeroed proof -> 7008; a real `merge_24_1` proof cross-submitted to ring merge is not tested)
  - Kind: precondition
  - Statement: `ring_merge_transact` verifies only against `merge_ring_8_1::VERIFYINGKEY`, `merge_ring_24_1::VERIFYINGKEY` or `merge_ring_52_1::VERIFYINGKEY`, by input count; the embedded `output_encryption` scheme does not take part in the selection. A proof for a default-rail key (`merge_8_1`, `merge_24_1` or `merge_52_1` for PoseidonCtrV1) does not verify (the two key selections are mutually exclusive by owner-binding variant).
  - Location: `programs/shielded-pool/src/instructions/merge/verify.rs:110-131` (`fn verifying_key`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-RING-MERGE-08: ring public-input shape is the 7-element prefix plus ring data and ring id**
  - Partial coverage: `program-tests/ring-test-program/tests/ring_lifecycle.rs` `ring_merge_consolidates_inputs` (successful end-to-end verification exercises the chain; no explicit element-count assertion); `prover/server/circuits/spp_merge/ring_test.go` `TestMergeRingPublicInputsHaveNoCiphertextTail` (the circuit solves with the 9-element preimage and rejects one with a salt and ciphertext appended)
  - Kind: state
  - Statement: the `ring_merge_transact` public-input hash chains the 7-element prefix (as in INV-MERGE-12), then folds `output_ring_data_hash` and `ring_program_id`: 9 elements in total. It folds no signing or viewing key field (owner identity is omitted by design) and no `output_encryption` element.
  - Location: `programs/shielded-pool/src/instructions/merge/verify.rs:148-187` (`fn public_input_hash`, `Ring` arm), `prover/server/circuits/spp_merge/ring.go` (`fn RingCircuit.Define`)
  - Severity: High
  - Suggested test: property (client-side comparison); harness: `cargo test -p`

### Success Postconditions

- [ ] **INV-RING-MERGE-09: merge_view_tag is single-use**
  - Not applicable post-PR164 (the `merge_view_tag` field was removed; replay protection comes from the queued proof-bound input nullifiers themselves -- INV-RING-MERGE-12).

- [x] **INV-RING-MERGE-10: the emitted output is indexed by the first input nullifier**
  - Covered by: `program-tests/ring-test-program/tests/ring_lifecycle.rs` `ring_merge_consolidates_inputs`
  - Kind: postcondition
  - Statement: after a successful `ring_merge_transact`, the emitted `GeneralEvent`'s single output is indexed by the first input's published nullifier (there is no instruction-supplied tag).
  - Location: `programs/shielded-pool/src/instructions/merge_ring/processor.rs:54-69` (`fn process_merge_ring_ix`), `merge/event.rs:15-42`
  - Severity: Medium
  - Suggested test: positive; harness: litesvm

- [x] **INV-RING-MERGE-11: external hash uses the ring-merge discriminator**
  - Covered by: `program-tests/ring-test-program/tests/ring_lifecycle.rs` `ring_merge_rejects_a_default_merge_proof` (a valid discriminator-13 merge proof built from default-ring UTXOs is submitted unchanged through discriminator 16 and rejected atomically with 7008).
  - Kind: postcondition
  - Statement: the recomputed `external_data_hash` for `ring_merge_transact` uses `spp_instruction_discriminator` exactly 16 (`RING_MERGE_TRANSACT`), so a proof built for `merge_transact` (discriminator 13) with identical fields fails verification.
  - Location: `programs/shielded-pool/src/instructions/merge_ring/processor.rs:34-40` (`fn process_merge_ring_ix`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: High (cross-instruction replay)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-RING-MERGE-13: ring merge event publishes the output ring_data_hash**
  - Partial coverage: `program-tests/ring-test-program/tests/ring_lifecycle.rs` `ring_merge_consolidates_inputs` (successful ring merge exercises the emit; the output `data` payload is not field-asserted)
  - Kind: postcondition
  - Statement: the rebuilt `GeneralEvent`'s single output contains `Encrypted(6 || output_ring_data_hash || salt || ciphertext)` as its `data` payload (default merge: `VerifiablyEncrypted` without the ring data hash). The outer tag is `Encrypted` because SPP did not verify the ciphertext (INV-RING-MERGE-15). The public-input hash includes the same `output_ring_data_hash` (INV-RING-MERGE-08), so a relayer cannot alter it; it does not include the salt or ciphertext.
  - Location: `programs/shielded-pool/src/instructions/merge_ring/processor.rs:57-69` (`fn process_merge_ring_ix`), `merge/event.rs:15-42` (`fn build_merge_event`), `program-libs/event/src/merge_output.rs` (`fn encode_merge_output_data`)
  - Severity: Medium (wallet reconstruction)
  - Suggested test: positive (assert the event output `data` equals the encoding above); harness: litesvm

- [ ] **INV-RING-MERGE-15: SPP does not verify the ring merge output ciphertext**
  - Partial coverage: `prover/server/circuits/spp_merge/ring_test.go` `TestMergeRingPublicInputsHaveNoCiphertextTail` (circuit side only; no program-level test submits a ring merge with a wrong ciphertext)
  - Kind: state (accepted risk)
  - Statement: `ring_merge_transact` decodes `merge.output_encryption` with the instruction data but does not compare its scheme with a registry record, does not check its elements for canonicality, and does not include it in the public-input hash; the ring merge circuit does not constrain a ciphertext. A ring that needs a recoverable merge output must enforce the ciphertext in its own program before the CPI. The custom-ring rails do not, so a holder of the owner's nullifier secret (for example, an operator that opened the escrowed nullifier key) can merge a note the owner cannot open with a ciphertext that does not decrypt to the output. The owner's hash check (INV-MERGE-31) rejects that ciphertext, and recovery leaves the merged note unopened.
  - Location: `programs/shielded-pool/src/instructions/merge_ring/processor.rs` (`fn process_merge_ring_ix`), `programs/shielded-pool/src/instructions/merge/verify.rs` (`MergeOwnerBinding::Ring`), `prover/server/circuits/spp_merge/ring.go`
  - Severity: Medium (accepted: a ring merge output can be unrecoverable from its ciphertext)
  - Suggested test: positive (a ring merge with a ciphertext that does not match the output succeeds and its event uses `Encrypted`); harness: program-tests integration (`cargo test-sbf`)

### Nullifier Integrity

- [x] **INV-RING-MERGE-12: merge_ring queues exactly the proof-bound input nullifiers**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` shape tests; compile-level absence of the removed merge_view_tag field in `MergeRingIxData` (`program-libs/interface/src/instruction/instruction_data/merge_ring.rs`)
  - Kind: postcondition
  - Statement: after a successful `ring_merge_transact`, exactly the proof's 8 input nullifiers are queued and nothing else: the single-use `merge_view_tag` field no longer exists, the emitted output is indexed by the first input nullifier, and `output_ring_data_hash` is proof-bound (eliminates the unvalidated-tag queue-poisoning class, F-02/F-09).
  - Location: `programs/shielded-pool/src/instructions/merge_ring/processor.rs:57-69` (`fn process_merge_ring_ix`), `programs/shielded-pool/src/instructions/merge/verify.rs:23-27, 102-110` (`MergeOwnerBinding::Ring`)
  - Error: `ShieldedPoolError::NullifierTreeUpdateFailed = 7002` (replay), `TransactProofVerificationFailed = 7008` (binding mismatch)
  - Severity: Critical
  - Suggested test: negative (replay) + negative (foreign-ring proof); harness: program-tests integration (`cargo test-sbf`)

## Merge Cache

Both tags may carry a `cache_slot: Option<u8>` plus a trailing `CacheAccount` PDA and write-authority signer
(`program-libs/interface/src/state/cache.rs`), so these entries apply to
`MergeTransact` and `RingMergeTransact` alike and keep the `INV-MERGE` prefix for
that reason. Three mechanisms are deliberately separate: the write authority
governs insertion, nullification governs spending, and the timeout governs
closure. The cache binds no owner. The
cached *spend* rail belongs to `Transact` and `RingTransact`: every owner-signed
circuit folds a cache selection into its public input hash whether or not a cache
is supplied, so a cached spend verifies against its rail's ordinary verifying key
and no standalone cached circuit exists
(`program-libs/interface/src/verifying_keys/circuit.rs`, `fn CircuitId::uncached`).
`CircuitId` carries one cached twin per owner-signed rail --
`ConfidentialEddsaCached`, `ConfidentialRingEddsaCached` -- and
`RingAuthority` has none, because its circuit binds no selection. INV-MERGE-23
records why the spend needs no identity check; its `CacheSlotEmpty`,
`InvalidCacheBitmap` and `InvalidCacheRootIndex` legs are pinned there rather
than by entries of their own.

### Write Authorization

- [x] **INV-MERGE-20: a merge writes a cache only with its write authority's signature**
  - Covered by: `program-tests/shielded-pool/tests/cache/functional.rs` `merge_writes_the_bound_slot` and `ring_merge_writes_the_bound_slot` (`reject_cache_sponsor_write`: the rent sponsor signing in the writer's place fails with 7076 and leaves every writable account unchanged; the same proof then succeeds with the writer and a distinct payer), `program-tests/shielded-pool/tests/cache/contract.rs` `merge_rejects_invalid_writes_and_rolls_back_overwrites` (out-of-range slot -> 7069, expired cache -> 7073, each with the cache and tree unchanged)
  - Kind: precondition
  - Statement: `merge_transact` and `merge_ring` load a named cache once, before the proof, and return Err unless the signer immediately after it equals the stored `write_authority`, the cache has not expired and the slot is in range. No owner is compared on either rail: the write authority alone decides which verified outputs reach the slots, for registry owners of either curve and for policy-ring users. The default merge proof still binds the registered signing identity and nullifier public key (INV-MERGE-12), so the output it writes belongs to the registry owner.
  - Location: `programs/shielded-pool/src/instructions/merge/cache.rs` (`fn parse_cache_accounts`, `fn load_merge_cache`), `instructions/cache/write.rs` (`fn CacheWrite::load`)
  - Error: `ShieldedPoolError::CacheWriteAuthorityMismatch = 7076`, `CacheExpired = 7073`, `InvalidCacheSlot = 7069`
  - Severity: Critical (cache takeover)
  - Suggested test: negative; harness: litesvm + program-tests integration (`cargo test-sbf`)

- [x] **INV-MERGE-21: a cache accepts only outputs appended to its own tree**
  - Covered by: `program-tests/shielded-pool/tests/cache/functional.rs` `merge_rejects_a_cache_for_another_tree` (real proof, 7071, the cache is byte-identical afterwards), `program-tests/shielded-pool/tests/cache/queued.rs` `ten_proofs_in_parallel_then_sequential_splits_and_delayed_spends` (a transact write to a cache retagged to another tree -> 7071)
  - Kind: precondition
  - Statement: every write compares the cache's `tree_id` with the output tree before the proof is verified, on both merge rails and on transact. A cached spend proves its commitments under the cache's tree (INV-MERGE-23), so a commitment from another tree could never be spent from the slot.
  - Location: `programs/shielded-pool/src/instructions/cache/write.rs` (`fn CacheWrite::check_output_tree`), `merge/processor.rs` (`fn process_merge_core`), `transact/cache.rs` (`fn check_cache_output_tree`)
  - Error: `ShieldedPoolError::CacheTreeMismatch = 7071`
  - Severity: High
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-MERGE-22: a proof names its cache destination**
  - Covered by: `program-libs/interface/tests/merge_shape.rs` `cache_mode_address_and_slot_are_bound_by_both_merge_hashes` (both merge tags, every address and slot change moves the external data hash), `sdk-libs/instruction/tests/cache.rs` `cache_write_binding_commits_to_destination_writes_and_external_data`, `program-tests/shielded-pool/tests/cache/queued.rs` `ten_proofs_in_parallel_then_sequential_splits_and_delayed_spends` (a proven transact redirected to another cache or given other write slots -> 7008, atomically)
  - Kind: precondition
  - Statement: the merge rails fold the cache address and slot into `MergeExternalDataHash`, and transact folds the cache address and its `write_slots` pairs into its external data hash (`bind_cache_write`), so a relayer holding the writer's signature still cannot move a proven output to another cache or slot. A read-only transact binds no destination and keeps its original preimage.
  - Location: `program-libs/interface/src/instruction/instruction_data/merge_transact.rs` (`MergeExternalDataHash`), `program-libs/interface/src/state/cache.rs` (`fn bind_cache_write`), `programs/shielded-pool/src/instructions/transact/cache.rs` (`fn bind_cache_write`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: High
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-MERGE-23: the cache substitutes for the inclusion proof, never for authority**
  - Covered by: `program-tests/shielded-pool/tests/cache/functional.rs` `transact_spends_cached_commitments_without_mutating_the_cache` (real cached spend leaves the complete account unchanged even after expiry, appends outputs and queues nullifiers, and rejects replay) and `a_cached_spend_rejects_every_broken_cache_binding` (one proven instruction, each binding broken in turn: a dropped trailing cache account -> 7009, an emptied selected slot -> 7068, and a cache retagged to another tree -> 7008, with every refused spend preserving the cache); plus `program-tests/shielded-pool/tests/transact/validate_circuit.rs` `a_cached_selector_must_fit_the_inputs_the_outputs_and_the_cache` (7070 on both the confidential and ring twins) and `a_cached_selector_is_accepted_exactly_where_its_rail_is` (each cached twin is accepted by its own instruction tag and by no other, 7035)
  - Kind: state
  - Statement: The write-authority signature authorizes insertion only, because a merge output has no nullifier yet and nothing else could authorize placing it in a slot. Spending is authorized by the proof instead: the selected commitments are chained into the transact public-input hash and the circuit independently requires ownership and a valid nullifier for each selected input, so referencing another party's cache forces you to spend their UTXO. That argument is the same on every owner-signed rail, which is why each of them binds the selection and none of them needs a cached circuit of its own. A selection that reads no input publishes the uncached selection, so a write-only selector's public inputs equal those of a spend without a cache. The spend path consequently checks no identity and no expiry; its two checks are deliberately not ownership checks -- `CacheTreeMismatch` because the commitments stand in for that tree's inclusion, `CacheSlotEmpty` because the bitmap selected a slot nothing ever wrote.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs` (`fn assign_cached_inputs`), `transact/tree.rs` (`fn resolve_input_tree_slot`), `program-libs/interface/src/state/cache.rs` (`fn cached_input_fields`)
  - Error: `ShieldedPoolError::CacheTreeMismatch = 7071`, `CacheSlotEmpty = 7068`
  - Severity: Critical (double-spend boundary)
  - Suggested test: negative; harness: litesvm

- [x] **INV-MERGE-24: overwrites are writer-authorized and reads precede writes**
  - Covered by: `program-tests/shielded-pool/tests/cache/queued.rs` `ten_proofs_in_parallel_then_sequential_splits_and_delayed_spends`; `merge_writes_the_bound_slot` and `ring_merge_writes_the_bound_slot` exercise overwriting with a payer independent of the writer.
  - Kind: state
  - Statement: a cache has no frozen or spent flag. Only an explicit write-authority signer can replace slots, and every replacement comes from a verified output with the correct tree binding. Transact loads the cache once, writable exactly when it writes, reconstructs its input commitments from the contents before any write, and checks the writer, expiry and tree before the proof. Cache writes bind the destination address and bitmap through external data; any later proof or settlement failure rolls back all mutations. Nullifiers protect both cached and tree spends.
  - Error: `CacheWriteAuthorityMismatch`, `CacheExpired`, `CacheTreeMismatch`, `TransactProofVerificationFailed`
  - Severity: Critical

### Lifecycle

- [x] **INV-MERGE-25: create is permissionless and its address belongs to the signing sponsor**
  - Covered by: `program-tests/shielded-pool/tests/cache/contract.rs` `create_is_idempotent_and_close_refunds_sponsor` and `create_is_permissionless_and_scoped_to_the_signing_sponsor` (a second sponsor reusing the nonce lands at a different address and leaves the first untouched)
  - Kind: precondition
  - Statement: `create_cache` takes `payer` (signer, stored as `rent_sponsor`), `cache` (writable) and the system program, with no owner and no `ring_config` signer, and derives the PDA from `[CACHE_SEED, rent_sponsor, nonce]` with a canonical bump. Because the sponsor signs, no third party can create that address at all, so nobody can pre-create a conflicting configuration to block a legitimate create.
  - Location: `programs/shielded-pool/src/instructions/cache/create.rs` (`fn process_create_cache`), `instructions/shared.rs` (`fn verify_pda`)
  - Error: `ShieldedPoolError::InvalidCache = 7066`
  - Severity: High (availability)
  - Suggested test: positive + negative; harness: litesvm

- [x] **INV-MERGE-26: `tree_id`, `expires_at`, `rent_sponsor` and `write_authority` are immutable**
  - Covered by: `program-tests/shielded-pool/tests/cache/contract.rs` `create_and_close_reject_unauthorized_configuration` (`tree_id`, `expires_at` and `write_authority` mismatches -> 7067)
  - Kind: state
  - Statement: a repeated `create_cache` on an existing account compares `write_authority`, `tree_id` and `expires_at` and returns Err on any difference, and it never compares or resets `utxo_hashes`. The derivation already fixes `rent_sponsor` and the bump. A re-send can therefore neither extend the timeout nor clear the cache.
  - Location: `programs/shielded-pool/src/instructions/cache/create.rs` (`fn process_create_cache`)
  - Error: `ShieldedPoolError::CacheConfigMismatch = 7067`
  - Severity: High
  - Suggested test: negative per field; harness: litesvm

- [x] **INV-MERGE-27: an expired cache accepts no further writes**
  - Covered by: `program-tests/shielded-pool/tests/cache/contract.rs` `merge_rejects_invalid_writes_and_rolls_back_overwrites` (expired case -> 7073), `program-tests/shielded-pool/tests/cache/queued.rs` `ten_proofs_in_parallel_then_sequential_splits_and_delayed_spends` (expired transact write -> 7073) and `program-tests/shielded-pool/tests/cache/contract.rs` `create_is_permissionless_and_scoped_to_the_signing_sponsor` (an `expires_at` that is not in the future -> 7075)
  - Kind: precondition
  - Statement: both merge rails and transact reject a write once `Clock::unix_timestamp >= expires_at`, and `create_cache` rejects an `expires_at` that is not in the future with its own error. Entries inserted before expiry stay spendable until the account is closed, and the merged outputs stay spendable afterwards regardless: `process_merge_core` appends the output to the output tree before it touches the cache, and does so whether or not a cache is supplied.
  - Location: `programs/shielded-pool/src/instructions/cache/write.rs` (`fn CacheWrite::load`), `cache/create.rs` (`fn process_create_cache`), `merge/processor.rs` (`fn process_merge_core`)
  - Error: `ShieldedPoolError::CacheExpired = 7073`, `CacheExpiryNotInFuture = 7075`
  - Severity: Medium
  - Suggested test: negative; harness: litesvm

- [x] **INV-MERGE-28: closure requires expiry or the writer, and refunds the stored sponsor**
  - Covered by: `create_is_idempotent_and_close_refunds_sponsor`, `create_and_close_reject_unauthorized_configuration`, and `writer_can_close_before_expiry_and_only_refund_sponsor` in `program-tests/shielded-pool/tests/cache/contract.rs`.
  - Kind: precondition
  - Statement: `close_cache` takes the writable cache, writable rent recipient and optional writer signer. Before expiry the signer must match `write_authority`; after expiry anyone may close. Both paths transfer the whole balance to `rent_sponsor` and to no other recipient. This applies to every cache.
  - Error: `CacheNotExpired`, `CacheWriteAuthorityMismatch`, `CacheRentRecipientMismatch`, `InvalidSigner`
  - Severity: High (rent custody)
