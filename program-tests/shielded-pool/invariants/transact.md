# Transact Invariants

Covers `Transact` (tag 0), `ZoneTransact` (tag 2), `ZoneAuthorityTransact` (tag 3).
Invariants shared with other instructions (expiry, pause, stale root, double-spend,
rollback, rail/vk separation, external_data_hash, settlement amount semantics) live
in `cross-cutting.md`.

All three tags parse the same `TransactIxDataRef` and run the same shared core
(`process_transact_core`), so the instruction-data invariants INV-TRANSACT-07..12,
the settlement invariants INV-TRANSACT-13..17, the tree/settlement postconditions
INV-TRANSACT-23..28, and the frame conditions INV-TRANSACT-29..30 apply verbatim to
`ZoneTransact` and `ZoneAuthorityTransact`; they are stated once here (this file
covers the whole group) and referenced from the coverage matrix.

## Transact

### Account Constraints

- [x] **INV-TRANSACT-01: payer must sign**
  - Covered by: `program-tests/shielded-pool/tests/transact/settlement.rs` `sol_withdrawal_rejects_an_unsigned_payer_meta`
  - Kind: precondition
  - Statement: `transact` can only succeed when the first account (`payer`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs:24` (`fn validate_and_parse`)
  - Error: account-checks error (not a `ShieldedPoolError`)
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-02: tree account must be writable**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_a_non_writable_tree_meta`
  - Kind: precondition
  - Statement: `transact` can only succeed when the second account (`tree`) is writable.
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs:25` (`fn validate_and_parse`)
  - Error: account-checks error / `TreeError::NotWritable` path
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-03: tree account must be program-owned with tree discriminator**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_a_tree_not_owned_by_the_program`, `transact_rejects_a_tree_with_a_wrong_discriminator`
  - Kind: precondition
  - Statement: `transact` returns Err for every tree account that is not owned by the shielded-pool program or whose first byte is not exactly `TREE_ACCOUNT_DISCRIMINATOR` (1).
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:131-140` (`fn process_transact_core`), `program-libs/tree/src/lib.rs:197-216` (`fn load_checked`)
  - Error: `ShieldedPoolError::InvalidTreeAccounts = 7001`
  - Severity: Critical
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-04: every eddsa-owned input's signer account must sign**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_unsigned_eddsa_input_owner`
  - Kind: precondition
  - Statement: for every input with `eddsa_signer_index != 255`, the account at that index in the raw account list must be a signer; a non-signer account at that index makes the instruction return Err.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:259-285` (`fn check_input_signers`)
  - Error: account-checks signer error; missing index: `ProgramError::NotEnoughAccountKeys`
  - Severity: Critical (spend authorization)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-05: input owner hash binds the signer key**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_a_substituted_input_signer`
  - Kind: postcondition
  - Statement: for every eddsa-owned input, the public-input element folded for that input is exactly `Poseidon(pk_low, pk_high)` of the signer account's address; substituting a different signer account changes the public-input hash and the proof no longer verifies.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:273-277` (`fn check_input_signers`), `programs/shielded-pool/src/instructions/hash.rs:24-29` (`fn solana_pk_hash`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (spend authorization)
  - Suggested test: negative + property; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-TRANSACT-06: P256-owned inputs fold the shared signing-key field**
  - Not applicable post-PR164 (the P256 transact ownership rail and the `p256_signing_pk_x` instruction field were removed; every input owner is ed25519 and is folded via `solana_pk_hash` under INV-TRANSACT-05). The covering `transact/p256.rs` suite was deleted with the rail.

### Instruction Data Validation

- [x] **INV-TRANSACT-07: malformed wincode payload is rejected**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_a_malformed_wincode_payload` (program-level built-in `ProgramError::InvalidInstructionData` asserted). Note: post-PR164 the ref decoder is exact-length, so trailing bytes are also rejected at parse; `transact_rejects_trailing_payload_bytes_at_parse` covers that boundary.
  - Kind: precondition
  - Statement: every payload that `TransactIxDataRef::from_bytes` fails to parse (truncated, wrong enum tag, overlong length prefix) makes `transact` return Err before any account is read.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:38-39` (`fn process_transact_ix`)
  - Error: `ProgramError::InvalidInstructionData` (built-in, not 7000)
  - Severity: Medium
  - Suggested test: fuzz + negative; harness: mollusk unit

- [x] **INV-TRANSACT-08: more than 8 outputs is rejected**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_more_outputs_than_any_circuit_supports`
  - Kind: precondition
  - Statement: every instruction with strictly more than `MAX_OUTPUTS` (8) outputs returns Err during output resolution.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:63-71` (`fn resolve_outputs`), `verify.rs:33` (`MAX_OUTPUTS`)
  - Error: `ShieldedPoolError::InvalidTransactShape = 7006`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-09: more than 5 inputs is rejected**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_more_inputs_than_any_circuit_supports`
  - Kind: precondition
  - Statement: every instruction with strictly more than `MAX_INPUTS` (5) inputs returns Err before proof verification.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:279-282` (`fn check_input_signers`), `processor.rs:212-218` (`fn apply_tree`), `verify.rs:31` (`MAX_INPUTS`)
  - Error: `ShieldedPoolError::InvalidTransactShape = 7006`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-10: owner-tag account index out of range is rejected**
  - Covered by: `program-libs/interface/src/instruction/instruction_data/transact.rs` `fetch_tag_resolves_every_variant`
  - Kind: precondition
  - Statement: every output whose `OwnerTag::Account(i)` references an index with no account in the transaction makes the instruction return Err.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:64-67` (`fn resolve_outputs`), `program-libs/interface/src/instruction/instruction_data/transact.rs:236-250` (`fn fetch_tag`)
  - Error: `ShieldedPoolError::OwnerTagAccountMissing = 7025`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-11: P256SigningKey tag without a P256 key is rejected**
  - Covered by: `program-libs/interface/src/instruction/instruction_data/transact.rs` `fetch_tag_resolves_every_variant`
  - Kind: precondition
  - Statement: every output with `OwnerTag::P256SigningKey` while `p256_signing_pk_x` is `None` makes the instruction return Err.
  - Location: `program-libs/interface/src/instruction/instruction_data/transact.rs:246-249` (`fn fetch_tag`)
  - Error: `ShieldedPoolError::MissingP256SigningKey = 7024`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [ ] **INV-TRANSACT-12: both public amounts set is rejected**
  - Not applicable post-PR164 (the `public_sol_amount`/`public_spl_amount` fields were replaced by an ordered `interface_transfers` list; multiple legs -- including SOL and SPL legs in one instruction -- are legal and settle independently per leg, so the both-present guard is unnecessary). The covering `both_public_amounts_are_rejected` test was removed with the fields.

### Settlement Account Constraints

- [x] **INV-TRANSACT-13: SOL settlement requires the canonical sol_interface PDA**
  - Covered by: `program-tests/shielded-pool/tests/transact/settlement.rs` `sol_withdrawal_rejects_a_non_canonical_sol_interface`
  - Kind: precondition
  - Statement: when `public_sol_amount` is `Some`, the `sol_interface` account address must equal the PDA derived from `[b"sol_interface", [0]]` under the program id; any other address returns Err.
  - Location: `programs/shielded-pool/src/instructions/settlement/validate.rs:15-28` (`fn validate_sol_interface`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Critical (fund theft)
  - Suggested test: negative; harness: mollusk unit

- [ ] **INV-TRANSACT-14: SPL withdrawal requires the canonical CPI authority**
  - Not applicable post-PR164 (`cpi_authority` is no longer instruction data: the SPL withdrawal account group carries the canonical authority PDA by construction and the vault's token-owner field must equal it -- the binding is now covered by INV-TRANSACT-15's canonical-vault/ownership checks). The covering `spl_withdrawal_rejects_a_wrong_cpi_authority` test was removed with the field.

- [x] **INV-TRANSACT-15: SPL vault must be the canonical per-mint vault PDA**
  - Covered by: `program-tests/shielded-pool/tests/transact/settlement.rs` `spl_withdrawal_rejects_a_non_canonical_vault`, `spl_withdrawal_rejects_a_vault_user_mint_mismatch`, `spl_withdrawal_rejects_a_vault_not_owned_by_the_cpi_authority`
  - Kind: precondition
  - Statement: when `public_spl_amount` is `Some`, the vault address must equal the PDA derived from `[b"spl_asset_vault", mint]`, the vault and user token accounts must share one mint, and the vault's owner must be `SHIELDED_POOL_CPI_AUTHORITY`; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/settlement/validate.rs:39-70` (`fn validate_spl_settlement`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Critical (fund theft / liquidity split)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-16: SPL settlement token accounts must be initialized SPL-token accounts**
  - Covered by: `program-tests/shielded-pool/tests/transact/settlement.rs` `spl_withdrawal_rejects_a_user_token_account_not_owned_by_the_token_program`, `spl_withdrawal_rejects_a_user_token_account_with_a_wrong_length`, `spl_withdrawal_rejects_an_uninitialized_user_token_account`
  - Kind: precondition
  - Statement: every settlement token account (vault, user token account) must be owned by the SPL Token program, have `data_len` exactly 165, and have state byte `Initialized`; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/settlement/validate.rs:44-51, 77-103` (`fn validate_spl_settlement`, `fn read_token_account`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [ ] **INV-TRANSACT-17: settlement addresses are bound into external_data_hash**
  - Partial coverage: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_tampered_public_amount` (recipient+amount tampering fails with 7008, but the settlement-address binding is not isolated from the amount binding)
  - Kind: postcondition
  - Statement: the recomputed `external_data_hash` public input contains exactly the SOL recipient address (SOL settlement), or exactly the user token account and vault addresses (SPL settlement), or all-zero placeholders (pure shielded transfer); substituting any settlement account after proving makes proof verification fail.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:143-160, 189-199` (`fn process_transact_core`, `fn settlement_accounts`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (withdrawal redirection)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

### Proof and Tree

- [x] **INV-TRANSACT-18: confidential verifying key is selected by exact shape and rail**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_an_unsupported_proof_shape`
  - Kind: precondition
  - Statement: `transact` verifies only against the `transfer_confidential_<n>_<m>` key whose `(n, m)` equals exactly `(inputs.len(), outputs.len())`; every unsupported shape returns Err.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:78-88, 258-286` (`fn verify`, `fn select_confidential_verifying_key`)
  - Error: `ShieldedPoolError::InvalidTransactShape = 7006`
  - Severity: Critical
  - Suggested test: negative + positive per shape; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-TRANSACT-19: P256 rail is selected exactly by a 255 signer index**
  - Not applicable post-PR164 (the P256 rail and the 255 sentinel were removed; every transact verifies on the eddsa rail selected by `CircuitId`).

- [x] **INV-TRANSACT-20: payer address is bound into the public input hash**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_a_substituted_payer`
  - Kind: postcondition
  - Statement: the `payer_pubkey_hash` public-input element is exactly `Sha256BE(payer address)`; a transaction proven for payer A submitted with payer B fails proof verification.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:162-163` (`fn process_transact_core`), `verify.rs:191` (`fn public_input_hash`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: High (relayer front-running / fee theft)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-21: SPL mint is bound into the public input hash**
  - Covered by: `program-tests/shielded-pool/tests/transact/withdrawal.rs` `shield_then_withdraw_spl_with_a_real_proof` (a proof bound to mint A is rejected atomically when submitted with mint B's canonical settlement accounts, then succeeds with mint A).
  - Kind: postcondition
  - Statement: when SPL settlement accounts are present, the `public_spl_asset_pubkey` public-input element is exactly `hash_field(mint)` of the validated vault mint, and `[0; 32]` otherwise; a proof built for mint A cannot settle mint B.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:165` (`fn process_transact_core`), `verify.rs:168-171` (`fn public_input_hash`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (asset substitution)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-22: confidential variant binds output owners and the P256 key**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_tampered_output_owner_tag`
  - Kind: postcondition
  - Statement: the `transact` public-input hash chain contains the 6-element base (nullifier chain, output chain, utxo-root chain, nullifier-root chain, `private_tx_hash`, `external_data_hash`), the interleaved public movement slots `(asset, amount)`, then `zone_program_id`, `payer_pubkey_hash`, `allow_dummy_inputs`, `hash_chain(input_owner_pk_hashes)`, and `hash_chain(output_owner_pk_hashes)`, where each output-owner element is `hash_bytes(resolved owner tag)`; changing any resolved output owner tag makes verification fail.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:143-201` (`fn public_input_hash`), `processor.rs:288-301` (`fn fill_output_owner_pk_hashes`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (output redirection)
  - Suggested test: negative + golden vector (exists: `verify.rs` `circuit_vector_tests`); harness: mollusk unit + `cargo test -p`

### Success Postconditions

- [x] **INV-TRANSACT-23: UTXO tree next_index increases by exactly the output count**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_sends_valid_proof`
  - Kind: postcondition
  - Statement: after a successful `transact` with M outputs, the UTXO tree's `next_index` is exactly its value before plus M, and the M output `utxo_hash` values occupy leaves `first_output_leaf_index .. first_output_leaf_index + M` in instruction order.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:229-237` (`fn apply_tree`)
  - Severity: Critical
  - Suggested test: positive + property; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-24: nullifier queue next_index increases by exactly the input count**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_sends_valid_proof`
  - Kind: postcondition
  - Statement: after a successful `transact` with N inputs, the nullifier queue's `next_index` is exactly its value before plus N, and each input's `nullifier_hash` has been inserted exactly once.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:211-227` (`fn apply_tree`)
  - Severity: Critical (double-spend)
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-25: successful transact emits exactly one Transact GeneralEvent**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_sends_valid_proof`
  - Kind: postcondition
  - Statement: after a successful `transact`, exactly one self-CPI `EmitEvent` inner instruction is recorded carrying a `GeneralEvent` whose inputs list the N nullifiers with their assigned queue sequence numbers, whose outputs map 1:1 to `ix.outputs` with the resolved owner tag as `view_tag`, and whose `first_output_leaf_index` equals the pre-append `next_index`.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:167,177` (`fn process_transact_core`), `event.rs:21-66` (`fn build_transact_event`)
  - Severity: Medium (indexer correctness)
  - Suggested test: positive; harness: litesvm

- [x] **INV-TRANSACT-26: SOL deposit moves exactly the public amount from recipient to sol_interface**
  - Covered by: `program-tests/shielded-pool/tests/transact/withdrawal.rs` `transact_sol_deposit_settles_exact_lamport_deltas`
  - Kind: postcondition
  - Statement: after a successful SOL deposit (`public_sol_amount = Some(a)`, `a > 0`), the `sol_interface` lamports are exactly the before-value plus `a` and the recipient's lamports are exactly the before-value minus `a`.
  - Location: `programs/shielded-pool/src/instructions/settlement/sol.rs:13-40` (`fn settle_sol`), `transact/processor.rs:170-176`
  - Severity: Critical
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-27: SOL withdrawal moves exactly the public amount from sol_interface to recipient**
  - Covered by: `program-tests/shielded-pool/tests/transact/withdrawal.rs` `shield_before_authority_rotation_then_withdraw_sol`
  - Kind: postcondition
  - Statement: after a successful SOL withdrawal (`public_sol_amount = Some(a)`, `a < 0`), the recipient's lamports are exactly the before-value plus `|a|` and the `sol_interface` lamports are exactly the before-value minus `|a|`, transferred under the `[b"sol_interface", [0], bump]` PDA signature.
  - Location: `programs/shielded-pool/src/instructions/settlement/sol.rs:25-39` (`fn settle_sol`)
  - Severity: Critical
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-28: SPL settlement direction follows the amount sign**
  - Covered by: `program-tests/shielded-pool/tests/transact/withdrawal.rs` `transact_spl_deposit_settles_exact_token_deltas` and `shield_then_withdraw_spl_with_a_real_proof` (positive user-to-vault and negative vault-to-user transfers assert exact token deltas with real proofs).
  - Kind: postcondition
  - Statement: after a successful SPL settlement of amount `a`, a deposit (`a > 0`) transfers exactly `a` tokens from the user token account to the vault with the recipient as authority, and a withdrawal (`a < 0`) transfers exactly `|a|` tokens from the vault to the user token account signed by the `[b"cpi_authority", 254]` PDA.
  - Location: `programs/shielded-pool/src/instructions/settlement/spl.rs:48-75` (`fn settle_spl`)
  - Severity: Critical
  - Suggested test: positive both directions; harness: program-tests integration (`cargo test-sbf`)

### Frame Conditions

- [x] **INV-TRANSACT-29: pure shielded transfer moves no lamports and no tokens**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_sends_valid_proof` (frame assertions: every lamport balance unchanged except the payer's signature fee)
  - Kind: frame
  - Statement: after a successful `transact` with both public amounts `None`, every account's lamports and every token-account balance are unchanged (only the tree account's data changes, minus transaction fees paid outside the program).
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:170-176` (`fn process_transact_core`, `None` arm)
  - Severity: High
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-30: transact modifies no account other than tree and settlement accounts**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_sends_valid_proof` (journaled snapshot compare: the tree is the only account whose data changed)
  - Kind: frame
  - Statement: after a successful `transact`, every account other than the tree account and (when a public amount is present) the two settlement balance accounts has unchanged data and unchanged lamports.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:116-178` (`fn process_transact_core`)
  - Severity: High
  - Suggested test: positive; harness: mollusk unit (full account snapshot compare)

### Nullifier Integrity

- [x] **INV-TRANSACT-31: every input slot's nullifier is circuit-derived and proven non-included**
  - Covered by: `prover/server/circuits/spp_transaction/shared/nullifier_attack_test.go` `TestDummyInputRejectsAttackerChosenNullifier`, `TestDummyInputRejectsZeroNullifier`
  - Kind: precondition
  - Statement: for every input slot -- spendable UTXO, address slot, or padding dummy -- the published nullifier is exactly the circuit-derived `Poseidon(utxo_hash, blinding, nullifier_secret)` and is proven non-included against the referenced nullifier-tree root; no slot type can carry a free (attacker-chosen) nullifier. This is the F-01 fix: unconstrained padding nullifiers could brick the nullifier queue.
  - Location: `prover/server/circuits/spp_transaction/shared/inputs.go` (`fn constrainInput`, `fn Input.checkNonInclusion`)
  - Error: circuit constraint failure (proof cannot be constructed)
  - Severity: Critical
  - Suggested test: negative per slot type (attacker-chosen and zero nullifier on a dummy slot); harness: Go circuit tests (`go test ./circuits/spp_transaction/shared`)

- [x] **INV-TRANSACT-32: nullifiers are pairwise-distinct across all input slots**
  - Covered by: `prover/server/circuits/spp_transaction/shared/nullifier_attack_test.go` `TestCircuitRejectsSharedNullifierAcrossSlots`
  - Kind: state
  - Statement: for every pair of input slots in one transaction, the published nullifiers differ unconditionally, regardless of slot type; two inputs (real or dummy) sharing one nullifier make the witness unsatisfiable.
  - Location: `prover/server/circuits/spp_transaction/shared/inputs.go` (pairwise `AssertIsDifferent` loop over slot nullifiers)
  - Error: circuit constraint failure (proof cannot be constructed)
  - Severity: Critical
  - Suggested test: negative (two slots, same nullifier); harness: Go circuit tests (`go test ./circuits/spp_transaction/shared`)

## ZoneTransact

### Account Constraints

- [x] **INV-ZONE-TRANSACT-01: zone_config must sign**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `zone_transact_rejects_an_unsigned_zone_config`
  - Kind: precondition
  - Statement: `zone_transact` can only succeed when the third account (`zone_config`) is a signer; only the zone program can produce that signature for its `zone_auth` PDA.
  - Location: `programs/shielded-pool/src/instructions/zone_transact/account.rs:31` (`fn validate_and_parse`)
  - Error: account-checks signer error
  - Severity: Critical (zone authorization)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-TRANSACT-02: zone_config must be a valid SPP-owned ZoneConfig**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `zone_transact_rejects_a_zone_config_with_a_wrong_owner`, `zone_transact_rejects_a_zone_config_with_a_wrong_discriminator`
  - Kind: precondition
  - Statement: the `zone_config` account must be owned by the shielded-pool program, have `data_len` exactly `ZoneConfig::SIZE` (67), and discriminator byte exactly 4; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/zone_config/loader.rs:13-28` (`fn load_zone_config`)
  - Error: `ShieldedPoolError::InvalidZoneConfig = 7014`
  - Severity: Critical
  - Suggested test: negative; harness: mollusk unit

### Proof Binding

- [x] **INV-ZONE-TRANSACT-03: zone_program_id public input comes from the signed ZoneConfig**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `zone_transact_rejects_a_proof_bound_to_a_different_zone`
  - Kind: postcondition
  - Statement: the `zone_program_id` public-input element is exactly `Poseidon(low, high)` of the `program_id` stored in the signing `zone_config` account; it is never taken from instruction data.
  - Location: `programs/shielded-pool/src/instructions/zone_transact/processor.rs:33-35` (`fn process_zone_transact_ix`), `zone_transact/account.rs:32-35`
  - Error: (mismatch) `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (cross-zone spend prevention)
  - Suggested test: negative (proof for zone A submitted with zone B's config); harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-ZONE-TRANSACT-04: zone variant uses the anonymous key family**
  - Partial coverage: `program-libs/interface/tests/vk_fingerprint.rs` `verifying_key_fingerprint_is_pinned` (all 26 committed keys are pinned; no test submits a confidential proof on the zone rail and asserts the 7008 rejection)
  - Kind: precondition
  - Statement: `zone_transact` verifies only against `transfer_zone_*` keys; a proof generated for the confidential (`transfer_confidential_*`) circuit of the same shape does not verify.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:81-85, 290-318` (`fn verify`, `fn select_zone_verifying_key`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-ZONE-TRANSACT-05: zone variant folds no output-owner public inputs**
  - Covered by: `programs/shielded-pool/src/instructions/transact/verify.rs` `program_assembly_matches_the_go_ordering_on_every_variant`
  - Kind: postcondition
  - Statement: the `zone_transact` public-input hash chain contains the 6-element base, the interleaved public movement slots, then `zone_program_id`, `payer_pubkey_hash`, `allow_dummy_inputs`, `hash_chain(input_owner_pk_hashes)`, and `hash_chain(output_owner_pk_hashes)` (ZoneEddsa binds output owners; ZoneAuthority omits both owner chains).
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:193-200` (`fn public_input_hash`)
  - Severity: High
  - Suggested test: golden vector (exists: `circuit_vector_tests`); harness: `cargo test -p zolana-shielded-pool`

- [ ] **INV-ZONE-TRANSACT-06: P256-owned zone inputs fold the zero sentinel**
  - Not applicable post-PR164 (the P256 zone-transfer rail was removed; the covering `p256_zone_transfer_updates_recipient_wallet` test was deleted with it).

- [x] **INV-ZONE-TRANSACT-07: enabled flag is not required for zone_transact**
  - Covered by: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `zone_transact_succeeds_while_zone_authority_transact_is_disabled`
  - Kind: precondition
  - Statement: `zone_transact` succeeds for a zone whose `zone_authority_transact_is_enabled` is 0, all other preconditions held equal.
  - Location: `programs/shielded-pool/src/instructions/zone_transact/processor.rs:34` (`validate_and_parse::<false>`), `zone_transact/account.rs:36-38`
  - Severity: Medium
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

## ZoneAuthorityTransact

### Authorization

- [x] **INV-ZONE-AUTH-01: zone_config must sign**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `zone_authority_transact_rejects_an_unsigned_zone_config`
  - Kind: precondition
  - Statement: `zone_authority_transact` can only succeed when the `zone_config` account is a signer.
  - Location: `programs/shielded-pool/src/instructions/zone_transact/account.rs:31` (`fn validate_and_parse`), called from `zone_authority_transact/processor.rs:41-42`
  - Error: account-checks signer error
  - Severity: Critical
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-AUTH-02: disabled zones are rejected**
  - Covered by: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `invalid_proofs_and_disabled_authority_are_atomic`
  - Kind: precondition
  - Statement: `zone_authority_transact` returns Err whenever the signing zone's `zone_authority_transact_is_enabled` field is exactly 0.
  - Location: `programs/shielded-pool/src/instructions/zone_transact/account.rs:36-38` (`fn validate_and_parse`, `REQUIRE_ENABLED = true`)
  - Error: `ShieldedPoolError::ZoneAuthorityTransactDisabled = 7022`
  - Severity: Critical (authority containment)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-AUTH-03: no input-owner signature is required**
  - Covered by: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `zone_authority_transfer_reowns_a_utxo`
  - Kind: precondition
  - Statement: `zone_authority_transact` succeeds without any input-owner account signing; input-signer checks are skipped entirely for this variant (the zone_config signature is the sole spend authorization).
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:101-103` (`fn prepare_proof_inputs`, `IS_AUTHORITY = true`), `zone_authority_transact/processor.rs:39-40`
  - Severity: Critical
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

### Proof Binding

- [x] **INV-ZONE-AUTH-04: zone-authority verifying keys cover exactly the square shapes**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `zone_authority_transact_rejects_a_non_square_shape`
  - Kind: precondition
  - Statement: `zone_authority_transact` verifies only for shapes `(1,1)`, `(2,2)`, `(3,3)`, `(4,4)`; every other `(inputs.len(), outputs.len())` returns Err.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:325-337` (`fn select_zone_authority_verifying_key`)
  - Error: `ShieldedPoolError::InvalidTransactShape = 7006`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [ ] **INV-ZONE-AUTH-05: zone-authority proofs must use the eddsa (uncommitted) encoding**
  - Not applicable post-PR164 (`TransactProof` is a single plain Groth16 struct -- there is no committed/P256 encoding to mismatch, and `MismatchedTransactProofRail` no longer exists). The covering `zone_authority_transact_rejects_a_p256_proof_encoding` test was removed with the rail.

- [x] **INV-ZONE-AUTH-06: authority variant folds no input-owner public inputs**
  - Covered by: `programs/shielded-pool/src/instructions/transact/verify.rs` `program_assembly_matches_the_go_ordering_on_every_variant`
  - Kind: postcondition
  - Statement: the `zone_authority_transact` public-input hash chain contains the 6-element base, the interleaved public movement slots, then `zone_program_id`, `payer_pubkey_hash`, and `allow_dummy_inputs` (no input-owner chain, no output-owner chain).
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:193-200` (`fn public_input_hash`, `IS_AUTHORITY = true`)
  - Severity: High
  - Suggested test: golden vector (exists: `circuit_vector_tests`); harness: `cargo test -p zolana-shielded-pool`

- [x] **INV-ZONE-AUTH-07: zone_program_id binds the signing zone**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `zone_authority_transact_rejects_a_proof_bound_to_a_different_zone`
  - Kind: postcondition
  - Statement: as for `zone_transact`, the `zone_program_id` public-input element is exactly `Poseidon(low, high)` of the signing `zone_config.program_id`; a zone authority cannot transition UTXOs of a different zone.
  - Location: `programs/shielded-pool/src/instructions/zone_authority_transact/processor.rs:41-43` (`fn process_zone_authority_transact_ix`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)
