# Transact Invariants

Covers `Transact` (tag 0), `ZoneTransact` (tag 2), `ZoneAuthorityTransact` (tag 3).
Invariants shared with other instructions (expiry, pause, stale root, double-spend,
rollback, rail/vk separation, external_data_hash, settlement amount semantics) live
in `cross-cutting.md`.

All three tags parse the same `TransactIxDataRef` and run the same shared core
(`process_transact_ix`), so the instruction-data invariants INV-TRANSACT-07..12,
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
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs:32` (`fn validate_and_parse`)
  - Error: account-checks error (not a `ShieldedPoolError`)
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-02: tree accounts must be writable**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_a_non_writable_tree_meta`
  - Kind: precondition
  - Statement: `transact` can only succeed when the second and third accounts (`input_tree`, `output_tree`) are writable.
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs:33-34` (`fn validate_and_parse`)
  - Error: account-checks error / `TreeError::NotWritable` path
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-03: tree accounts must be program-owned with tree discriminator**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_a_tree_not_owned_by_the_program`, `transact_rejects_a_tree_with_a_wrong_discriminator`
  - Kind: precondition
  - Statement: `transact` returns Err for every tree account (`input_tree` or `output_tree`) that is not owned by the shielded-pool program or whose first byte is not exactly `TREE_ACCOUNT_DISCRIMINATOR` (1).
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:77-98` (`fn process_transact_ix`), `program-libs/tree/src/lib.rs:192-204` (`fn from_account_view_mut`)
  - Error: `ShieldedPoolError::InvalidTreeAccounts = 7001`
  - Severity: Critical
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-04: every eddsa-owned input's signer account must sign**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_unsigned_eddsa_input_owner`
  - Kind: precondition
  - Statement: for every input, the account at `eddsa_signer_index` in the raw account list must be a signer (an index of 255 — the retired P256 sentinel — is rejected with 7006 at selector validation); a non-signer account at that index makes the instruction return Err.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:41-59` (`fn check_input_signers`)
  - Error: account-checks signer error; missing index: `ProgramError::NotEnoughAccountKeys`
  - Severity: Critical (spend authorization)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-05: input owner hash binds the signer key**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_a_substituted_input_signer`
  - Kind: postcondition
  - Statement: for every eddsa-owned input, the public-input element folded for that input is exactly `solana_pk_hash` of the signer account's address — `hash_bytes`, which packs the 32 bytes big-endian into 31-byte + 1-byte chunks and folds `Poseidon(chunk_0, chunk_1)`; substituting a different signer account changes the public-input hash and the proof no longer verifies.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:46-57` (`fn check_input_signers`), `programs/shielded-pool/src/instructions/hash.rs:20-22` (`fn solana_pk_hash`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (spend authorization)
  - Suggested test: negative + property; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-TRANSACT-06: P256-owned inputs fold the shared signing-key field**
  - Not applicable post-PR164 (the P256 transact ownership rail and the `p256_signing_pk_x` instruction field were removed; every input owner is ed25519 and is folded via `solana_pk_hash` under INV-TRANSACT-05). The covering `transact/p256.rs` suite was deleted with the rail.

- [ ] **INV-TRANSACT-40: input/output tree split**
  - Partial coverage: all functional tests exercise the two-account layout; no test asserts distinct input/output trees.
  - Kind: precondition
  - Statement: the account layout is `payer` (signer), `input_tree` (writable), `output_tree` (writable); both trees are loaded with owner/discriminator/pause checks; nullifiers queue into the input tree (which also supplies both root histories and the `allow_dummy_inputs` flag and receives the forester fee), outputs append to the output tree, and the emitted event records the output tree's address. The program does not require the two to be the same account. (Replaces the single-`tree` wording of INV-TRANSACT-02/03.)
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs:32-36`, `transact/processor.rs:77-98`, `transact/tree.rs`
  - Error: `ShieldedPoolError::InvalidTreeAccounts = 7001` / `ShieldedPoolError::TreePaused = 7013`
  - Severity: High
  - Suggested test: positive with two distinct tree accounts; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-41: trailing system program account is mandatory**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_a_wrong_trailing_system_program_account` (merge-side unit also exists, see INV-MERGE-18)
  - Kind: precondition
  - Statement: after the settlement groups, the next account must be the system program (kept in the account keys so the forester-fee Transfer CPI resolves); any other address returns Err.
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs:115-118` (`fn from_iter`)
  - Error: `ShieldedPoolError::InvalidSystemProgram = 7028`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

### Instruction Data Validation

- [x] **INV-TRANSACT-07: malformed wincode payload is rejected**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_a_malformed_wincode_payload` (program-level built-in `ProgramError::InvalidInstructionData` asserted). Note: post-PR164 the ref decoder is exact-length, so trailing bytes are also rejected at parse; `transact_rejects_trailing_payload_bytes_at_parse` covers that boundary.
  - Kind: precondition
  - Statement: every payload that `TransactIxDataRef::from_bytes` fails to parse (truncated, wrong enum tag, overlong length prefix) makes `transact` return Err before any account is read.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:43-44` (`fn process_transact_ix`)
  - Error: `ProgramError::InvalidInstructionData` (built-in, not 7000)
  - Severity: Medium
  - Suggested test: fuzz + negative; harness: mollusk unit

- [x] **INV-TRANSACT-08: more than 8 outputs is rejected**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_more_outputs_than_any_circuit_supports`
  - Kind: precondition
  - Statement: every instruction with strictly more than `MAX_OUTPUTS` (8) outputs returns Err during output resolution.
  - Location: `programs/shielded-pool/src/instructions/transact/event.rs:22-35` (`fn resolve_outputs`), `verify.rs:22` (`MAX_OUTPUTS`)
  - Error: `ShieldedPoolError::InvalidTransactShape = 7006`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-09: more than 5 inputs is rejected**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_more_inputs_than_any_circuit_supports`
  - Kind: precondition
  - Statement: every instruction with strictly more than `MAX_INPUTS` (5) inputs returns Err before proof verification.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:53-56` (`fn check_input_signers`), `transact/tree.rs:25-29` (`fn apply_input_tree`), `verify.rs:20` (`MAX_INPUTS`)
  - Error: `ShieldedPoolError::InvalidTransactShape = 7006`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-10: owner-tag account index out of range is rejected**
  - Covered by: `program-libs/interface/src/instruction/instruction_data/transact.rs` `fetch_tag_resolves_every_variant`
  - Kind: precondition
  - Statement: every output whose `OwnerTag::Account(i)` references an index with no account in the transaction makes the instruction return Err.
  - Location: `programs/shielded-pool/src/instructions/transact/event.rs:27-32` (`fn resolve_outputs`), `program-libs/interface/src/instruction/instruction_data/transact.rs:225-235` (`fn fetch_tag`)
  - Error: `ShieldedPoolError::OwnerTagAccountMissing = 7025`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [ ] **INV-TRANSACT-11: P256SigningKey tag without a P256 key is rejected**
  - Not applicable post-PR164 (the `P256SigningKey` owner-tag variant and `p256_signing_pk_x` were removed; `OwnerTag` is `Inline`/`Account` only and `MissingP256SigningKey = 7024` is retired). The decode-level rejection of the retired discriminant is covered by INV-XC-32.

- [ ] **INV-TRANSACT-12: both public amounts set is rejected**
  - Not applicable post-PR164 (the `public_sol_amount`/`public_spl_amount` fields were replaced by an ordered `interface_transfers` list; multiple legs -- including SOL and SPL legs in one instruction -- are legal and settle independently per leg, so the both-present guard is unnecessary). The covering `both_public_amounts_are_rejected` test was removed with the fields.

- [x] **INV-TRANSACT-34: circuit selector family must match the dispatched tag**
  - Covered by: `programs/shielded-pool/tests/validate_circuit.rs` `selector_family_must_match_instruction`
  - Kind: precondition
  - Statement: before any account is read, `Transact` accepts only `CircuitId::ConfidentialEddsa`, `ZoneTransact` only `ZoneEddsa`, `ZoneAuthorityTransact` only `ZoneAuthority`; any other selector returns Err. The untrusted selector is validated before it may drive account parsing, proof-input layout, or key selection.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:139-151` (`fn validate_circuit_type`)
  - Error: `ShieldedPoolError::MismatchedCircuitType = 7039`
  - Severity: Critical
  - Suggested test: negative per (tag, selector family) pair; harness: mollusk unit

- [x] **INV-TRANSACT-35: selector shape must equal the payload shape and be supported**
  - Covered by: `programs/shielded-pool/tests/validate_circuit.rs` `selector_dimensions_and_signer_indices_are_fail_closed`, `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_an_unsupported_proof_shape`, `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_overrunning_eddsa_signer_index`, `program-libs/interface/src/verifying_keys/circuit.rs` `supported_shapes_are_fail_closed`
  - Kind: precondition
  - Statement: the instruction returns Err unless `circuit.num_inputs() == inputs.len()`, `circuit.num_outputs() == outputs.len()`, `circuit.num_public_asset_slots() <= N_PUBLIC_SLOTS` (3), `circuit.is_supported()`, and no input carries the retired P256 sentinel `eddsa_signer_index == 255`.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:152-163` (`fn validate_circuit_type`); supported-shape table `program-libs/interface/src/verifying_keys/circuit.rs:73-96`
  - Error: `ShieldedPoolError::InvalidTransactShape = 7006`
  - Severity: Critical
  - Suggested test: negative per dimension; harness: mollusk unit

- [x] **INV-TRANSACT-36: interface-transfer wire limits**
  - Covered by: `program-libs/interface/src/instruction/instruction_data/transact.rs` `interface_transfer_validation_accepts_many_transfers_up_to_limit`, `interface_transfer_count_rejects_256_during_serialization_and_hashing`; `program-tests/shielded-pool/tests/transact/interface_transfers.rs` `zero_interface_transfer_is_rejected`
  - Kind: precondition
  - Statement: more than `MAX_INTERFACE_TRANSFERS` (255) legs returns 7035; any leg with amount 0 returns 7036.
  - Location: `program-libs/interface/src/instruction/instruction_data/transact.rs:77-87` (`fn validate_interface_transfers`), called from `programs/shielded-pool/src/instructions/transact/account.rs:48`
  - Error: `ShieldedPoolError::TooManyInterfaceTransfers = 7035` / `ShieldedPoolError::ZeroInterfaceTransferAmount = 7036`
  - Severity: Medium
  - Suggested test: negative at the boundary (255 ok, 256 rejected; zero leg rejected); harness: mollusk unit

### Settlement Account Constraints

- [x] **INV-TRANSACT-13: SOL settlement requires the canonical sol_interface PDA**
  - Covered by: `program-tests/shielded-pool/tests/transact/settlement.rs` `sol_withdrawal_rejects_a_non_canonical_sol_interface`
  - Kind: precondition
  - Statement: when the `interface_transfers` list carries a SOL leg (`SolDeposit` / `SolWithdrawal`), the `sol_interface` account address must equal the PDA derived from `[b"sol_interface", [0]]` under the program id; any other address returns Err.
  - Location: `programs/shielded-pool/src/instructions/settlement/validate.rs:60-74` (`fn validate_sol_settlement`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Critical (fund theft)
  - Suggested test: negative; harness: mollusk unit

- [ ] **INV-TRANSACT-14: SPL withdrawal requires the canonical CPI authority**
  - Not applicable post-PR164 (`cpi_authority` is no longer instruction data: the SPL withdrawal account group carries the canonical authority PDA by construction and the vault's token-owner field must equal it -- the binding is now covered by INV-TRANSACT-15's canonical-vault/ownership checks). The covering `spl_withdrawal_rejects_a_wrong_cpi_authority` test was removed with the field.

- [x] **INV-TRANSACT-15: SPL vault must be the canonical per-mint vault PDA**
  - Covered by: `program-tests/shielded-pool/tests/transact/settlement.rs` `spl_withdrawal_rejects_a_non_canonical_vault`, `spl_withdrawal_rejects_a_vault_user_mint_mismatch`, `spl_withdrawal_rejects_a_vault_not_owned_by_the_cpi_authority`
  - Kind: precondition
  - Statement: when the `interface_transfers` list carries an SPL leg (`SplDeposit` / `SplWithdrawal`), the vault address must equal the PDA derived from `[b"spl_asset_vault", mint]`, the vault and user token accounts must share one mint, and the vault's owner must be `SHIELDED_POOL_CPI_AUTHORITY`; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/settlement/validate.rs:85-121` (`fn validate_spl_settlement`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Critical (fund theft / liquidity split)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-16: SPL settlement token accounts must be initialized token-program accounts**
  - Covered by: `program-tests/shielded-pool/tests/transact/settlement.rs` `spl_withdrawal_rejects_a_user_token_account_not_owned_by_the_token_program`, `spl_withdrawal_rejects_a_user_token_account_with_a_wrong_length`, `spl_withdrawal_rejects_an_uninitialized_user_token_account`
  - Kind: precondition
  - Statement: every settlement token account (vault, user token account) must be owned by the settlement token program — SPL Token or Token-2022 (a wrong token-program account returns `UnsupportedSplTokenProgram = 7041`) — must unpack as `PodStateWithExtensions<PodAccount>` (extension-bearing Token-2022 accounts are legal; the exact-165 length rule is gone), and must have state `Initialized`; any other violation returns Err. (Token-2022 wording superseded by INV-TRANSACT-43.)
  - Location: `programs/shielded-pool/src/instructions/settlement/validate.rs:29-37, 85-121, 128-149` (`fn validate_token_program`, `fn validate_spl_settlement`, `fn read_token_account`)
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009` / `ShieldedPoolError::UnsupportedSplTokenProgram = 7041`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [ ] **INV-TRANSACT-17: settlement addresses are bound into external_data_hash**
  - Partial coverage: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_tampered_public_amount` (recipient+amount tampering fails with 7008, but the settlement-address binding is not isolated from the amount binding)
  - Kind: postcondition
  - Statement: the recomputed `external_data_hash` public input covers the resolved `interface_transfers` list — the SOL recipient address per SOL leg, and the user token account and vault addresses per SPL leg (the list is empty for a pure shielded transfer); substituting any settlement account after proving makes proof verification fail.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:100-112` (`fn process_transact_ix`, `external_data_hash` construction), `transact/interface_transfer.rs:111-143` (`fn resolve_interface_transfers`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (withdrawal redirection)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-39: SPL deposit leg depositor must sign**
  - Covered by: `program-tests/shielded-pool/tests/transact/interface_transfers.rs` `spl_deposit_requires_depositor_signature`
  - Kind: precondition
  - Statement: for every `SplDeposit` leg, the `depositor` account (the transfer authority) must be a signer.
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs:56-57` (`fn from_iter`)
  - Error: `ShieldedPoolError::SplDepositorMustSign = 7040`
  - Severity: Critical (theft of third-party tokens)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-43: settlement token program must be SPL Token or Token-2022**
  - Covered by: `program-tests/shielded-pool/tests/transact/interface_transfers.rs` `spl_withdrawal_rejects_a_shifted_token_program_account` (7041), `token_2022_withdrawal_accounts_reach_proof_verification`; `program-tests/shielded-pool/tests/transact/mixed_interface_transfers.rs` `token_2022_withdrawals_settle_independently` (positive legs); supersedes the stale wording of INV-TRANSACT-16
  - Kind: precondition
  - Statement: the `token_program` account must be the SPL Token or Token-2022 program id; vault and user token accounts must be owned by that program, unpack as `PodStateWithExtensions<PodAccount>` (extension-bearing Token-2022 accounts are legal — the exact-165 length rule is gone), and have state `Initialized`.
  - Location: `programs/shielded-pool/src/instructions/settlement/validate.rs:29-37, 128-149` (`fn validate_token_program`, `fn read_token_account`)
  - Error: `ShieldedPoolError::UnsupportedSplTokenProgram = 7041` (bad program) / `ShieldedPoolError::InvalidSettlementAccounts = 7009` (bad accounts)
  - Severity: High
  - Suggested test: negative (shifted token program); harness: mollusk unit

### Interface Transfers

- [x] **INV-TRANSACT-37: public-slot count and net-amount overflow gates**
  - Covered by: `program-tests/shielded-pool/tests/transact/interface_transfers.rs` `four_distinct_public_assets_are_rejected`, `same_asset_aggregate_overflow_is_rejected`
  - Kind: precondition
  - Statement: a batch of legs naming more distinct assets than the circuit's public slots returns 7037; a per-asset i128 net overflow or a net whose magnitude exceeds u64 returns 7038.
  - Location: `programs/shielded-pool/src/instructions/transact/interface_transfer.rs:54-72, 95-100` (`fn process_interface_transfers`, `fn checked_slot_amount`)
  - Error: `ShieldedPoolError::TooManyPublicAssets = 7037` / `ShieldedPoolError::PublicAssetAmountOverflow = 7038`
  - Severity: High
  - Suggested test: negative at the slot boundary and at the u64 magnitude boundary; harness: mollusk unit

- [x] **INV-TRANSACT-38: public-slot aggregation semantics**
  - Covered by: `program-tests/shielded-pool/tests/transact/mixed_interface_transfers.rs` `two_sol_withdrawals_share_one_public_asset_slot`, `three_distinct_assets_support_opposite_public_directions`, `full_u64_spl_cancellation_and_net_withdrawal_reach_proof_verification`, `reordered_same_asset_account_groups_fail_closed`; pinned by `programs/shielded-pool/src/instructions/transact/verify.rs` `field_derivation_vector_pins_the_shared_encodings`
  - Kind: state
  - Statement: legs aggregate by first-seen asset into the circuit's fixed slots, deposits positive and withdrawals negative; an assigned slot stays occupied even when its net returns to zero; the asset field is `SOL_ASSET_FIELD` for SOL legs and `hash_bytes(mint)` for SPL legs; settlement then executes per leg (not per slot) after proof verification.
  - Location: `programs/shielded-pool/src/instructions/transact/interface_transfer.rs:19-75` (`fn process_interface_transfers`)
  - Severity: High
  - Suggested test: positive with mixed legs; harness: program-tests integration (`cargo test-sbf`)

### Proof and Tree

- [x] **INV-TRANSACT-18: confidential verifying key is selected by exact shape and rail**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_an_unsupported_proof_shape`
  - Kind: precondition
  - Statement: `transact` verifies only against the `transfer_confidential_<n>_<m>` key whose `(n, m, public_asset_slots)` equals exactly `(inputs.len(), outputs.len(), circuit.num_public_asset_slots())` with `public_asset_slots == N_PUBLIC_SLOTS` (3) enforced; every unsupported shape returns Err.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:96-118` (`fn verify`), `program-libs/interface/src/verifying_keys/circuit.rs:73-96` (`fn is_supported`)
  - Error: `ShieldedPoolError::InvalidTransactShape = 7006`
  - Severity: Critical
  - Suggested test: negative + positive per shape; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-TRANSACT-19: P256 rail is selected exactly by a 255 signer index**
  - Not applicable post-PR164 (the P256 rail and the 255 sentinel were removed; every transact verifies on the eddsa rail selected by `CircuitId`).

- [x] **INV-TRANSACT-20: payer address is bound into the public input hash**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_a_substituted_payer`
  - Kind: postcondition
  - Statement: the `payer_pubkey_hash` public-input element is exactly `Sha256BE(payer address)`; a transaction proven for payer A submitted with payer B fails proof verification.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:114-115` (`fn process_transact_ix`), `verify.rs:194` (`fn public_input_hash`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: High (relayer front-running / fee theft)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-21: SPL mint is bound into the public input hash**
  - Covered by: `program-tests/shielded-pool/tests/transact/withdrawal.rs` `shield_then_withdraw_spl_with_a_real_proof` (a proof bound to mint A is rejected atomically when submitted with mint B's canonical settlement accounts, then succeeds with mint A).
  - Kind: postcondition
  - Statement: for every SPL leg the validated mint's `hash_bytes` occupies the leg's public movement slot asset field (SOL legs occupy their slot with `SOL_ASSET_FIELD`, unused slots are zero); a proof built for mint A cannot settle mint B.
  - Location: `programs/shielded-pool/src/instructions/transact/interface_transfer.rs:39-53` (`fn process_interface_transfers`), `verify.rs:188-191` (`fn public_input_hash`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (asset substitution)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-22: confidential variant binds output owners**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_tampered_output_owner_tag`
  - Kind: postcondition
  - Statement: the `transact` public-input hash chain contains the 6-element base (nullifier chain, output chain, utxo-root chain, nullifier-root chain, `private_tx_hash`, `external_data_hash`), the interleaved public movement slots `(asset, amount)`, then `zone_program_id`, `payer_pubkey_hash`, `allow_dummy_inputs`, `hash_chain(input_owner_pk_hashes)`, and `hash_chain(output_owner_pk_hashes)`, where each output-owner element is `hash_bytes(resolved owner tag)`; changing any resolved output owner tag makes verification fail.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:133-204` (`fn public_input_hash`), `verify.rs:62-75` (`fn fill_output_owner_pk_hashes`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (output redirection)
  - Suggested test: negative + golden vector (exists: `verify.rs` `circuit_vector_tests`); harness: mollusk unit + `cargo test -p`

### Success Postconditions

- [x] **INV-TRANSACT-23: UTXO tree next_index increases by exactly the output count**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_sends_valid_proof`
  - Kind: postcondition
  - Statement: after a successful `transact` with M outputs, the UTXO tree's `next_index` is exactly its value before plus M, and the M output `utxo_hash` values occupy leaves `first_output_leaf_index .. first_output_leaf_index + M` in instruction order.
  - Location: `programs/shielded-pool/src/instructions/transact/tree.rs:46-63` (`fn apply_output_tree`)
  - Severity: Critical
  - Suggested test: positive + property; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-24: nullifier queue next_index increases by exactly the input count**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_sends_valid_proof`
  - Kind: postcondition
  - Statement: after a successful `transact` with N inputs, the nullifier queue's `next_index` is exactly its value before plus N, and each input's `nullifier_hash` has been inserted exactly once.
  - Location: `programs/shielded-pool/src/instructions/transact/tree.rs:13-43` (`fn apply_input_tree`)
  - Severity: Critical (double-spend)
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-25: successful transact emits exactly one Transact GeneralEvent**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_sends_valid_proof`
  - Kind: postcondition
  - Statement: after a successful `transact`, exactly one self-CPI `EmitEvent` inner instruction is recorded carrying a `GeneralEvent` whose inputs list the N nullifiers with their assigned queue sequence numbers, whose outputs map 1:1 to `ix.outputs` with the resolved owner tag as `view_tag`, and whose `first_output_leaf_index` equals the pre-append `next_index`.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:128-134` (`fn process_transact_ix`), `event.rs:41-90` (`fn build_transact_event`)
  - Severity: Medium (indexer correctness)
  - Suggested test: positive; harness: litesvm

- [x] **INV-TRANSACT-26: SOL deposit moves exactly the public amount from recipient to sol_interface**
  - Covered by: `program-tests/shielded-pool/tests/transact/withdrawal.rs` `transact_sol_deposit_settles_exact_lamport_deltas`
  - Kind: postcondition
  - Statement: after a successful SOL deposit (an `InterfaceTransfer::SolDeposit { amount: a }` leg), the `sol_interface` lamports are exactly the before-value plus `a` and the recipient's lamports are exactly the before-value minus `a`.
  - Location: `programs/shielded-pool/src/instructions/settlement/sol.rs:13-40` (`fn settle_sol`), `transact/interface_transfer.rs:79-92` (`fn settle_interface_transfers`)
  - Severity: Critical
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-27: SOL withdrawal moves exactly the public amount from sol_interface to recipient**
  - Covered by: `program-tests/shielded-pool/tests/transact/withdrawal.rs` `shield_before_authority_rotation_then_withdraw_sol`
  - Kind: postcondition
  - Statement: after a successful SOL withdrawal (an `InterfaceTransfer::SolWithdrawal { amount: a }` leg), the recipient's lamports are exactly the before-value plus `a` and the `sol_interface` lamports are exactly the before-value minus `a`, transferred under the `[b"sol_interface", [0], bump]` PDA signature.
  - Location: `programs/shielded-pool/src/instructions/settlement/sol.rs:25-39` (`fn settle_sol`)
  - Severity: Critical
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-28: SPL settlement direction follows the leg variant**
  - Covered by: `program-tests/shielded-pool/tests/transact/withdrawal.rs` `transact_spl_deposit_settles_exact_token_deltas` and `shield_then_withdraw_spl_with_a_real_proof` (positive user-to-vault and negative vault-to-user transfers assert exact token deltas with real proofs).
  - Kind: postcondition
  - Statement: after a successful SPL settlement of amount `a`, a deposit leg (`InterfaceTransfer::SplDeposit`) transfers exactly `a` tokens from the user token account to the vault with the depositor as authority (which must sign, else `SplDepositorMustSign = 7040`), and a withdrawal leg (`InterfaceTransfer::SplWithdrawal`) transfers exactly `a` tokens from the vault to the user token account signed by the `[b"cpi_authority", 254]` PDA.
  - Location: `programs/shielded-pool/src/instructions/settlement/spl.rs:58-80, 84-101` (`fn settle_spl_deposit`, `fn settle_spl_withdrawal`)
  - Severity: Critical
  - Suggested test: positive both directions; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-42: forester fee is collected from the payer per queued input**
  - Covered by: `programs/shielded-pool/src/instructions/shared.rs` unit `per_tree_fee_scales_with_inserted_elements`; exercised economically in `program-tests/spp-test-validator/tests/actions/merge.rs` (no exact on-chain delta assertion)
  - Kind: postcondition
  - Statement: after proof verification, the payer transfers exactly `forester_fee_per_queue_element(zkp_batch_size) * inputs.len()` lamports to the input tree via one System-Program CPI; a fee-computation overflow returns 7026; a zero fee skips the CPI; the tree must be writable and program-owned else 7001.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:121-126` (`fn process_transact_ix`), `shared.rs:77-103` (`fn collect_forester_fee`)
  - Error: `ShieldedPoolError::InvalidForesterFee = 7026`
  - Severity: High (fund movement)
  - Suggested test: positive with exact lamport delta; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-44: SPL deposit settles only if the vault gains exactly the nominal amount**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `transfer_fee_deposit_is_rejected_when_vault_receives_less_than_nominal_amount`
  - Kind: postcondition
  - Statement: after an SPL deposit `TransferChecked` CPI, the vault's base amount must equal its pre-CPI amount plus exactly the leg amount (checked_add overflow also fails); any shortfall (e.g. a transfer-fee mint netting less) aborts the instruction. Extension balances such as `withheld_amount` never count as collateral.
  - Location: `programs/shielded-pool/src/instructions/settlement/spl.rs:58-77, 105-111` (`fn settle_spl_deposit`, `fn token_account_amount`)
  - Error: `ShieldedPoolError::PublicSettlementFailed = 7010`
  - Severity: Critical (unbacked-note mint via fee-on-transfer)
  - Suggested test: negative (transfer-fee mint); harness: program-tests integration (`cargo test-sbf`)

### Frame Conditions

- [x] **INV-TRANSACT-29: pure shielded transfer moves no lamports and no tokens**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_sends_valid_proof` (frame assertions: every lamport balance unchanged except the payer's signature fee and the forester fee to the input tree)
  - Kind: frame
  - Statement: after a successful `transact` with an empty `interface_transfers` list, every account's token balance is unchanged, and the only lamport movements are the payer's transaction fee and the forester fee (`forester_fee_per_queue_element(zkp_batch_size)` × input count) from the payer to the input tree (only the tree accounts' data changes).
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:119-126` (`fn process_transact_ix`), `shared.rs:77-103` (`fn collect_forester_fee`)
  - Severity: High
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-30: transact modifies no account other than trees, payer fee and settlement accounts**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_sends_valid_proof` (journaled snapshot compare: the trees are the only accounts whose data changed)
  - Kind: frame
  - Statement: after a successful `transact`, every account other than the two tree accounts (`input_tree`, `output_tree`), the payer (forester fee), and (when `interface_transfers` legs are present) the settlement balance accounts has unchanged data and unchanged lamports.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:38-135` (`fn process_transact_ix`)
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

- [x] **INV-TRANSACT-33: dummy-slot proofs are locked out once the tree crosses the capacity threshold**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_dummy_inputs_after_capacity_threshold`
  - Kind: precondition
  - Statement: when the nullifier tree has strictly fewer free leaves than the state tree (queue reservations count against nullifier capacity), the on-chain `allow_dummy_inputs` public input is false; a proof carrying dummy input slots commits to `allow_dummy_inputs = true`, so the public input hash mismatches and verification fails. Equality of the two remaining capacities still allows dummies.
  - Location: `programs/shielded-pool/src/instructions/transact/tree.rs:20-21` (`fn apply_input_tree`), `program-libs/tree/src/lib.rs:279-290` (`fn allow_dummy_inputs`); the merge rail gates the same flag with the explicit `NullifierTreeTooFullForMerge` (`programs/shielded-pool/src/instructions/merge/processor.rs:100-106`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: High (availability: near-capacity trees must not accept spends they cannot nullify)
  - Suggested test: negative (queue cursor moved past the threshold, roots unchanged); harness: program-tests integration (`cargo test-sbf`)

## ZoneTransact

### Account Constraints

- [x] **INV-ZONE-TRANSACT-01: zone_config must sign**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `zone_transact_rejects_an_unsigned_zone_config`
  - Kind: precondition
  - Statement: `zone_transact` can only succeed when the fourth account (`zone_config`) is a signer; only the zone program can produce that signature for its `zone_auth` PDA.
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs:152` (`ZoneTransactAccounts::validate_and_parse`)
  - Error: account-checks signer error
  - Severity: Critical (zone authorization)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-TRANSACT-02: zone_config must be a valid SPP-owned ZoneConfig**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `zone_transact_rejects_a_zone_config_with_a_wrong_owner`, `zone_transact_rejects_a_zone_config_with_a_wrong_discriminator`
  - Kind: precondition
  - Statement: the `zone_config` account must be owned by the shielded-pool program, have `data_len` exactly `ZoneConfig::SIZE` (67), and discriminator byte exactly 4; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/zone_config/loader.rs:14-20` (`fn load_zone_config`)
  - Error: `ShieldedPoolError::InvalidZoneConfig = 7014`
  - Severity: Critical
  - Suggested test: negative; harness: mollusk unit

### Proof Binding

- [x] **INV-ZONE-TRANSACT-03: zone_program_id public input comes from the signed ZoneConfig**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `zone_transact_rejects_a_proof_bound_to_a_different_zone`
  - Kind: postcondition
  - Statement: the `zone_program_id` public-input element is exactly `solana_pk_hash` of the `program_id` stored in the signing `zone_config` account — `hash_bytes`, which packs the 32 bytes big-endian into 31-byte + 1-byte chunks and folds `Poseidon(chunk_0, chunk_1)`; it is never taken from instruction data.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:60-65` (`fn process_transact_ix`), `transact/account.rs:152-156`
  - Error: (mismatch) `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (cross-zone spend prevention)
  - Suggested test: negative (proof for zone A submitted with zone B's config); harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-ZONE-TRANSACT-04: zone variant uses the anonymous key family**
  - Partial coverage: `program-libs/interface/tests/vk_fingerprint.rs` `verifying_key_fingerprint_is_pinned` (all 26 committed keys are pinned; no test submits a confidential proof on the zone rail and asserts the 7008 rejection)
  - Kind: precondition
  - Statement: `zone_transact` verifies only against `transfer_zone_*` keys; a proof generated for the confidential (`transfer_confidential_*`) circuit of the same shape does not verify.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:96-118` (`fn verify`), `program-libs/interface/src/verifying_keys/circuit.rs:98-161` (`fn verifying_key`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-ZONE-TRANSACT-05: zone variant folds no output-owner public inputs**
  - Covered by: `programs/shielded-pool/src/instructions/transact/verify.rs` `program_assembly_matches_the_go_ordering_on_every_variant`
  - Kind: postcondition
  - Statement: the `zone_transact` public-input hash chain contains the 6-element base, the interleaved public movement slots, then `zone_program_id`, `payer_pubkey_hash`, `allow_dummy_inputs`, `hash_chain(input_owner_pk_hashes)`, and `hash_chain(output_owner_pk_hashes)` (ZoneEddsa binds output owners; ZoneAuthority omits both owner chains).
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:192-202` (`fn public_input_hash`)
  - Severity: High
  - Suggested test: golden vector (exists: `circuit_vector_tests`); harness: `cargo test -p zolana-shielded-pool`

- [ ] **INV-ZONE-TRANSACT-06: P256-owned zone inputs fold the zero sentinel**
  - Not applicable post-PR164 (the P256 zone-transfer rail was removed; the covering `p256_zone_transfer_updates_recipient_wallet` test was deleted with it).

- [x] **INV-ZONE-TRANSACT-07: enabled flag is not required for zone_transact**
  - Covered by: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `zone_transact_succeeds_while_zone_authority_transact_is_disabled`
  - Kind: precondition
  - Statement: `zone_transact` succeeds for a zone whose `zone_authority_transact_is_enabled` is 0, all other preconditions held equal.
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs:157-159` (`fn validate_and_parse`, `require_enabled = false`), `transact/processor.rs:60-62`
  - Severity: Medium
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

## ZoneAuthorityTransact

### Authorization

- [x] **INV-ZONE-AUTH-01: zone_config must sign**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `zone_authority_transact_rejects_an_unsigned_zone_config`
  - Kind: precondition
  - Statement: `zone_authority_transact` can only succeed when the `zone_config` account is a signer.
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs:152` (`ZoneTransactAccounts::validate_and_parse`), called from `transact/processor.rs:60-62`
  - Error: account-checks signer error
  - Severity: Critical
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-AUTH-02: disabled zones are rejected**
  - Covered by: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `invalid_proofs_and_disabled_authority_are_atomic`
  - Kind: precondition
  - Statement: `zone_authority_transact` returns Err whenever the signing zone's `zone_authority_transact_is_enabled` field is exactly 0.
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs:157-159` (`fn validate_and_parse`, `require_enabled = true`)
  - Error: `ShieldedPoolError::ZoneAuthorityTransactDisabled = 7022`
  - Severity: Critical (authority containment)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-ZONE-AUTH-03: no input-owner signature is required**
  - Covered by: `program-tests/zone-test-program/tests/zone_lifecycle.rs` `zone_authority_transfer_reowns_a_utxo`
  - Kind: precondition
  - Statement: `zone_authority_transact` succeeds without any input-owner account signing; input-signer checks are skipped entirely for this variant (the zone_config signature is the sole spend authorization).
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:52-54, 60-62` (`fn process_transact_ix`, `CircuitId::ZoneAuthority` arm, `requires_input_signatures() == false`)
  - Severity: Critical
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

### Proof Binding

- [x] **INV-ZONE-AUTH-04: zone-authority verifying keys cover exactly the square shapes**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `zone_authority_transact_rejects_a_non_square_shape`
  - Kind: precondition
  - Statement: `zone_authority_transact` verifies only for shapes `(1,1)`, `(2,2)`, `(3,3)`, `(4,4)`; every other `(inputs.len(), outputs.len())` returns Err.
  - Location: `program-libs/interface/src/verifying_keys/circuit.rs:92-94` (`fn is_supported`, `ZoneAuthority` arm)
  - Error: `ShieldedPoolError::InvalidTransactShape = 7006`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [ ] **INV-ZONE-AUTH-05: zone-authority proofs must use the eddsa (uncommitted) encoding**
  - Not applicable post-PR164 (`TransactProof` is a single plain Groth16 struct -- there is no committed/P256 encoding to mismatch, and `MismatchedTransactProofRail` no longer exists). The covering `zone_authority_transact_rejects_a_p256_proof_encoding` test was removed with the rail.

- [x] **INV-ZONE-AUTH-06: authority variant folds no input-owner public inputs**
  - Covered by: `programs/shielded-pool/src/instructions/transact/verify.rs` `program_assembly_matches_the_go_ordering_on_every_variant`
  - Kind: postcondition
  - Statement: the `zone_authority_transact` public-input hash chain contains the 6-element base, the interleaved public movement slots, then `zone_program_id`, `payer_pubkey_hash`, and `allow_dummy_inputs` (no input-owner chain, no output-owner chain).
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:192-202` (`fn public_input_hash`, authority selector omits both owner chains)
  - Severity: High
  - Suggested test: golden vector (exists: `circuit_vector_tests`); harness: `cargo test -p zolana-shielded-pool`

- [x] **INV-ZONE-AUTH-07: zone_program_id binds the signing zone**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `zone_authority_transact_rejects_a_proof_bound_to_a_different_zone`
  - Kind: postcondition
  - Statement: as for `zone_transact`, the `zone_program_id` public-input element is exactly `solana_pk_hash` of the signing `zone_config.program_id`; a zone authority cannot transition UTXOs of a different zone.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:60-65` (`fn process_transact_ix`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)
