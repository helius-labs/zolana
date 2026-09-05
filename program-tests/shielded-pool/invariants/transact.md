# Transact Invariants

Covers `Transact` (tag 12), `RingTransact` (tag 15), `RingAuthorityTransact` (tag 17).
Invariants shared with other instructions (expiry, pause, stale root, double-spend,
rollback, rail/vk separation, external_data_hash, settlement amount semantics) live
in `cross-cutting.md`.

All three tags parse the same `TransactIxDataRef` and run the same shared core
(`process_transact_ix`), so the instruction-data invariants INV-TRANSACT-07..12,
the settlement invariants INV-TRANSACT-13..17, the tree/settlement postconditions
INV-TRANSACT-23..28, and the frame conditions INV-TRANSACT-29..30 apply verbatim to
`RingTransact` and `RingAuthorityTransact`; they are stated once here (this file
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
  - Statement: the signer run — payer first, then first-occurrence-deduplicated eddsa owner signers — is folded into the public input as a fixed-width right-folded chain of `solana_pk_hash` values (`hash_bytes`, which packs the 32 bytes big-endian into 31-byte + 1-byte chunks and folds `Poseidon(chunk_0, chunk_1)`); the circuit checks each input's ownership against a chain element, so substituting a different signer account changes the chain and the proof no longer verifies.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs` (`fn fill_owner_signer_hashes`, `fn fixed_signer_hash_chain`), `programs/shielded-pool/src/instructions/hash.rs` (`fn solana_pk_hash`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (spend authorization)
  - Suggested test: negative + property; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-45: the signer run is payer-first, deduplicated, and width-bounded**
  - Covered by: `program-tests/shielded-pool/tests/transact/signer_run.rs` (`owner_signers_are_first_occurrence_deduplicated_with_payer_first`, `zero_suffix_optimization_matches_fixed_width_right_fold`, `zero_suffix_constants_cover_every_supported_width`, `fixed_signer_hash_chain_rejects_empty_signer_prefix`), `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_an_owner_signer_run_longer_than_the_input_count`, `transact_rejects_unsigned_eddsa_input_owner`
  - Kind: precondition + postcondition
  - Statement: authorization identities come from the accounts array, not instruction data: slot 0 is the payer (a duplicate payer in `owner_signers` is ignored), then the eddsa owner signers in first-occurrence order; the account parser limits the owner-signer run to `n_inputs`, so its unique payer-first prefix fits the circuit-derived `MAX_SIGNERS = MAX_INPUTS + 1` storage exactly, and every owner-signer account must actually sign. The public input folds the run as a right-folded chain zero-padded to `n_inputs + 1` (a one-element run folds to itself), so the witness and the on-chain recompute agree on exactly one canonical encoding of any signer set.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs` (`fn fill_owner_signer_hashes`, `fn fixed_signer_hash_chain`, `SIGNER_ZERO_SUFFIX_CHAINS`)
  - Error: `ShieldedPoolError::InvalidTransactShape = 7006` (an unsigned would-be owner signer ends the run at the loader's first-non-signer scan, leaving an unparsable account)
  - Severity: Critical (spend authorization)
  - Suggested test: unit (exists) + negative overflow + negative unsigned owner (exist); harness: `cargo test -p shielded-pool-tests --test transact_signer_run` + program-tests integration

- [x] **INV-TRANSACT-06: P256-owned inputs are authorized in-circuit (RingP256 only)**
  - Covered by: `prover/server/circuits/spp_transaction/shared/custom_p256_test.go` (`TestCustomRingP256Solves`, `TestCustomRingP256KeepsRingOnlyOwnerPrivate`, `TestCustomRingP256AcceptsMixedOwners`), `program-tests/ring-test-program/tests/p256_ring_lifecycle.rs`
  - Kind: postcondition
  - Statement: on the RingP256 rail there is no per-input signer element (and no shared `p256_signing_pk_x` instruction field): ownership is proved inside the circuit by a P256 signature over `Sha256(private_tx_hash)`, split low/high as public inputs; the owner's pubkey x-coordinate is exposed on the wire as `RingP256ProofData.default_owner_tag` ONLY when a real default-ring P256 input is present (ring-only P256 ownership stays private). The confidential (default-ring) transact rail has no P256 variant — that scope stays not applicable.
  - Location: `sdk-libs/client/src/prover/transact/ring_p256.rs`, `programs/shielded-pool/src/instructions/transact/verify.rs` (`fn public_input_hash`, `is_p256()` appendix)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (spend authorization)
  - Suggested test: positive per ownership layout (exists, Go) + on-chain owner-tag binding (exists); harness: `go test` + program-tests integration

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

- [x] **INV-TRANSACT-08: an unsupported output count is rejected**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_more_outputs_than_any_circuit_supports`
  - Kind: precondition
  - Statement: every instruction whose output count matches no circuit returns Err. The program itself no longer caps outputs -- nothing is sized by an output constant any more -- so the rejection comes from the supported-shape check, before any account or tree is touched.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs` (`fn validate_circuit_type`), `program-libs/interface/src/verifying_keys/circuit.rs` (`fn is_supported`)
  - Error: `ShieldedPoolError::InvalidTransactShape = 7006`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-09: an unsupported input count is rejected**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_more_inputs_than_any_circuit_supports`
  - Kind: precondition
  - Statement: every instruction whose input count matches no circuit returns Err before proof verification, before any tree write. The rejection comes from the supported-shape check, not from a buffer bound; the supported counts are 1 to 5 plus the 36-input consolidation shape, so six inputs is rejected while thirty-six is accepted.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs` (`fn validate_circuit_type`), `program-libs/interface/src/verifying_keys/circuit.rs` (`fn is_supported`)
  - Error: `ShieldedPoolError::InvalidTransactShape = 7006`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-10: owner-tag account index out of range is rejected**
  - Covered by: `programs/shielded-pool/src/instructions/transact/processor.rs` `external_data_hash_rejects_missing_owner_account`
  - Kind: precondition
  - Statement: every output whose `OwnerTag::Account(i)` references an index with no account in the transaction makes the instruction return Err.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs` (`fn hash_external_data_from_accounts`), `programs/shielded-pool/src/instructions/transact/verify.rs` (`fn fill_output_owner_chain`)
  - Error: `ShieldedPoolError::OwnerTagAccountMissing = 7025`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-TRANSACT-11: a RingP256 proof with an invalid BSB22 commitment is rejected before pairing**
  - Covered by: `program-tests/ring-test-program/tests/p256_ring_lifecycle.rs` `p256_ring_transfer_updates_recipient_wallet` (bad-commitment leg)
  - Kind: precondition
  - Statement: a `CircuitId::RingP256` selector whose embedded `RingP256ProofData.bsb22_commitment` does not verify against the proof returns the encoding error before any pairing work. (The pre-PR164 `P256SigningKey` owner-tag variant and `p256_signing_pk_x` field did NOT return; `OwnerTag` is `Inline`/`Account` only and `MissingP256SigningKey = 7024` stays retired — the decode-level rejection of the retired discriminant is covered by INV-XC-32.)
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs` (`fn verify`, commitment leg)
  - Error: `ShieldedPoolError::InvalidTransactProofEncoding = 7007`
  - Severity: Critical (spend authorization)
  - Suggested test: negative (exists); harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-TRANSACT-12: both public amounts set is rejected**
  - Not applicable post-PR164 (the `public_sol_amount`/`public_spl_amount` fields were replaced by an ordered `interface_transfers` list; multiple legs -- including SOL and SPL legs in one instruction -- are legal and settle independently per leg, so the both-present guard is unnecessary). The covering `both_public_amounts_are_rejected` test was removed with the fields.

- [x] **INV-TRANSACT-34: circuit selector family must match the dispatched tag**
  - Covered by: `program-tests/shielded-pool/tests/transact/validate_circuit.rs` `selector_family_must_match_instruction`
  - Kind: precondition
  - Statement: before any account is read, `Transact` accepts only `CircuitId::ConfidentialEddsa`, `RingTransact` only `RingEddsa`, `RingAuthorityTransact` only `RingAuthority`; any other selector returns Err. The untrusted selector is validated before it may drive account parsing, proof-input layout, or key selection.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:139-151` (`fn validate_circuit_type`)
  - Error: `ShieldedPoolError::MismatchedCircuitType = 7039`
  - Severity: Critical
  - Suggested test: negative per (tag, selector family) pair; harness: mollusk unit

- [x] **INV-TRANSACT-35: selector shape must equal the payload shape and be supported**
  - Covered by: `program-tests/shielded-pool/tests/transact/validate_circuit.rs` `selector_dimensions_are_fail_closed`, `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_an_unsupported_proof_shape`, `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_an_owner_signer_run_longer_than_the_input_count`, `program-libs/interface/src/verifying_keys/circuit.rs` `supported_shapes_are_fail_closed`
  - Kind: precondition
  - Statement: the instruction returns Err unless `circuit.num_inputs() == inputs.len()`, `circuit.num_outputs() == outputs.len()`, `circuit.num_public_asset_slots() <= N_PUBLIC_SLOTS` (3), and `circuit.is_supported()`. The owner-signer account run may not exceed `circuit.num_inputs()`; after payer-first deduplication it therefore fits `MAX_SIGNERS = MAX_INPUTS + 1`. The retired per-input `eddsa_signer_index` field (and its 255 P256 sentinel) is deleted from the wire: fail-closed is the fixed-width `InputUtxo` decode plus the signer-run bound, not a field check.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:152-163` (`fn validate_circuit_type`); supported-shape table `program-libs/interface/src/verifying_keys/circuit.rs:73-96`; signer-run bound `programs/shielded-pool/src/instructions/transact/verify.rs` (`fn fill_owner_signer_hashes`)
  - Error: `ShieldedPoolError::InvalidTransactShape = 7006`
  - Severity: Critical
  - Suggested test: negative per dimension; harness: mollusk unit

- [x] **INV-TRANSACT-36: interface-transfer wire limits**
  - Covered by: `program-libs/interface/src/instruction/instruction_data/transact.rs` `interface_transfer_validation_accepts_many_transfers_up_to_limit`, `interface_transfer_count_rejects_protocol_overflow_during_serialization`; `program-tests/shielded-pool/tests/transact/interface_transfers.rs` `zero_interface_transfer_is_rejected`
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

- [x] **INV-TRANSACT-14: SPL settlement requires the canonical cpi_authority account**
  - Covered by: `program-tests/shielded-pool/tests/transact/settlement.rs` `spl_withdrawal_rejects_a_wrong_cpi_authority_account`
  - Kind: precondition
  - Statement: on every SPL settlement leg (`SplDeposit` / `SplWithdrawal`), the account at the `cpi_authority` slot (first of the SPL account group) must be the canonical `SHIELDED_POOL_CPI_AUTHORITY` PDA; any other address returns Err. The check is defense-in-depth: `settle_spl_withdrawal` derives its signer from the hardcoded seed, and INV-TRANSACT-15 independently pins the vault's token-owner field to the same authority. (The retired piece is the `cpi_authority` INSTRUCTION-DATA field, which PR164 removed; the account slot and its validation remain live.)
  - Location: `programs/shielded-pool/src/instructions/settlement/validate.rs:77-83` (`fn validate_cpi_authority`), called from `transact/account.rs:78,84` on both SPL legs
  - Error: `ShieldedPoolError::InvalidSettlementAccounts = 7009`
  - Severity: Medium (defense-in-depth)
  - Suggested test: none remaining (negative exists)

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
  - Covered by: `program-tests/shielded-pool/tests/transact/mixed_interface_transfers.rs` `two_sol_withdrawals_share_one_public_asset_slot`, `three_distinct_assets_support_opposite_public_directions`, `full_u64_spl_cancellation_and_net_withdrawal_reach_proof_verification`, `reordered_same_asset_account_groups_fail_closed`; pinned by `program-tests/shielded-pool/tests/transact/circuit_vectors.rs` `field_derivation_vector_pins_the_shared_encodings`
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

- [x] **INV-TRANSACT-19: the proof rail is selected exactly by the CircuitId selector**
  - Covered by: `program-tests/shielded-pool/tests/transact/validate_circuit.rs` `selector_family_must_match_instruction`, `program-tests/ring-test-program/tests/p256_ring_lifecycle.rs` `cross_rail_proof_grafting_is_rejected`
  - Kind: precondition
  - Statement: the proof rail (uncommitted eddsa vs BSB22-committed P256) is selected ONLY by the `CircuitId` discriminant in instruction data, validated against the dispatched tag before any account is read; there is no sentinel value anywhere in the payload that can reroute a proof to another rail. (Replaces the pre-PR164 255-signer-index selection model; the retired `eddsa_signer_index` field is deleted from the wire.)
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:139-151` (`fn validate_circuit_type`), `program-libs/interface/src/verifying_keys/circuit.rs` (`CircuitId`)
  - Error: `ShieldedPoolError::MismatchedCircuitType = 7039`
  - Severity: Critical
  - Suggested test: negative per (tag, selector) pair + cross-rail grafting (both exist); harness: mollusk unit + program-tests integration

- [x] **INV-TRANSACT-20: payer address is bound into the public input hash**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_a_substituted_payer`
  - Kind: postcondition
  - Statement: the first signer-chain element is exactly `hash_bytes(payer address)`; a transaction proven for payer A submitted with payer B fails proof verification.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs` (`fn fill_owner_signer_hashes`, payer occupies slot 0), `fn public_input_hash`
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
  - Statement: the `transact` public-input hash chain contains the base chain (nullifier chain, output chain, utxo-root chain, nullifier-root chain, `private_tx_hash`), `external_data_hash`, the interleaved public transfer slots `(asset, amount)`, then `ring_program_id`, the right-folded payer-first signer chain, `allow_dummy_inputs`, and `hash_chain(output_owner_pk_hashes)`, where each output-owner element is `hash_bytes(resolved owner tag)`; changing any resolved output owner tag makes verification fail.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs` (`fn public_input_hash`, `fn fill_output_owner_pk_hashes`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (output redirection)
  - Suggested test: negative + golden vector (exists: `program-tests/shielded-pool/tests/transact/circuit_vectors.rs`); harness: mollusk unit + `cargo test -p`

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

- [x] **INV-TRANSACT-42: the tree's insertion fee is collected from the payer per queued input and credited to the fee balance**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_sends_valid_proof` (exact on-chain deltas: the input tree gains `inputs.len() * fees.fee_per_nullifier`, the payer loses the signature fee plus that amount, the header's `fee_balance` grows by the same amount); `program-tests/shielded-pool/tests/nullifier/nullifier_pdas.rs` `transact_rejects_when_working_capital_would_borrow_from_the_fee_pool` (the credited balance is what PDA funding must stay above, INV-TRANSACT-49); overflow legs `program-tests/shielded-pool/tests/tree/contract.rs` `reimbursement_recipient_balance_overflow_is_invalid_forester_fee` (7026), `program-libs/tree/tests/fees.rs` `credit_insertion_fee_overflow_is_reported`, `zero_schedule_charges_and_pays_nothing`
  - Kind: postcondition
  - Statement: while queueing the inputs, the input tree's `fee_balance` increases by exactly `fee = tree.fees.fee_per_nullifier * inputs.len()` (the schedule stored in the tree header, INV-SET-FEES-07; no constant fee exists any more), and the payer then transfers exactly `fee` lamports to the input tree via one System-Program CPI, before any PDA is funded from the tree; a fee-computation or balance overflow returns 7026; a zero fee (all-zero schedule) skips the CPI; the tree must be writable and program-owned else 7001. The payer never pays into a tree other than the input tree.
  - Location: `programs/shielded-pool/src/instructions/transact/tree.rs` (`fn apply_input_tree`, `credit_insertion_fee`), `transact/processor.rs` (`collect_forester_fee` before `create_nullifier_pdas`), `shared.rs` (`fn collect_forester_fee`), `program-libs/tree/src/fees.rs` (`fn TreeAccount::credit_insertion_fee`)
  - Error: `ShieldedPoolError::InvalidForesterFee = 7026` / `InvalidTreeAccounts = 7001`
  - Severity: High (fund movement)
  - Suggested test: none remaining (exact deltas and the reachable 7026 overflow legs are pinned; the applied-batches multiplication cannot overflow from a u32 — type-bound pinned in `applied_batches_cannot_overflow_by_type_bound`)

- [ ] **INV-TRANSACT-44: SPL deposit settles only if the vault gains exactly the nominal amount**
  - Partial coverage: the only mint kind that could net the vault less than the leg amount (a transfer-fee mint) is now rejected at interface creation (`program-tests/shielded-pool/tests/spl_interface/rejection.rs` `transfer_fee_mint_is_rejected_before_interface_creation`, INV-CREATE-SPL-13), so the post-CPI exact-gain check in `settle_spl_deposit` has no reachable shortfall input left to exercise end-to-end; the check stays as defence in depth and is untested
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
  - Statement: after a successful `transact` with an empty `interface_transfers` list, every account's token balance is unchanged, and the only lamport movements are the payer's transaction fee and the insertion fee (`input_tree.fees.fee_per_nullifier` × input count, credited to the tree's `fee_balance`) from the payer to the input tree (only the tree accounts' data changes).
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs` (`fn process_transact_ix`), `shared.rs` (`fn collect_forester_fee`)
  - Severity: High
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-TRANSACT-30: transact modifies no account other than trees, payer fee and settlement accounts**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_sends_valid_proof` (journaled snapshot compare: the trees are the only accounts whose data changed)
  - Kind: frame
  - Statement: after a successful `transact`, every account other than the two tree accounts (`input_tree`, `output_tree`), the payer (insertion fee at the input tree's `fee_per_nullifier`), and (when `interface_transfers` legs are present) the settlement balance accounts has unchanged data and unchanged lamports.
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

## RingTransact

### Account Constraints

- [x] **INV-RING-TRANSACT-01: ring_config must sign**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `ring_transact_rejects_an_unsigned_ring_config`
  - Kind: precondition
  - Statement: `ring_transact` can only succeed when the fourth account (`ring_config`) is a signer; only the ring program can produce that signature for its `ring_auth` PDA.
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs:152` (`RingTransactAccounts::validate_and_parse`)
  - Error: account-checks signer error
  - Severity: Critical (ring authorization)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-RING-TRANSACT-02: ring_config must be a valid SPP-owned RingConfig**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `ring_transact_rejects_a_ring_config_with_a_wrong_owner`, `ring_transact_rejects_a_ring_config_with_a_wrong_discriminator`
  - Kind: precondition
  - Statement: the `ring_config` account must be owned by the shielded-pool program, have `data_len` exactly `RingConfig::SIZE` (68), and discriminator byte exactly 4; any violation returns Err.
  - Location: `programs/shielded-pool/src/instructions/ring_config/loader.rs:14-20` (`fn load_ring_config`)
  - Error: `ShieldedPoolError::InvalidRingConfig = 7014`
  - Severity: Critical
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-RING-TRANSACT-08: a paused ring cannot transact**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `ring_transact_rejects_a_paused_ring_config`, `ring_authority_transact_prioritizes_paused_over_disabled`
  - Kind: precondition
  - Statement: both ring transact variants return `RingPaused` whenever the valid signing config has a nonzero `paused` field. For `ring_authority_transact`, this check precedes `ring_authority_transact_is_enabled`.
  - Location: `programs/shielded-pool/src/instructions/ring_config/loader.rs` (`fn load_active_ring_config`), `transact/account.rs` (`fn validate_and_parse`)
  - Error: `ShieldedPoolError::RingPaused = 7047`
  - Severity: Critical
  - Suggested test: negative; harness: litesvm

### Proof Binding

- [x] **INV-RING-TRANSACT-03: ring_program_id public input comes from the signed RingConfig**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `ring_transact_rejects_a_proof_bound_to_a_different_ring`
  - Kind: postcondition
  - Statement: the `ring_program_id` public-input element is exactly `solana_pk_hash` of the `program_id` stored in the signing `ring_config` account — `hash_bytes`, which packs the 32 bytes big-endian into 31-byte + 1-byte chunks and folds `Poseidon(chunk_0, chunk_1)`; it is never taken from instruction data.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:60-65` (`fn process_transact_ix`), `transact/account.rs:152-156`
  - Error: (mismatch) `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (cross-ring spend prevention)
  - Suggested test: negative (proof for ring A submitted with ring B's config); harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-RING-TRANSACT-04: ring variant uses the anonymous key family**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `ring_transact_rejects_a_confidential_proof_bound_to_the_ring_tag`, `program-libs/interface/tests/vk_fingerprint.rs` `verifying_key_fingerprint_is_pinned`
  - Kind: precondition
  - Statement: `ring_transact` verifies only against `transfer_ring_*` keys; a proof generated for the confidential (`transfer_confidential_*`) circuit of the same shape does not verify.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:96-118` (`fn verify`), `program-libs/interface/src/verifying_keys/circuit.rs:98-161` (`fn verifying_key`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-RING-TRANSACT-05: ring variant folds no output-owner public inputs**
  - Covered by: `program-tests/shielded-pool/tests/transact/circuit_vectors.rs` `program_assembly_matches_the_go_ordering_on_every_variant`
  - Kind: postcondition
  - Statement: the `ring_transact` public-input hash chain contains the base chain, `external_data_hash`, the interleaved public transfer slots, then `ring_program_id`, the right-folded payer-first signer chain, `allow_dummy_inputs`, and `hash_chain(output_owner_pk_hashes)`; the RingP256 selector additionally appends the P256 message hash and the default-owner-tag element after `private_tx_hash` (RingEddsa/RingP256 bind output owners; RingAuthority omits the owner chain and folds a bare payer element).
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:192-202` (`fn public_input_hash`)
  - Severity: High
  - Suggested test: golden vector (exists: `program-tests/shielded-pool/tests/transact/circuit_vectors.rs`); harness: `cargo nextest run -p shielded-pool-tests --test transact_circuit_vectors`

- [x] **INV-RING-TRANSACT-06: ring-only P256 ownership stays private on the wire**
  - Covered by: `program-tests/ring-test-program/tests/p256_ring_lifecycle.rs` `p256_ring_transfer_updates_recipient_wallet`, `default_ring_p256_input_exposes_and_binds_owner_tag`
  - Kind: postcondition
  - Statement: for a ring-owned P256 input the wire carries NO owner identifier — `RingP256ProofData.default_owner_tag` is `None` and the public input's owner-tag element is 0; ownership exists only inside the proof. Only a real DEFAULT-ring P256 input exposes the pubkey x-coordinate (`Some`), and that exposed tag is bound into the public input (a wrong tag fails pairing).
  - Location: `sdk-libs/client/src/prover/transact/ring_p256.rs` (`has_default_p256_input`), `programs/shielded-pool/src/instructions/transact/verify.rs` (`fn public_input_hash`, `default_p256_owner_tag` leg)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: High (confidentiality + binding)
  - Suggested test: positive private-by-default + positive exposed-and-bound + negative wrong tag (all exist); harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-RING-TRANSACT-07: enabled flag is not required for ring_transact**
  - Covered by: `program-tests/ring-test-program/tests/ring_lifecycle.rs` `ring_transact_succeeds_while_ring_authority_transact_is_disabled`
  - Kind: precondition
  - Statement: `ring_transact` succeeds for a ring whose `ring_authority_transact_is_enabled` is 0, all other preconditions held equal.
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs:157-159` (`fn validate_and_parse`, `require_enabled = false`), `transact/processor.rs:60-62`
  - Severity: Medium
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

## RingAuthorityTransact

### Authorization

- [x] **INV-RING-AUTH-01: ring_config must sign**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `ring_authority_transact_rejects_an_unsigned_ring_config`
  - Kind: precondition
  - Statement: `ring_authority_transact` can only succeed when the `ring_config` account is a signer.
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs:152` (`RingTransactAccounts::validate_and_parse`), called from `transact/processor.rs:60-62`
  - Error: account-checks signer error
  - Severity: Critical
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-RING-AUTH-02: disabled rings are rejected**
  - Covered by: `program-tests/ring-test-program/tests/ring_lifecycle.rs` `invalid_proofs_and_disabled_authority_are_atomic`
  - Kind: precondition
  - Statement: `ring_authority_transact` returns Err whenever the signing ring's `ring_authority_transact_is_enabled` field is exactly 0.
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs:157-159` (`fn validate_and_parse`, `require_enabled = true`)
  - Error: `ShieldedPoolError::RingAuthorityTransactDisabled = 7022`
  - Severity: Critical (authority containment)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-RING-AUTH-03: no input-owner signature is accepted or required**
  - Covered by: `program-tests/ring-test-program/tests/ring_lifecycle.rs` `ring_authority_transfer_reowns_a_utxo`, `program-tests/shielded-pool/tests/transact/guard.rs` `ring_authority_transact_rejects_an_owner_signer`
  - Kind: precondition
  - Statement: `ring_authority_transact` succeeds without any input-owner account signing, and rejects an owner-signer account run as `InvalidTransactShape`; the ring_config signature is the sole spend authorization.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:52-54, 60-62` (`fn process_transact_ix`, `CircuitId::RingAuthority` arm, `requires_input_signatures() == false`), `transact/account.rs:197`
  - Error: `ShieldedPoolError::InvalidTransactShape = 7006`
  - Severity: Critical
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

### Proof Binding

- [x] **INV-RING-AUTH-04: ring-authority verifying keys cover exactly the square shapes**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `ring_authority_transact_rejects_a_non_square_shape`, `program-tests/shielded-pool/tests/transact/functional.rs` `ring_authority_transact_accepts_the_maximum_square_shape`
  - Kind: precondition
  - Statement: `ring_authority_transact` verifies only for shapes `(1,1)`, `(2,2)`, `(3,3)`, `(4,4)`; every other `(inputs.len(), outputs.len())` returns Err.
  - Location: `program-libs/interface/src/verifying_keys/circuit.rs:92-94` (`fn is_supported`, `RingAuthority` arm)
  - Error: `ShieldedPoolError::InvalidTransactShape = 7006`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-RING-AUTH-05: ring-authority proofs must use the uncommitted (non-P256) encoding**
  - Covered by: `program-tests/shielded-pool/tests/transact/validate_circuit.rs` `selector_family_must_match_instruction`
  - Kind: precondition
  - Statement: `ring_authority_transact` accepts only the `CircuitId::RingAuthority` selector; a BSB22-committed `RingP256` selector (or any other family) under the authority tag is rejected by the pre-account selector-family validation. The authority rail itself carries no commitment: `TransactProof` is the plain 128-byte Groth16 triple.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:139-151` (`fn validate_circuit_type`)
  - Error: `ShieldedPoolError::MismatchedCircuitType = 7039`
  - Severity: High
  - Suggested test: negative per selector family (exists); harness: mollusk unit

- [x] **INV-RING-AUTH-06: authority variant folds no input-owner public inputs**
  - Covered by: `program-tests/shielded-pool/tests/transact/circuit_vectors.rs` `program_assembly_matches_the_go_ordering_on_every_variant`
  - Kind: postcondition
  - Statement: the `ring_authority_transact` public-input hash chain contains the base chain, `external_data_hash`, the interleaved public transfer slots, then `ring_program_id`, the bare `hash_bytes(payer)` element (a one-element signer "chain"), and `allow_dummy_inputs` (no output-owner chain).
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:192-202` (`fn public_input_hash`, authority selector omits both owner chains)
  - Severity: High
  - Suggested test: golden vector (exists: `program-tests/shielded-pool/tests/transact/circuit_vectors.rs`); harness: `cargo nextest run -p shielded-pool-tests --test transact_circuit_vectors`

- [x] **INV-RING-AUTH-07: ring_program_id binds the signing ring**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `ring_authority_transact_rejects_a_proof_bound_to_a_different_ring`
  - Kind: postcondition
  - Statement: as for `ring_transact`, the `ring_program_id` public-input element is exactly `solana_pk_hash` of the signing `ring_config.program_id`; a ring authority cannot transition UTXOs of a different ring.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:60-65` (`fn process_transact_ix`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)
