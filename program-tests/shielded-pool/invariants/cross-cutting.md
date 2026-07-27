# Cross-Cutting Invariants

Invariants that apply to more than one instruction. Each entry lists the affected
instructions; per-instruction files reference these IDs instead of duplicating them.

## Dispatch

- [x] **INV-XC-01: wrong program id is rejected**
  - Covered by: `programs/shielded-pool/tests/instruction_validation.rs` `rejects_the_wrong_program_before_dispatch`
  - Kind: precondition
  - Affects: all 18 instructions
  - Statement: `process_instruction` returns Err whenever the invoked `program_id` differs from the declared program id `sppzgEd25DF4PC1FgNerLWVZndUAV82LV9Dy5yCvRVA`.
  - Location: `programs/shielded-pool/src/lib.rs:40-42` (`fn process_instruction`)
  - Error: `ProgramError::IncorrectProgramId`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-XC-02: empty instruction data is rejected**
  - Covered by: `programs/shielded-pool/tests/instruction_validation.rs` `rejects_empty_unknown_and_malformed_instruction_data_exactly`
  - Kind: precondition
  - Affects: all 18 instructions
  - Statement: `process_instruction` returns Err for the zero-length instruction data (no tag byte).
  - Location: `programs/shielded-pool/src/lib.rs:43-45` (`fn process_instruction`)
  - Error: `ProgramError::InvalidInstructionData`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-XC-03: every unknown tag is rejected**
  - Covered by: `programs/shielded-pool/tests/instruction_validation.rs` `every_first_byte_dispatches_or_is_rejected_exactly` (full 256-byte sweep)
  - Kind: precondition
  - Affects: all 18 instructions
  - Statement: for every first byte outside the set {0..16, 51}, `process_instruction` returns Err; for every byte inside the set it dispatches to exactly the processor of that tag.
  - Location: `programs/shielded-pool/src/lib.rs:47-75` (`fn process_instruction`), `program-libs/event/src/tag.rs:47-73` (`impl TryFrom<u8> for InstructionTag`)
  - Error: `ProgramError::InvalidInstructionData`
  - Severity: Medium
  - Suggested test: property (all 256 first bytes); harness: mollusk unit

## Atomicity / Rollback

- [ ] **INV-XC-04: every failing instruction leaves every account unchanged**
  - Partial coverage: `program-tests/shielded-pool/tests/deposit/rejection.rs` `sol_deposit_rejects_foreign_tree_atomically` and peers (rollback asserted for Transact, Deposit, Merge, CreateTree, PauseTree, and SPL paths; the zone variants, ZoneDeposit, ZoneMerge, CreateAssetCounter, and zone-config updates lack account-equality assertions)
  - Kind: rollback
  - Affects: all 18 instructions
  - Statement: when any shielded-pool instruction returns Err, every account's data and lamports after the transaction equal their values before it (SVM transaction rollback; the program never communicates partial state outside the transaction).
  - Location: `programs/shielded-pool/src/lib.rs:35-76` (`fn process_instruction`); runtime guarantee relied on because tree writes precede proof verification (see INV-XC-05)
  - Severity: Critical
  - Suggested test: negative per instruction (assert full account equality after Err); harness: mollusk unit / litesvm
  - Note: this is the per-instruction "rollback" cell of the coverage matrix; each instruction needs at least one failing-path test asserting account equality.

- [x] **INV-XC-05: a failing proof leaves the trees unchanged**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `default_rail_merge_rejects_a_zeroed_proof_exactly`
  - Kind: rollback
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact, MergeTransact, ZoneMergeTransact
  - Statement: these instructions insert nullifiers and append outputs before verifying the proof; when verification fails, the transaction aborts and the UTXO tree `next_index`, nullifier queue `next_index`, and all roots after the transaction are exactly their values before it.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:130-168` (tree write at 130-141, verify at 168), `merge/processor.rs:100-119`
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (a persisted write with a failed proof would mint unbacked notes)
  - Suggested test: negative (garbage proof, then assert tree state); harness: program-tests integration (`cargo test-sbf`)

## Expiry and Pause

- [x] **INV-XC-06: an expired transaction is rejected**
  - Covered by: `program-tests/shielded-pool/tests/transact/withdrawal.rs` `shield_before_authority_rotation_then_withdraw_sol`
  - Kind: precondition
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact, MergeTransact, ZoneMergeTransact
  - Statement: each of these instructions returns Err whenever `Clock.unix_timestamp` as u64 is strictly greater than `expiry_unix_ts`; execution at `unix_timestamp == expiry_unix_ts` is still accepted.
  - Location: `programs/shielded-pool/src/instructions/shared.rs:12-17` (`fn check_not_expired`); call sites `transact/processor.rs:42`, `zone_transact/processor.rs:29`, `zone_authority_transact/processor.rs:33`, `merge/processor.rs:37`, `merge_zone/processor.rs:44`
  - Error: `ShieldedPoolError::ExpiredTransaction = 7005`
  - Severity: High
  - Suggested test: negative + boundary (ts == expiry); harness: litesvm (warped clock)

- [x] **INV-XC-07: a negative clock is rejected**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_a_negative_clock`; `transact/guard.rs` `transact_rejects_a_negative_clock`
  - Kind: precondition
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact, MergeTransact, ZoneMergeTransact
  - Statement: each of these instructions returns Err whenever `Clock.unix_timestamp` is strictly less than 0, for every `expiry_unix_ts`.
  - Location: `programs/shielded-pool/src/instructions/shared.rs:13` (`fn check_not_expired`)
  - Error: `ShieldedPoolError::ExpiredTransaction = 7005`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit (fabricated clock sysvar)

- [x] **INV-XC-08: a paused tree blocks every tree write except unpausing**
  - Covered by all 8 affected instructions: `tree/contract.rs` `pause_blocks_tree_mutation_and_unpause_restores_it` (Deposit/Transact/Merge), `nullifier/batch.rs` `batch_update_rejects_a_paused_tree`, `deposit/rejection.rs` `paused_tree_rejects_zone_deposit`, `merge/contract.rs` `merge_zone_rejects_a_paused_tree`, `transact/guard.rs` `zone_transact_rejects_a_paused_tree`, `zone_authority_transact_rejects_a_paused_tree`
  - Kind: precondition
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact, Deposit, ZoneDeposit, MergeTransact, ZoneMergeTransact, BatchUpdateNullifierTree
  - Statement: while the tree's state byte is exactly `PAUSED` (2), each of these instructions returns Err and no tree byte changes; only `pause_tree` (which loads with `from_account_view_mut_allow_paused`) can operate on a paused tree.
  - Location: `program-libs/tree/src/lib.rs:175-195` (`fn from_account_view_mut`); mappings `transact/processor.rs:240-246` and `merge/processor.rs:174-180` (`fn tree_error`), `deposit/processor.rs:131-133`, `batch_update_nullifier_tree.rs:31-32` (via `From<TreeError>`)
  - Error: `ShieldedPoolError::TreePaused = 7013`
  - Severity: Critical (freeze semantics)
  - Suggested test: negative per instruction; harness: program-tests integration (`cargo test-sbf`)

## Tree Roots and Double-Spend

- [x] **INV-XC-09: a stale or out-of-range root index is rejected**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_a_stale_nullifier_root_index`
  - Kind: precondition
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact, MergeTransact, ZoneMergeTransact
  - Statement: each of these instructions returns Err whenever any input's `utxo_tree_root_index` or `nullifier_tree_root_index` is out of range of the root history, or the referenced nullifier-root slot holds the zeroed (stale) root.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:212-218` and `merge/processor.rs:140-145` (root reads), `program-libs/tree/src/lib.rs:234-250` (`fn get_nullifier_tree_root`), error mapping `transact/processor.rs:243` (`TreeError::InvalidRootIndex`)
  - Error: `ShieldedPoolError::StaleNullifierRoot = 7015`
  - Severity: Critical (spending against a pre-nullification root)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-XC-10: every nullifier is inserted at most once**
  - Covered by: `program-tests/shielded-pool/tests/transact/withdrawal.rs` `shield_before_authority_rotation_then_withdraw_sol` (cross-transaction replay -> 7002 with rollback); `transact/guard.rs` `transact_rejects_a_duplicate_nullifier_within_one_instruction` (two equal nullifiers in one instruction -> 7002)
  - Kind: state
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact, MergeTransact, ZoneMergeTransact
  - Statement: for every 32-byte nullifier value, at most one queue insertion ever succeeds across all instructions and all transactions (including two inputs with the same nullifier inside one instruction); every later insertion attempt makes its instruction return Err.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:219-221` and `merge/processor.rs:146-148` (`insert_address_into_queue`), `program-libs/batched-merkle-tree/src/merkle_tree.rs:311-344`
  - Error: `ShieldedPoolError::NullifierTreeUpdateFailed = 7002`
  - Severity: Critical (double-spend)
  - Suggested test: negative (same nullifier twice across transactions, and twice within one instruction); harness: program-tests integration (`cargo test-sbf`)

## Proof System

- [ ] **INV-XC-11: tampering with any public input invalidates the proof**
  - Partial coverage: `programs/shielded-pool/src/instructions/transact/verify.rs` `program_assembly_matches_the_go_ordering_on_every_variant` (golden vectors pin the full chain ordering; LiteSVM now exercises owner-tag, amount, private-tx-hash, and external-data tampering, but there is still no exhaustive per-field bit-flip loop)
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_tampered_output_owner_tag`, `transact_rejects_tampered_public_amount`, `transact_rejects_tampered_private_transaction_hash`, and `transact_rejects_tampered_external_data`
  - Kind: postcondition
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact, MergeTransact, ZoneMergeTransact
  - Statement: every element of the recomputed public-input hash chain (nullifiers, output hashes, roots, `private_tx_hash`, `external_data_hash`, public amounts, mint, zone program id, payer hash, owner fields) enters the chain exactly once, and changing any single element after proving makes verification return Err; the on-chain assembly is pinned to the Go circuit ordering by golden vectors.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:143-201` (`fn public_input_hash`), `merge/verify.rs:85-131`; vectors `transact/verify.rs:394-765` (`mod circuit_vector_tests`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical
  - Suggested test: property (per-field bit-flip loop) + golden vectors (exist); harness: `cargo test -p zolana-shielded-pool` + program-tests integration

- [ ] **INV-XC-12: proof encoding and rail must match the selected circuit**
  - Not applicable post-PR164 (the P256 rail and the `TransactProof::P256` encoding were removed; `TransactProof` is a single plain Groth16 struct, so no encoding/rail mismatch class remains). The covering `transact_rejects_a_p256_proof_on_the_eddsa_rail` test was removed with the rail.

- [x] **INV-XC-13: undecompressable proof points are an encoding error, not a verification error**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_proof_points_that_fail_decompression`
  - Kind: precondition
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact, MergeTransact, ZoneMergeTransact
  - Statement: every proof whose `a`, `b`, `c`, commitment, or commitment-PoK point fails G1/G2 decompression makes the instruction return the encoding error (7007), and every well-formed proof that fails the pairing returns the verification error (7008); the two failure classes never alias.
  - Location: `programs/shielded-pool/src/instructions/verifier.rs:78-115` (`fn verify_groth16`), `merge/verify.rs:58-67`
  - Error: `ShieldedPoolError::InvalidTransactProofEncoding = 7007` vs `TransactProofVerificationFailed = 7008`
  - Severity: Medium (diagnostic stability)
  - Suggested test: negative both classes; harness: mollusk unit

- [x] **INV-XC-14: verifying keys are pairwise distinct per (variant, shape)**
  - Covered by: `program-libs/interface/tests/vk_fingerprint.rs` `verifying_key_fingerprint_is_pinned`
  - Kind: state
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact, MergeTransact, ZoneMergeTransact
  - Statement: for every supported shape, the confidential, zone, and zone-authority (and for merge: default vs zone) verifying keys are distinct constants, so a proof generated for one variant never verifies under another; the variant is fixed by the dispatched instruction tag, so no attacker-controlled data selects the key family.
  - Location: `program-libs/interface/src/verifying_keys/circuit.rs` (`CircuitId::verifying_key`), `merge/verify.rs:62-65`; all 26 committed keys pinned by `program-libs/interface/tests/vk_fingerprint.rs`
  - Severity: Critical
  - Suggested test: property (exists: fingerprint pin) + negative cross-variant proof; harness: `cargo test -p` + program-tests integration

## External Data Hash

- [x] **INV-XC-15: external_data_hash is domain-separated by instruction tag**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_replay_under_the_zone_transact_tag` (a valid transact payload replayed under the ZONE_TRANSACT tag fails verification)
  - Kind: postcondition
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact, MergeTransact, ZoneMergeTransact
  - Statement: the recomputed `external_data_hash` preimage begins with exactly the invoking instruction's tag byte (0, 2, 3, 12, or 13), so an otherwise identical payload proven for one instruction fails verification under any other.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:145-146` (`spp_instruction_discriminator: discriminator`), `merge/processor.rs:57-58`, `merge_zone/processor.rs:48-49`; preimages `program-libs/interface/src/instruction/instruction_data/transact.rs:339-377`, `merge_transact.rs:124-134`
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: High (cross-instruction replay)
  - Suggested test: negative (transact proof replayed as zone_transact); harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-XC-16: the external_data_hash preimage is injective and binds the decryption context**
  - Covered by: `program-libs/interface/src/instruction/instruction_data/transact.rs` `external_data_hash_is_injective_across_output_message_boundary` (plus the empty-vs-none and owner-tag boundary tests in the same module)
  - Kind: state
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact
  - Statement: the `ExternalDataHash` preimage covers exactly: the instruction discriminator, `expiry_unix_ts`, the resolved `interface_transfers` legs (post-PR164, replacing the old `public_sol_amount`/`public_spl_amount`/`relayer_fee` fields), the `data_hash`/`zone_data_hash` option presence and values, `tx_viewing_pk`, `salt`, the resolved outputs, and the messages. Binding `tx_viewing_pk` and `salt` (the F-05 fix) means a relayer can no longer corrupt the only on-chain decryption context; the count prefixes and presence bytes keep the encoding injective across output/message/owner-tag/data boundaries.
  - Location: `program-libs/interface/src/instruction/instruction_data/transact.rs:329-348` (`struct ExternalDataHash`), hash at `instruction_data/transact.rs` (`fn ExternalDataHash::hash`)
  - Severity: High
  - Suggested test: property (proptest over adjacent encodings; unit tests exist); harness: `cargo test -p zolana-interface`

- [ ] **INV-XC-17: the resolved owner tag, not its encoding, enters the hash**
  - Partial coverage: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_tampered_output_owner_tag` (tamper -> 7008 with rollback; the positive Inline/Account encoding-equivalence and account-reorder cases are untested)
  - Kind: postcondition
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact
  - Statement: `external_data_hash` covers each output's resolved 32-byte owner tag (after `fetch_tag`), so two encodings resolving to the same tag (e.g. `Inline(addr)` vs `Account(i)` pointing at `addr`) produce the same hash, and re-ordering the account list to change an `Account(i)` resolution changes the hash and fails verification.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:59-73` (`fn resolve_outputs`), `program-libs/interface/src/instruction/instruction_data/transact.rs:252-259` (`struct ResolvedOutput`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: High (account-list tampering)
  - Suggested test: negative + positive (encoding equivalence); harness: program-tests integration (`cargo test-sbf`)

## Value and Settlement

- [x] **INV-XC-18: exactly the absolute public amount settles on-chain**
  - Covered by: `program-tests/shielded-pool/tests/transact/withdrawal.rs` `shield_before_authority_rotation_then_withdraw_sol`
  - Kind: postcondition
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact
  - Statement: for every interface-transfer leg, the on-chain settlement moves exactly the leg's `amount` lamports (SOL) or tokens (SPL), independently per leg and in leg order; aggregation into public movement slots affects proof inputs only.
  - Location: `programs/shielded-pool/src/instructions/transact/interface_transfer.rs:79-92` (`fn settle_interface_transfers`), slot aggregation pinned at `transact/verify.rs` (`field_derivation_vector_pins_the_shared_encodings`, `public_slots` entries)
  - Severity: Critical
  - Suggested test: positive (balance deltas); harness: program-tests integration (`cargo test-sbf`)
  - SPEC_DIVERGENCE (resolved 2026-07-23): the spec previously said the program transfers `public_sol_amount + relayer_fee` and typed the amounts as `Option<u64>`; `docs/spec.md` now states signed `Option<i64>` amounts and that exactly the absolute value settles, matching the code.

- [x] **INV-XC-19: shielded balance conservation is enforced only by the proof**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_tampered_public_amount` (the binding half; the in-circuit formula stays INSUFFICIENT_INFO below)
  - Kind: state
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact, MergeTransact, ZoneMergeTransact
  - Statement: the program performs no on-chain amount arithmetic over UTXO values; the conservation relation (sum of input amounts = sum of output amounts + public amount, per asset) holds only because the public amounts, mint, and commitment chains are bound into the verified public-input hash.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:179-200` (`amount_field` elements 8-10 of the chain)
  - Severity: Critical
  - Suggested test: negative (proof for amount A submitted with amount B in instruction data)
  - INSUFFICIENT_INFO: the exact conservation formula lives in the Go circuits (`prover/server/circuits/spp_transaction`, `spp_merge`), outside the analyzed Rust source; on the Rust side only the binding (INV-XC-11) is testable.

- [x] **INV-XC-20: signed public amounts encode as BN254 field elements**
  - Covered by: `programs/shielded-pool/src/instructions/transact/verify.rs` `field_derivation_vector_pins_the_shared_encodings`
  - Kind: state
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact
  - Statement: the public-amount public inputs are exactly `Fr::from(amount)` big-endian (negative amounts reduce modulo the BN254 scalar field), with `None` encoding exactly as 0; the encoding is pinned by the committed field-derivation vector including negative values.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:228-236` (`fn amount_field`), vector test at 699-764
  - Severity: High
  - Suggested test: golden vector (exists); harness: `cargo test -p zolana-shielded-pool`

## Lamports and PDAs

- [ ] **INV-XC-21: lamports are conserved across every instruction**
  - Partial coverage: `program-tests/shielded-pool/tests/deposit/functional.rs` `zone_sol_deposit_settles_and_indexes_the_exact_output` (matched depositor/interface deltas on deposit and withdrawal paths; no total-sum property and no coverage of the creation/admin instructions)
  - Kind: state
  - Affects: all 18 instructions
  - Statement: for every successful instruction, the sum of lamports over all transaction accounts after execution is exactly the sum before, minus nothing (creation instructions move rent from the fee payer to the new account; settlement moves lamports between depositor/recipient and the sol_interface; no path burns or mints lamports inside the program).
  - Location: `programs/shielded-pool/src/instructions/shared.rs:25-72` (`CreatePdaAccount`), `settlement/sol.rs:13-40`
  - Severity: High
  - Suggested test: property (sum lamports before/after per instruction); harness: mollusk unit

- [x] **INV-XC-22: a pre-funded PDA cannot block creation**
  - Covered by: `program-tests/shielded-pool/tests/admin/edge_cases.rs` `protocol_config_creation_succeeds_for_prefunded_pda`; `spl_interface/contract.rs` `asset_counter_creation_succeeds_for_a_prefunded_pda`; `spl_interface/functional.rs` `spl_interface_creation_succeeds_for_prefunded_pdas`; `zone_config/contract.rs` `zone_config_creation_succeeds_for_a_prefunded_pda`
  - Kind: reachability
  - Affects: CreateProtocolConfig, CreateAssetCounter, CreateSplInterface, CreateZoneConfig
  - Statement: for every creation instruction, an attacker donating lamports to the target PDA address before creation does not make the creation fail (the pinocchio minimum-balance helper handles the cold path: allocate + assign + top-up instead of CreateAccount).
  - Location: `programs/shielded-pool/src/instructions/shared.rs:19-72` (`struct CreatePdaAccount`), `zone_config/create.rs:54-61` (`create_account_with_minimum_balance`)
  - Severity: High (DoS on singleton PDAs would be permanent)
  - Suggested test: positive (donate first, then create); harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-XC-23: PDA creation always uses the canonical bump**
  - Partial coverage: `program-tests/shielded-pool/tests/admin/rejection.rs` `asset_counter_creation_rejects_a_non_canonical_pda` (asset counter -> 7016 and zone config -> 7014 tested; protocol config and SPL registry/vault non-canonical addresses untested)
  - Kind: precondition
  - Affects: CreateProtocolConfig, CreateAssetCounter, CreateSplInterface, CreateZoneConfig
  - Statement: every PDA-creating instruction derives the bump via `find_program_address` on-chain and rejects any account address that is not the canonical PDA; no instruction accepts a bump from instruction data for account creation.
  - Location: `programs/shielded-pool/src/instructions/shared.rs:76-90` (`fn verify_pda`), `zone_config/create.rs:33-38, 75-78` (`fn derive_zone_auth`)
  - Error: `ShieldedPoolError::InvalidPda = 7016` (zone config: `InvalidZoneConfig = 7014`)
  - Severity: Critical
  - Suggested test: negative (non-canonical address per instruction); harness: mollusk unit

## Shared State-Struct and Loader Invariants

- [x] **INV-XC-24: every state account is loaded through a checking loader**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `mollusk_deposit_rejects_wrong_tree_owner_exactly` (plus the per-loader cosplay/wrong-owner tests cited in the instruction files)
  - Kind: state
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact, Deposit, ZoneDeposit, MergeTransact, ZoneMergeTransact, CreateTree, BatchUpdateNullifierTree, PauseTree, CreateAssetCounter, CreateSplInterface, UpdateProtocolConfig, UpdateZoneConfig, UpdateZoneConfigOwner
  - Statement: every read or write of a `ProtocolConfig`, `ZoneConfig`, `SplAssetCounter`, `SplAssetRegistry`, tree, token, or user-record account goes through a `load_*`/`from_account_view_*`/`read_*` function that checks program ownership and exact `data_len` (and the discriminator for initialized reads); no instruction deserializes the same account twice.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/loader.rs:14-51`, `zone_config/loader.rs:13-48`, `create_asset_counter.rs:64-77`, `settlement/validate.rs:77-103`, `merge/account.rs:50-62`, `program-libs/tree/src/lib.rs:197-216`
  - Severity: High
  - Suggested test: negative per loader (wrong owner / wrong size / wrong discriminator); harness: mollusk unit

- [x] **INV-XC-25: state struct sizes and discriminators are fixed constants**
  - Covered by: `program-libs/interface/tests/state_props.rs` `state_sizes_and_discriminators_are_stable`
  - Kind: state
  - Affects: CreateProtocolConfig, UpdateProtocolConfig, CreateZoneConfig, UpdateZoneConfig, UpdateZoneConfigOwner, CreateAssetCounter, CreateSplInterface, CreateTree
  - Statement: `ProtocolConfig::SIZE` is exactly 132 with discriminator 3, `ZoneConfig::SIZE` exactly 67 with discriminator 4, `SplAssetCounter::SIZE` exactly 16 with discriminator 6, `SplAssetRegistry::SIZE` exactly 48 with discriminator 5, and the tree discriminator is exactly 1; each created account's `data_len` equals exactly its struct's SIZE.
  - Location: `program-libs/interface/src/state/protocol_config.rs:66-67`, `zone_config.rs:37-38`, `spl_asset_counter.rs:58-59`, `spl_asset_registry.rs:64-65`, `discriminator.rs:1-5`
  - Severity: Medium (compile-time asserts exist; runtime pin catches layout drift)
  - Suggested test: positive (const asserts exist; add explicit pin test mirroring `error_codes_are_stable`); harness: `cargo test -p zolana-interface`

## Zone Authorization Pattern

- [x] **INV-XC-26: zone instructions authorize by zone_config signature, never re-derivation**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `zone_deposit_rejects_an_unsigned_zone_config` (plus the unsigned-config tests on zone_transact and zone merge cited in their files)
  - Kind: precondition
  - Affects: ZoneTransact, ZoneAuthorityTransact, ZoneDeposit, ZoneMergeTransact
  - Statement: each zone instruction requires the `zone_config` account to be a signer and validates it only by owner + size + discriminator (the `zone_auth` derivation is checked exactly once, at `create_zone_config`); consequently a valid, signed config of zone A can never authorize an operation attributed to zone B, because the bound `program_id` is read from the signing account itself.
  - Location: `programs/shielded-pool/src/instructions/zone_transact/account.rs:28-38`, `deposit/account.rs:49-55`, `merge_zone/account.rs:19-29`, `zone_config/loader.rs:13-28`
  - Error: `ShieldedPoolError::InvalidZoneConfig = 7014` / signer errors
  - Severity: Critical
  - Suggested test: negative (unsigned config; config faked with correct bytes but wrong owner); harness: mollusk unit

## Events

- [ ] **INV-XC-27: every successful state-changing instruction emits its event by self-CPI**
  - Partial coverage: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_sends_valid_proof` (transact and deposit events asserted with exact content; the zone/merge/batch variants and the tag-14/zero-accounts inner-instruction structure are not asserted)
  - Kind: postcondition
  - Affects: Transact, ZoneTransact, ZoneAuthorityTransact, Deposit, ZoneDeposit, MergeTransact, ZoneMergeTransact, BatchUpdateNullifierTree (conditional)
  - Statement: after each of these instructions succeeds, the transaction contains exactly one inner instruction to the shielded-pool program itself with first byte `EMIT_EVENT` (14) and zero accounts, carrying the encoded event (for `batch_update_nullifier_tree`: exactly when the update produced an event).
  - Location: `programs/shielded-pool/src/instructions/event.rs:11-35` (`fn emit_encoded_event`)
  - Severity: Medium (indexer completeness)
  - Suggested test: positive per instruction; harness: litesvm (inner-instruction inspection)

## Error Codes

- [x] **INV-XC-28: error codes are stable**
  - Kind: state
  - Affects: all instructions
  - Statement: every `ShieldedPoolError` discriminant equals exactly its documented code (7000..7026 and 7029..7045, 43 variants), pinned one-by-one.
  - Location: `program-libs/interface/src/error.rs`; pin test `error.rs` (`fn error_codes_are_stable`)
  - Severity: Medium (client ABI)
  - Suggested test: positive (exists: `error_codes_are_stable`); harness: `cargo test -p zolana-interface`
  - Covered by: `program-libs/interface/src/error.rs` `error_codes_are_stable`

- [ ] **INV-XC-29: InterfaceError and TreeError conversions are fixed**
  - Partial coverage: `program-tests/shielded-pool/tests/admin/rejection.rs` `pause_tree_rejects_wrong_config_owner_exactly` (the 7012/7013/7001 mappings are exercised through instruction paths; no dedicated conversion-table test)
  - Kind: state
  - Affects: all instructions using loaders or trees
  - Statement: `InterfaceError` converts exactly as InvalidDiscriminator -> 7012, Unauthorized -> 7003, InvalidAccountData -> 7011, AlreadyInitialized -> 7026; `TreeError` converts exactly as Paused -> 7013 and every other variant -> 7001.
  - Location: `program-libs/interface/src/error.rs:85-104` (`impl From<InterfaceError>`, `impl From<TreeError>`)
  - Severity: Medium
  - Suggested test: positive (table test); harness: `cargo test -p zolana-interface`

- [ ] **INV-XC-30: unreachable error variants**
  - Kind: state
  - Affects: none (documentation of dead codes)
  - Statement: INSUFFICIENT_INFO -- `StateAppendFailed = 7004` and `PublicSettlementFailed = 7010` are declared and pinned but no program path returns either; no condition->error invariant can be written for them from the provided source. If they are reserved for future use, document that; otherwise they are dead codes.
  - Location: `program-libs/interface/src/error.rs:33-34, 45-46`
  - Severity: Medium (error-surface hygiene)
  - Suggested test: none possible (flag for the team)
