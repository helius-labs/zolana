# Cross-Cutting Invariants

Invariants that apply to more than one instruction. Each entry lists the affected
instructions; per-instruction files reference these IDs instead of duplicating them.

## Dispatch

- [x] **INV-XC-01: wrong program id is rejected**
  - Covered by: `program-tests/shielded-pool/tests/dispatch/validation.rs` `rejects_the_wrong_program_before_dispatch`
  - Kind: precondition
  - Affects: all 18 instructions
  - Statement: `process_instruction` returns Err whenever the invoked `program_id` differs from the declared program id `sppXZU59VoYodv9Accs4hHNTjYiuYmDFyFVjUjPxFsG`.
  - Location: `programs/shielded-pool/src/lib.rs:38-40` (`fn process_instruction`)
  - Error: `ProgramError::IncorrectProgramId`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-XC-02: empty instruction data is rejected**
  - Covered by: `program-tests/shielded-pool/tests/dispatch/validation.rs` `rejects_empty_unknown_and_malformed_instruction_data_exactly`
  - Kind: precondition
  - Affects: all 18 instructions
  - Statement: `process_instruction` returns Err for the zero-length instruction data (no tag byte).
  - Location: `programs/shielded-pool/src/lib.rs:41-43` (`fn process_instruction`)
  - Error: `ProgramError::InvalidInstructionData`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-XC-03: every unknown tag is rejected**
  - Covered by: `program-tests/shielded-pool/tests/dispatch/validation.rs` `every_first_byte_dispatches_or_is_rejected_exactly` (full 256-byte sweep)
  - Kind: precondition
  - Affects: all 18 instructions
  - Statement: for every first byte outside the set {0..=17}, `process_instruction` returns Err; for every byte inside the set it dispatches to exactly the processor of that tag.
  - Location: `programs/shielded-pool/src/lib.rs:45-75` (`fn process_instruction`), `program-libs/event/src/tag.rs:54-79` (`impl TryFrom<u8> for InstructionTag`)
  - Error: `ProgramError::InvalidInstructionData`
  - Severity: Medium
  - Suggested test: property (all 256 first bytes); harness: mollusk unit

## Atomicity / Rollback

- [x] **INV-XC-04: every failing instruction leaves every account unchanged**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `expect_ix_rejection` (asserts `last_transaction_trace().assert_rolled_back_except(&[payer])` on every Transact, RingTransact, and RingAuthorityTransact rejection, including `ring_transact_rejects_an_unsigned_ring_config` and `ring_authority_transact_rejects_an_unsigned_ring_config`); `program-tests/shielded-pool/tests/deposit/rejection.rs` `sol_deposit_rejects_foreign_tree_atomically` (Deposit) and `paused_tree_rejects_ring_deposit`, `ring_deposit_rejects_a_signer_that_is_not_the_ring_authority`, `ring_deposit_rejects_an_unsigned_ring_config`, `ring_deposit_rejects_malformed_payload_exactly` (RingDeposit); `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_dummy_inputs_after_capacity_threshold` (MergeTransact) and all six `merge_ring_rejects_*` tests (RingMergeTransact); `program-tests/shielded-pool/tests/spl_interface/contract.rs` `asset_counter_rejects_a_non_protocol_authority` and peers (CreateAssetCounter); `program-tests/shielded-pool/tests/ring_config/contract.rs` rejection tests (CreateRingConfig, UpdateRingConfig, UpdateRingConfigOwner); `program-tests/shielded-pool/tests/admin/rejection.rs` (CreateTree, PauseTree); `program-tests/shielded-pool/tests/spl_interface/rejection.rs` (CreateSplInterface and SPL deposit paths); `program-tests/shielded-pool/tests/nullifier/batch.rs` (BatchUpdateNullifierTree); `program-tests/shielded-pool/tests/protocol_config/contract.rs` (UpdateProtocolConfig)
  - Kind: rollback
  - Affects: all 18 instructions
  - Statement: when any shielded-pool instruction returns Err, every account's data and lamports after the transaction equal their values before it (SVM transaction rollback; the program never communicates partial state outside the transaction).
  - Location: `programs/shielded-pool/src/lib.rs:33-76` (`fn process_instruction`); runtime guarantee relied on because tree writes precede proof verification (see INV-XC-05)
  - Severity: Critical
  - Suggested test: negative per instruction (assert full account equality after Err); harness: mollusk unit / litesvm
  - Note: this is the per-instruction "rollback" cell of the coverage matrix; each instruction has at least one failing-path test asserting `last_transaction_trace().assert_rolled_back_except(&[fee_payer])` (full pre/post account equality outside the fee payer) or explicit per-account equality. No legs remain partial.

- [x] **INV-XC-05: a failing proof leaves the trees unchanged**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `default_rail_merge_rejects_a_zeroed_proof_exactly`
  - Kind: rollback
  - Affects: Transact, RingTransact, RingAuthorityTransact, MergeTransact, RingMergeTransact
  - Statement: these instructions insert nullifiers and append outputs before verifying the proof; when verification fails, the transaction aborts and the UTXO tree `next_index`, nullifier queue `next_index`, and all roots after the transaction are exactly their values before it.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:77-117` (tree writes at 77-98, verify at 117), `merge/processor.rs:92-137` (tree writes at 114-127, verify at 130)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (a persisted write with a failed proof would mint unbacked notes)
  - Suggested test: negative (garbage proof, then assert tree state); harness: program-tests integration (`cargo test-sbf`)

## Expiry and Pause

- [x] **INV-XC-06: an expired transaction is rejected**
  - Covered by: `program-tests/shielded-pool/tests/transact/withdrawal.rs` `shield_before_authority_rotation_then_withdraw_sol`
  - Kind: precondition
  - Affects: Transact, RingTransact, RingAuthorityTransact, MergeTransact, RingMergeTransact
  - Statement: each of these instructions returns Err whenever `Clock.unix_timestamp` as u64 is strictly greater than `expiry_unix_ts`; execution at `unix_timestamp == expiry_unix_ts` is still accepted.
  - Location: `programs/shielded-pool/src/instructions/shared.rs:148-153` (`fn check_not_expired`); call sites `transact/processor.rs:48`, `merge/processor.rs:35`, `merge_ring/processor.rs:30`
  - Error: `ShieldedPoolError::ExpiredTransaction = 7005`
  - Severity: High
  - Suggested test: negative + boundary (ts == expiry); harness: litesvm (warped clock)

- [x] **INV-XC-07: a negative clock is rejected**
  - Covered by: `program-tests/shielded-pool/tests/merge/contract.rs` `merge_rejects_a_negative_clock`; `transact/guard.rs` `transact_rejects_a_negative_clock`
  - Kind: precondition
  - Affects: Transact, RingTransact, RingAuthorityTransact, MergeTransact, RingMergeTransact
  - Statement: each of these instructions returns Err whenever `Clock.unix_timestamp` is strictly less than 0, for every `expiry_unix_ts`.
  - Location: `programs/shielded-pool/src/instructions/shared.rs:149` (`fn check_not_expired`)
  - Error: `ShieldedPoolError::ExpiredTransaction = 7005`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit (fabricated clock sysvar)

- [x] **INV-XC-08: a paused tree blocks every tree write except unpausing**
  - Covered by all 8 affected instructions: `tree/contract.rs` `pause_blocks_tree_mutation_and_unpause_restores_it` (Deposit/Transact/Merge), `nullifier/batch.rs` `batch_update_rejects_a_paused_tree`, `deposit/rejection.rs` `paused_tree_rejects_ring_deposit`, `merge/contract.rs` `merge_ring_rejects_a_paused_tree`, `transact/guard.rs` `ring_transact_rejects_a_paused_tree`, `ring_authority_transact_rejects_a_paused_tree`
  - Kind: precondition
  - Affects: Transact, RingTransact, RingAuthorityTransact, Deposit, RingDeposit, MergeTransact, RingMergeTransact, BatchUpdateNullifierTree
  - Statement: while the tree's state byte is exactly `PAUSED` (2), each of these instructions returns Err and no tree byte changes; only `pause_tree` (which loads with `from_account_view_mut_allow_paused`) can operate on a paused tree.
  - Location: `program-libs/tree/src/lib.rs:192-202` (`fn from_account_view_mut`); mapping `programs/shielded-pool/src/instructions/shared.rs:22-29` (`fn tree_error`), `deposit/processor.rs:92-94`, `batch_update_nullifier_tree.rs:35-36` (via `From<TreeError>`)
  - Error: `ShieldedPoolError::TreePaused = 7013`
  - Severity: Critical (freeze semantics)
  - Suggested test: negative per instruction; harness: program-tests integration (`cargo test-sbf`)

## Tree Roots and Double-Spend

- [x] **INV-XC-09: a stale or out-of-range root index is rejected**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_a_stale_nullifier_root_index`
  - Kind: precondition
  - Affects: Transact, RingTransact, RingAuthorityTransact, MergeTransact, RingMergeTransact
  - Statement: each of these instructions returns Err whenever any input's `utxo_tree_root_index` or `nullifier_tree_root_index` is out of range of the root history, or the referenced nullifier-root slot is zero (uninitialized or a synthetic stale-root fixture). Production reclaim naturally overwrites old roots instead of zeroing them.
  - Location: `programs/shielded-pool/src/instructions/transact/tree.rs:25-30` and `merge/processor.rs:155-160` (root reads), `program-libs/tree/src/lib.rs:296-308` (`fn get_nullifier_tree_root`), error mapping `programs/shielded-pool/src/instructions/shared.rs:25` (`tree_error`, `TreeError::InvalidRootIndex`)
  - Error: `ShieldedPoolError::StaleNullifierRoot = 7015`
  - Severity: Critical (spending against a pre-nullification root)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-XC-10: every nullifier is inserted at most once**
  - Covered by: `program-tests/shielded-pool/tests/transact/withdrawal.rs` `shield_before_authority_rotation_then_withdraw_sol` (cross-transaction replay -> 7048 with rollback); `transact/guard.rs` `transact_rejects_a_duplicate_nullifier_within_one_instruction` (two equal nullifiers in one instruction -> 7048); `nullifier/nullifier_pdas.rs` `transact_rejects_a_pending_nullifier`, `transact_rejects_the_same_nullifier_twice_in_one_instruction` (see INV-TRANSACT-47 in `tree.md`)
  - Kind: state
  - Affects: Transact, RingTransact, RingAuthorityTransact, MergeTransact, RingMergeTransact
  - Statement: for every 32-byte nullifier value, at most one queue insertion ever succeeds across all instructions and all transactions (including two inputs with the same nullifier inside one instruction); every later insertion attempt makes its instruction return Err.
  - Location: `programs/shielded-pool/src/instructions/nullifier_pda/loader.rs` (`load_unused_nullifier_pda`: an initialized PDA rejects the insertion), `transact/tree.rs` and `merge/processor.rs` (`insert_nullifier_into_queue`), `program-libs/tree/src/nullifier_tree/merkle_tree_update.rs`
  - Error: `ShieldedPoolError::NullifierAlreadyQueued = 7048`
  - Severity: Critical (double-spend)
  - Suggested test: negative (same nullifier twice across transactions, and twice within one instruction); harness: program-tests integration (`cargo test-sbf`)

## Proof System

- [ ] **INV-XC-11: tampering with any public input invalidates the proof**
  - Partial coverage: `programs/shielded-pool/src/instructions/transact/verify.rs` `program_assembly_matches_the_go_ordering_on_every_variant` (golden vectors pin the full chain ordering; LiteSVM now exercises owner-tag, amount, private-tx-hash, and external-data tampering, but there is still no exhaustive per-field bit-flip loop)
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_tampered_output_owner_tag`, `transact_rejects_tampered_public_amount`, `transact_rejects_tampered_private_transaction_hash`, and `transact_rejects_tampered_external_data`
  - Kind: postcondition
  - Affects: Transact, RingTransact, RingAuthorityTransact, MergeTransact, RingMergeTransact
  - Statement: every element of the recomputed public-input hash chain (nullifiers, output hashes, roots, `private_tx_hash`, `external_data_hash`, public amounts, mint, ring program id, payer hash, owner fields) enters the chain exactly once, and changing any single element after proving makes verification return Err; the on-chain assembly is pinned to the Go circuit ordering by golden vectors.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:133-204` (`fn public_input_hash`), `merge/verify.rs:84-115`; vectors `program-tests/shielded-pool/tests/transact/circuit_vectors.rs`
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical
  - Suggested test: property (per-field bit-flip loop) + golden vectors (exist); harness: `cargo nextest run -p shielded-pool-tests --test transact_circuit_vectors` + program-tests integration

- [x] **INV-XC-12: proof encoding and rail must match the selected circuit**
  - Covered by: `program-tests/ring-test-program/tests/p256_ring_lifecycle.rs` `cross_rail_proof_grafting_is_rejected`
  - Kind: precondition
  - Affects: Transact, RingTransact, RingAuthorityTransact
  - Statement: a proof is only valid under the circuit selector family it was built for: a BSB22-committed P256 proof under the RingEddsa selector fails pairing against the eddsa verifying key (7008); an uncommitted eddsa proof under the RingP256 selector can carry no valid BSB22 commitment (a zeroed one decodes as the point at infinity, so the graft fails at pairing, 7008; garbage bytes fail at encoding, 7007); a wrong selector FAMILY under any tag is rejected pre-account with 7039 (INV-TRANSACT-34).
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs` (`fn verify`, selector-keyed verifying key + commitment leg), `transact/processor.rs:139-151` (`fn validate_circuit_type`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008` / `InvalidTransactProofEncoding = 7007` / `MismatchedCircuitType = 7039`
  - Severity: Critical (cross-rail grafting)
  - Suggested test: negative both graft directions (exists); harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-XC-13: undecompressable proof points are an encoding error, not a verification error**
  - Covered by: `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_proof_points_that_fail_decompression`
  - Kind: precondition
  - Affects: Transact, RingTransact, RingAuthorityTransact, MergeTransact, RingMergeTransact
  - Statement: every proof is a plain 128-byte `a||b||c` (no commitments); every proof whose `a`, `b`, or `c` point fails G1/G2 decompression makes the instruction return the encoding error (7007), and every well-formed proof that fails the pairing returns the verification error (7008); the two failure classes never alias.
  - Location: `programs/shielded-pool/src/instructions/verifier.rs:24-40` (`fn verify_groth16`), `merge/verify.rs:51-73`
  - Error: `ShieldedPoolError::InvalidTransactProofEncoding = 7007` vs `TransactProofVerificationFailed = 7008`
  - Severity: Medium (diagnostic stability)
  - Suggested test: negative both classes; harness: mollusk unit

- [x] **INV-XC-14: verifying keys are pairwise distinct per (variant, shape)**
  - Covered by: `program-libs/interface/tests/vk_fingerprint.rs` `verifying_key_fingerprint_is_pinned`
  - Kind: state
  - Affects: Transact, RingTransact, RingAuthorityTransact, MergeTransact, RingMergeTransact
  - Statement: for every supported shape, the confidential, ring, and ring-authority (and for merge: default vs ring) verifying keys are distinct constants, so a proof generated for one variant never verifies under another; the variant is fixed by the dispatched instruction tag, so no attacker-controlled data selects the key family.
  - Location: `program-libs/interface/src/verifying_keys/circuit.rs` (`CircuitId::verifying_key`), `merge/verify.rs:62-65`; all 26 committed keys pinned by `program-libs/interface/tests/vk_fingerprint.rs`
  - Severity: Critical
  - Suggested test: property (exists: fingerprint pin) + negative cross-variant proof; harness: `cargo test -p` + program-tests integration

## External Data Hash

- [x] **INV-XC-15: external_data_hash is domain-separated by instruction tag**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_replay_under_the_ring_transact_tag` (a valid transact payload replayed under the RING_TRANSACT tag fails verification)
  - Kind: postcondition
  - Affects: Transact, RingTransact, RingAuthorityTransact, MergeTransact, RingMergeTransact
  - Statement: the recomputed `external_data_hash` preimage begins with exactly the invoking instruction's tag byte (12, 13, 15, 16, or 17), so an otherwise identical payload proven for one instruction fails verification under any other.
  - Location: `programs/shielded-pool/src/instructions/transact/processor.rs:100-112` (`spp_instruction_discriminator: instruction as u8`), `merge/processor.rs:54-60`, `merge_ring/processor.rs:34-40`; preimages `program-libs/interface/src/instruction/instruction_data/transact.rs:329-348, 351` (`struct ExternalDataHash`, `fn hash`), `merge_transact.rs:123-137`
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: High (cross-instruction replay)
  - Suggested test: negative (transact proof replayed as ring_transact); harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-XC-16: the external_data_hash preimage is injective and binds the decryption context**
  - Covered by: `program-libs/interface/src/instruction/instruction_data/transact.rs` `external_data_hash_is_injective_across_output_message_boundary` (plus the empty-vs-none and owner-tag boundary tests in the same module)
  - Kind: state
  - Affects: Transact, RingTransact, RingAuthorityTransact
  - Statement: the `ExternalDataHash` preimage covers exactly: the instruction discriminator, `expiry_unix_ts`, the resolved `interface_transfers` legs (post-PR164, replacing the old `public_sol_amount`/`public_spl_amount`/`relayer_fee` fields), the `data_hash`/`ring_data_hash` option presence and values, `tx_viewing_pk`, `salt`, the resolved outputs, and the messages. Binding `tx_viewing_pk` and `salt` (the F-05 fix) means a relayer can no longer corrupt the only on-chain decryption context; the count prefixes and presence bytes keep the encoding injective across output/message/owner-tag/data boundaries.
  - Location: `program-libs/interface/src/instruction/instruction_data/transact.rs:329-348` (`struct ExternalDataHash`), hash at `instruction_data/transact.rs:351` (`fn ExternalDataHash::hash`)
  - Severity: High
  - Suggested test: property (proptest over adjacent encodings; unit tests exist); harness: `cargo test -p zolana-interface`

- [ ] **INV-XC-17: the resolved owner tag, not its encoding, enters the hash**
  - Partial coverage: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_tampered_output_owner_tag` (tamper -> 7008 with rollback; the positive Inline/Account encoding-equivalence and account-reorder cases are untested)
  - Kind: postcondition
  - Affects: Transact, RingTransact, RingAuthorityTransact
  - Statement: `external_data_hash` covers each output's resolved 32-byte owner tag (after `fetch_tag`), so two encodings resolving to the same tag (e.g. `Inline(addr)` vs `Account(i)` pointing at `addr`) produce the same hash, and re-ordering the account list to change an `Account(i)` resolution changes the hash and fails verification.
  - Location: `programs/shielded-pool/src/instructions/transact/event.rs:22-35` (`fn resolve_outputs`), `program-libs/interface/src/instruction/instruction_data/transact.rs:240-244` (`struct ResolvedOutput`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: High (account-list tampering)
  - Suggested test: negative + positive (encoding equivalence); harness: program-tests integration (`cargo test-sbf`)

## Value and Settlement

- [x] **INV-XC-18: exactly the absolute public amount settles on-chain**
  - Covered by: `program-tests/shielded-pool/tests/transact/withdrawal.rs` `shield_before_authority_rotation_then_withdraw_sol`
  - Kind: postcondition
  - Affects: Transact, RingTransact, RingAuthorityTransact
  - Statement: for every interface-transfer leg, the on-chain settlement moves exactly the leg's `amount` lamports (SOL) or tokens (SPL), independently per leg and in leg order; aggregation into public movement slots affects proof inputs only.
  - Location: `programs/shielded-pool/src/instructions/transact/interface_transfer.rs:79-92` (`fn settle_interface_transfers`), slot aggregation pinned at `transact/verify.rs` (`field_derivation_vector_pins_the_shared_encodings`, `public_slots` entries)
  - Severity: Critical
  - Suggested test: positive (balance deltas); harness: program-tests integration (`cargo test-sbf`)
  - SPEC_DIVERGENCE (resolved 2026-07-23): the spec previously said the program transfers `public_sol_amount + relayer_fee` and typed the amounts as `Option<u64>`; `docs/spec.md` now states signed `Option<i64>` amounts and that exactly the absolute value settles, matching the code.

- [x] **INV-XC-19: shielded balance conservation is enforced only by the proof**
  - Covered by: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_rejects_tampered_public_amount` (the binding half; the in-circuit formula stays INSUFFICIENT_INFO below)
  - Kind: state
  - Affects: Transact, RingTransact, RingAuthorityTransact, MergeTransact, RingMergeTransact
  - Statement: the program performs no on-chain amount arithmetic over UTXO values; the conservation relation (sum of input amounts = sum of output amounts + public amount, per asset) holds only because the public amounts, mint, and commitment chains are bound into the verified public-input hash.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:188-191` (public-slot asset/amount elements of the chain), `transact/verify.rs:207-221` (`fn amount_field`)
  - Severity: Critical
  - Suggested test: negative (proof for amount A submitted with amount B in instruction data)
  - INSUFFICIENT_INFO: the exact conservation formula lives in the Go circuits (`prover/server/circuits/spp_transaction`, `spp_merge`), outside the analyzed Rust source; on the Rust side only the binding (INV-XC-11) is testable.

- [x] **INV-XC-20: signed public amounts encode as BN254 field elements**
  - Covered by: `program-tests/shielded-pool/tests/transact/circuit_vectors.rs` `field_derivation_vector_pins_the_shared_encodings`
  - Kind: state
  - Affects: Transact, RingTransact, RingAuthorityTransact
  - Statement: the public-amount public inputs are exactly `Fr::from(amount)` big-endian (negative amounts reduce modulo the BN254 scalar field); slots are aggregated `i128` per asset with unused slots exactly zero; the encoding is pinned by the committed field-derivation vector including negative values.
  - Location: `programs/shielded-pool/src/instructions/transact/verify.rs:207-221` (`fn amount_field`), vector test at 526-620
  - Severity: High
  - Suggested test: golden vector (exists); harness: `cargo nextest run -p shielded-pool-tests --test transact_circuit_vectors`

## Lamports and PDAs

- [ ] **INV-XC-21: lamports are conserved across every instruction**
  - Partial coverage: `program-tests/shielded-pool/tests/deposit/functional.rs` `ring_sol_deposit_settles_and_indexes_the_exact_output` (matched depositor/interface deltas on deposit and withdrawal paths; no total-sum property and no coverage of the creation/admin instructions)
  - Kind: state
  - Affects: all 18 instructions
  - Statement: for every successful instruction, the sum of lamports over all transaction accounts after execution is exactly the sum before, minus nothing (creation instructions move rent from the fee payer to the new account; settlement moves lamports between depositor/recipient and the sol_interface; no path burns or mints lamports inside the program).
  - Location: `programs/shielded-pool/src/instructions/shared.rs:161-208` (`CreatePdaAccount`), `settlement/sol.rs:13-40`
  - Severity: High
  - Suggested test: property (sum lamports before/after per instruction); harness: mollusk unit

- [x] **INV-XC-22: a pre-funded PDA cannot block creation**
  - Covered by: `program-tests/shielded-pool/tests/admin/edge_cases.rs` `protocol_config_creation_succeeds_for_prefunded_pda`; `spl_interface/contract.rs` `asset_counter_creation_succeeds_for_a_prefunded_pda`; `spl_interface/functional.rs` `spl_interface_creation_succeeds_for_prefunded_pdas`; `ring_config/contract.rs` `ring_config_creation_succeeds_for_a_prefunded_pda`
  - Kind: reachability
  - Affects: CreateProtocolConfig, CreateAssetCounter, CreateSplInterface, CreateRingConfig
  - Statement: for every creation instruction, an attacker donating lamports to the target PDA address before creation does not make the creation fail (the pinocchio minimum-balance helper handles the cold path: allocate + assign + top-up instead of CreateAccount).
  - Location: `programs/shielded-pool/src/instructions/shared.rs:161-208` (`struct CreatePdaAccount`), `ring_config/create.rs:53-60` (`create_account_with_minimum_balance`)
  - Severity: High (DoS on singleton PDAs would be permanent)
  - Suggested test: positive (donate first, then create); harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-XC-23: PDA creation always uses the canonical bump**
  - Partial coverage: `program-tests/shielded-pool/tests/admin/rejection.rs` `asset_counter_creation_rejects_a_non_canonical_pda` (asset counter -> 7016 and ring config -> 7014 tested; protocol config and SPL registry/vault non-canonical addresses untested)
  - Kind: precondition
  - Affects: CreateProtocolConfig, CreateAssetCounter, CreateSplInterface, CreateRingConfig
  - Statement: every PDA-creating instruction derives the bump via `find_program_address` on-chain and rejects any account address that is not the canonical PDA; no instruction accepts a bump from instruction data for account creation.
  - Location: `programs/shielded-pool/src/instructions/shared.rs:213-226` (`fn verify_pda`), `ring_config/create.rs:32-37, 71-79` (`fn derive_ring_auth`)
  - Error: `ShieldedPoolError::InvalidPda = 7016` (ring config: `InvalidRingConfig = 7014`)
  - Severity: Critical
  - Suggested test: negative (non-canonical address per instruction); harness: mollusk unit

## Shared State-Struct and Loader Invariants

- [x] **INV-XC-24: every state account is loaded through a checking loader**
  - Covered by: `program-tests/shielded-pool/tests/deposit/rejection.rs` `mollusk_deposit_rejects_wrong_tree_owner_exactly` (plus the per-loader cosplay/wrong-owner tests cited in the instruction files)
  - Kind: state
  - Affects: Transact, RingTransact, RingAuthorityTransact, Deposit, RingDeposit, MergeTransact, RingMergeTransact, CreateTree, BatchUpdateNullifierTree, PauseTree, CreateAssetCounter, CreateSplInterface, UpdateProtocolConfig, UpdateRingConfig, UpdateRingConfigOwner
  - Statement: every read or write of a `ProtocolConfig`, `RingConfig`, `SplAssetCounter`, `SplAssetRegistry`, tree, token, or user-record account goes through a `load_*`/`from_account_view_*`/`read_*` function that checks program ownership and exact `data_len` (and the discriminator for initialized reads); no instruction deserializes the same account twice.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/loader.rs:14-51`, `ring_config/loader.rs:14-48`, `create_asset_counter.rs:63-70`, `settlement/validate.rs:60-149`, `merge/account.rs:58-89`, `program-libs/tree/src/lib.rs:214-238`
  - Severity: High
  - Suggested test: negative per loader (wrong owner / wrong size / wrong discriminator); harness: mollusk unit

- [x] **INV-XC-25: state struct sizes and discriminators are fixed constants**
  - Covered by: `program-libs/interface/tests/state_props.rs` `state_sizes_and_discriminators_are_stable`
  - Kind: state
  - Affects: CreateProtocolConfig, UpdateProtocolConfig, CreateRingConfig, UpdateRingConfig, UpdateRingConfigOwner, CreateAssetCounter, CreateSplInterface, CreateTree
  - Statement: `ProtocolConfig::SIZE` is exactly 132 with discriminator 3, `RingConfig::SIZE` exactly 68 with discriminator 4, `SplAssetCounter::SIZE` exactly 16 with discriminator 6, `SplAssetRegistry::SIZE` exactly 48 with discriminator 5, and the tree discriminator is exactly 1; each created account's `data_len` equals exactly its struct's SIZE.
  - Location: `program-libs/interface/src/state/protocol_config.rs:66-67`, `ring_config.rs:37-38`, `spl_asset_counter.rs:58-59`, `spl_asset_registry.rs:64-65`, `discriminator.rs:1-5`
  - Severity: Medium (compile-time asserts exist; runtime pin catches layout drift)
  - Suggested test: positive (const asserts exist; add explicit pin test mirroring `error_codes_are_stable`); harness: `cargo test -p zolana-interface`

## Ring Authorization Pattern

- [x] **INV-XC-26: ring instructions require a signed, active ring_config and never re-derive it**
  - Covered by: the unsigned and paused-config rejection tests in `deposit/rejection.rs`, `transact/guard.rs`, and `merge/contract.rs`
  - Kind: precondition
  - Affects: RingTransact, RingAuthorityTransact, RingDeposit, RingMergeTransact
  - Statement: each operational ring instruction requires the `ring_config` account to be a signer, validates owner + size + discriminator, and requires `paused == 0` (the `ring_auth` derivation is checked exactly once, at `create_ring_config`); consequently a valid, signed config of ring A can never authorize an operation attributed to ring B, and a paused ring cannot mutate protocol state. Administrative config update and rotation remain available while paused.
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs:140-163` (`RingTransactAccounts::validate_and_parse`), `deposit/account.rs:77-78`, `merge_ring/account.rs:22-39`, `ring_config/loader.rs:14-20`
  - Error: `ShieldedPoolError::InvalidRingConfig = 7014` / `ShieldedPoolError::RingPaused = 7047` / signer errors
  - Severity: Critical
  - Suggested test: negative (unsigned config; config faked with correct bytes but wrong owner); harness: mollusk unit

## Events

- [ ] **INV-XC-27: every successful state-changing instruction emits its event by self-CPI**
  - Partial coverage: `program-tests/shielded-pool/tests/transact/functional.rs` `transact_sends_valid_proof` (transact and deposit events asserted with exact content; the ring/merge/batch variants and the tag-10/zero-accounts inner-instruction structure are not asserted)
  - Kind: postcondition
  - Affects: Transact, RingTransact, RingAuthorityTransact, Deposit, RingDeposit, MergeTransact, RingMergeTransact, BatchUpdateNullifierTree (conditional)
  - Statement: after each of these instructions succeeds, the transaction contains exactly one inner instruction to the shielded-pool program itself with first byte `EMIT_EVENT` (10) and zero accounts, carrying the encoded event (for `batch_update_nullifier_tree`: exactly when the update produced an event).
  - Location: `programs/shielded-pool/src/instructions/event.rs:11-19` (`fn emit_encoded_event`)
  - Severity: Medium (indexer completeness)
  - Suggested test: positive per instruction; harness: litesvm (inner-instruction inspection)

## Error Codes

- [x] **INV-XC-28: error codes are stable**
  - Kind: state
  - Affects: all instructions
  - Statement: every `ShieldedPoolError` discriminant equals exactly its documented code (live range 7000..7019, 7022, 7025..7047 — 44 variants, including `ZeroNetInterfaceTransferAmount = 7045`, `SplAssetCounterAlreadyInitialized = 7046`, and `RingPaused = 7047`; 7020/7021/7023/7024 retired; 7044 retired in place, kept for wire-code stability), pinned one-by-one with a compiler-exhaustive variant match and a count assert.
  - Location: `program-libs/interface/src/error.rs`; pin test `error.rs` (`fn error_codes_are_stable`)
  - Severity: Medium (client ABI)
  - Suggested test: positive (exists: `error_codes_are_stable`); harness: `cargo test -p zolana-interface`
  - Covered by: `program-libs/interface/src/error.rs` `error_codes_are_stable`

- [x] **INV-XC-29: InterfaceError and TreeError conversions are fixed**
  - Covered by: `program-libs/interface/tests/error_conversions.rs` `interface_error_conversions_are_stable`, `tree_error_conversions_are_stable` (full per-variant tables incl. the catch-all enumeration)
  - Kind: state
  - Affects: all instructions using loaders or trees
  - Statement: `InterfaceError` converts exactly as InvalidDiscriminator -> 7012, Unauthorized -> 7003, InvalidAccountData -> 7011, InvalidProtocolConfigData -> 7012; `TreeError` converts exactly as Paused -> 7013, TreeIsFull -> 7004, and every other variant -> 7001.
  - Location: `program-libs/interface/src/error.rs:128-151` (`impl From<InterfaceError>`, `impl From<TreeError>`)
  - Severity: Medium
  - Suggested test: none remaining (table test exists)

- [ ] **INV-XC-30: formerly-"unreachable" error variants are both reachable**
  - Kind: state
  - Affects: none (documentation of previously dead codes)
  - Statement: resolved post-PR171 — `StateAppendFailed = 7004` fires when a UTXO-tree append hits a full tree (`tree_error` maps `TreeError::TreeIsFull`; pinned by INV-XC-31), and `PublicSettlementFailed = 7010` fires when an SPL deposit CPI does not credit the vault exactly the leg amount (pinned by INV-TRANSACT-44). Both are reachable; the earlier INSUFFICIENT_INFO "no program path returns either" claim was falsified.
  - Location: `program-libs/interface/src/error.rs:38-39, 50-51`
  - Severity: Medium (error-surface hygiene)
  - Suggested test: none (pointer entry; the firing conditions carry their own invariants)

- [x] **INV-XC-31: tree_error maps TreeError to exactly four pool errors**
  - Covered by: `program-tests/shielded-pool/tests/tree/contract.rs` `tree_error_table_is_stable` (full per-variant table incl. every catch-all variant), `deposit_rejects_an_append_to_a_full_utxo_tree` (7004 full-tree append leg, deposit path via `From<TreeError>`), `program-libs/interface/tests/error_conversions.rs` `tree_error_conversions_are_stable` (the interface `From<TreeError>` table)
  - Kind: state
  - Affects: Transact, RingTransact, RingAuthorityTransact, Deposit, RingDeposit, MergeTransact, RingMergeTransact (via `tree_error`); BatchUpdateNullifierTree (via `From<TreeError>`)
  - Statement: `tree_error` maps `Paused -> 7013`, `InvalidRootIndex -> 7015`, `TreeIsFull -> 7004` (a full UTXO tree on append), every other variant -> 7001. The `From<TreeError>` impl agrees on `Paused`/`TreeIsFull` but maps `InvalidRootIndex -> 7001` (the batch-update path has no stale-root reads, so the 7015 leg exists only in `tree_error`).
  - Location: `programs/shielded-pool/src/instructions/shared.rs:22-29` (`fn tree_error`), `program-libs/interface/src/error.rs:142-151` (`impl From<TreeError>`)
  - Severity: Medium
  - Suggested test: positive (table test incl. the 7004 leg); harness: mollusk unit

- [x] **INV-XC-32: retired wire formats fail closed at decode, new wire formats are fixed-width**
  - Covered by: `program-libs/interface/src/instruction/instruction_data/transact.rs` units `rejects_retired_field_bearing_payload`, `rejects_retired_owner_tag_discriminant`
  - Kind: precondition
  - Affects: Transact, RingTransact, RingAuthorityTransact
  - Statement: payloads carrying the retired `p256_signing_pk_x` field encoding, the retired `OwnerTag::P256SigningKey` discriminant, or the retired per-input `eddsa_signer_index` byte fail deserialization (both owned and ref decoders) — the pre-PR172 P256 surface did NOT return and cannot be reintroduced by old clients. The NEW PR172 wire surface is fixed-width: `InputUtxo` is exactly 3 fields (nullifier, two root indices) and `RingP256ProofData` a statically-sized `(Bsb22Commitment, optional default_owner_tag)` adapter, so selector-bearing payloads decode allocation-free and any length drift fails closed.
  - Location: `program-libs/interface/src/instruction/instruction_data/transact.rs` (decoder tests), `program-libs/interface/src/verifying_keys/circuit.rs` (`RingP256ProofData`, `FixedOptionOwnerTag`)
  - Error: decode error (`ProgramError::InvalidInstructionData` at dispatch)
  - Severity: Medium
  - Suggested test: negative (exists); harness: `cargo test -p zolana-interface`

- [x] **INV-XC-33: RingP256ProofData is canonical and bound**
  - Covered by: `program-tests/ring-test-program/tests/p256_ring_lifecycle.rs` (`p256_ring_transfer_updates_recipient_wallet` bad-commitment leg, `default_ring_p256_input_exposes_and_binds_owner_tag` wrong-tag leg)
  - Kind: precondition
  - Affects: RingTransact (RingP256 selector)
  - Statement: the proof-specific payload travels inside the `CircuitId::RingP256` selector, not in `TransactProof`/`TransactIxData`, so the non-P256 layouts need no proof-specific fields and every selector stays statically sized; the embedded BSB22 commitment must verify against the proof (7007 otherwise), and `default_owner_tag` — when `Some` — is `hash_bytes`-bound into the public input (a wrong tag fails pairing, 7008).
  - Location: `program-libs/interface/src/verifying_keys/circuit.rs` (`RingP256ProofData`, `FixedOptionOwnerTag`), `programs/shielded-pool/src/instructions/transact/verify.rs` (commitment + `default_p256_owner_tag` legs)
  - Error: `ShieldedPoolError::InvalidTransactProofEncoding = 7007` / `TransactProofVerificationFailed = 7008`
  - Severity: High
  - Suggested test: negative both legs (exist); harness: program-tests integration (`cargo test-sbf`)
