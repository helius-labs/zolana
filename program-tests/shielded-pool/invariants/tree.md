# Tree Invariants

Covers `CreateTree` (tag 2), `BatchUpdateNullifierTree` (tag 4), `PauseTree` (tag 3),
`CloseNullifierMarkers` (tag 18), and the nullifier-marker accounts the transact
family creates while queueing nullifiers. Shared invariants (pause semantics across
write paths, rollback) live in `cross-cutting.md`.

Convention deviations confirmed for the marker design (`program-libs/batched-merkle-tree/spec.md`):
`close_nullifier_markers` is permissionless, takes no fee payer, and returns marker rent
to the tree (a caller-chosen `rent_recipient` would drain the tree's marker working
capital); the marker payload is a discriminator-less 9-byte Borsh
`NullifierMarker { queue_index, bump }`; a duplicate pending nullifier surfaces as
`ShieldedPoolError::NullifierAlreadyQueued = 7048`.

SPEC_DIVERGENCE (resolved 2026-07-23): the spec previously stated UTXO tree height 26
and omitted `batch_update_nullifier_tree` from the instruction table; `docs/spec.md`
now states H=32 and lists tag 4.

## CreateTree

### Authorization

- [x] **INV-CREATE-TREE-01: authority must sign**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `tree_creation_rejects_an_unsigned_authority`
  - Kind: precondition
  - Statement: `create_tree` can only succeed when the first account (`authority`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/create_tree.rs:15` (`fn process_create_tree`)
  - Error: account-checks signer error
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CREATE-TREE-02: non-permissionless creation requires the tree-creation authority**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `tree_creation_rejects_unconfigured_authority`
  - Kind: precondition
  - Statement: when `protocol_config.tree_creation_is_permissionless` is exactly 0, `create_tree` returns Err for every signer whose address differs from `protocol_config.tree_creation_authority`.
  - Location: `programs/shielded-pool/src/instructions/create_tree.rs:20-27` (`fn process_create_tree`)
  - Error: `ShieldedPoolError::UnauthorizedCaller = 7003`
  - Severity: High
  - Suggested test: negative + positive (permissionless flag set); harness: mollusk unit

### Account Constraints

- [x] **INV-CREATE-TREE-03: tree account must be owned by the program**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `tree_creation_rejects_an_account_not_owned_by_the_pool`
  - Kind: precondition
  - Statement: `create_tree` returns Err whenever the tree account is not owned by the shielded-pool program (the account is pre-allocated by the client; the program only initializes it).
  - Location: `programs/shielded-pool/src/instructions/create_tree.rs:28` (`fn process_create_tree`)
  - Error: account-checks owner error
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CREATE-TREE-04: tree account length must equal the canonical layout size**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `undersized_tree_creation_is_rejected`, `oversized_tree_creation_is_rejected`
  - Kind: precondition
  - Statement: `create_tree` returns Err whenever the tree account's `data_len` differs from exactly `TreeAccount::account_size()`.
  - Location: `programs/shielded-pool/src/instructions/create_tree.rs:30-32` (`fn process_create_tree`)
  - Error: `ShieldedPoolError::InvalidTreeAccounts = 7001`
  - Severity: High
  - Suggested test: negative (both shorter and longer); harness: mollusk unit

### Instruction Data Validation

- [x] **INV-CREATE-TREE-05: malformed or trailing instruction data is rejected**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `tree_creation_rejects_trailing_instruction_bytes`
  - Kind: precondition
  - Statement: `create_tree` returns Err for every non-empty payload that is not exactly one borsh `InitAddressTreeAccountsInstructionData` (parse failure or trailing bytes both fail); an empty payload is valid and selects the canonical parameters via `address_tree_params()`.
  - Location: `programs/shielded-pool/src/instructions/create_tree.rs:50-64` (`fn parse_create_tree_data`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative + fuzz; harness: mollusk unit

- [x] **INV-CREATE-TREE-06: non-canonical nullifier parameters are rejected**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `tree_creation_rejects_non_canonical_nullifier_params`
  - Kind: precondition
  - Statement: `create_tree` returns Err whenever the supplied nullifier parameters have `root_history_capacity` different from the canonical capacity or a `input_queue_batch_size / input_queue_zkp_batch_size` ratio different from the canonical ZKP batch count.
  - Location: `program-libs/tree/src/lib.rs:138-150` (`fn TreeAccount::init` parameter checks), `programs/shielded-pool/src/instructions/create_tree.rs:39-46`
  - Error: `ShieldedPoolError::InvalidTreeAccounts = 7001`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Success Postconditions

- [x] **INV-CREATE-TREE-07: initialization stamps discriminator and state exactly once**
  - Covered by: `program-libs/tree/tests/init.rs` `init_then_reload` (extended to assert `state == INITIALIZED`)
  - Kind: postcondition
  - Statement: after a successful `create_tree`, the tree account's first byte is exactly `TREE_ACCOUNT_DISCRIMINATOR` (1), its state byte is exactly `INITIALIZED` (1), the UTXO tree's `next_index` is exactly 0, and the nullifier tree is initialized with the supplied owner.
  - Location: `programs/shielded-pool/src/instructions/create_tree.rs:39-46` (`fn process_create_tree`), `program-libs/tree/src/lib.rs:122-177`
  - Severity: High
  - Suggested test: positive; harness: mollusk unit (exists: `program-libs/tree/tests/init.rs`)

- [x] **INV-CREATE-TREE-08: re-initialization is impossible**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `tree_creation_rejects_double_initialization`
  - Kind: precondition
  - Statement: `create_tree` on an account whose state byte is not exactly `UNINITIALIZED` (0) returns Err and leaves the account unchanged.
  - Location: `program-libs/tree/src/lib.rs:157-159` (`fn TreeAccount::init`)
  - Error: `ShieldedPoolError::InvalidTreeAccounts = 7001`
  - Severity: Critical (tree reset would erase nullifiers)
  - Suggested test: negative; harness: mollusk unit

### Frame Conditions

- [x] **INV-CREATE-TREE-09: only the tree account changes**
  - Covered by: `program-tests/shielded-pool/tests/admin/functional.rs` `tree_creation_changes_only_the_tree_account`
  - Kind: frame
  - Statement: after a successful `create_tree`, every account other than the tree account has unchanged data and unchanged lamports (the protocol config is read-only; no lamports move).
  - Location: `programs/shielded-pool/src/instructions/create_tree.rs:12-48` (`fn process_create_tree`)
  - Severity: Medium
  - Suggested test: positive; harness: mollusk unit

## BatchUpdateNullifierTree

### Authorization

- [x] **INV-BATCH-NULL-01: authority must sign**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/batch.rs` `batch_update_rejects_an_unsigned_authority`
  - Kind: precondition
  - Statement: `batch_update_nullifier_tree` can only succeed when the first account (`authority`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/batch_update_nullifier_tree.rs:22` (`fn process_batch_update_nullifier_tree`)
  - Error: account-checks signer error
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-BATCH-NULL-02: only the forester authority may update**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/batch.rs` `batch_update_rejects_a_non_forester_authority`
  - Kind: precondition
  - Statement: `batch_update_nullifier_tree` returns Err for every signer whose address differs from `protocol_config.forester_authority`; there is no permissionless flag for this instruction.
  - Location: `programs/shielded-pool/src/instructions/batch_update_nullifier_tree.rs:28-30` (`fn process_batch_update_nullifier_tree`)
  - Error: `ShieldedPoolError::UnauthorizedCaller = 7003`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Instruction Data Validation

- [x] **INV-BATCH-NULL-03: malformed borsh payload is rejected**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/batch.rs` `batch_update_rejects_malformed_instruction_data`
  - Kind: precondition
  - Statement: every payload that `BatchUpdateNullifierTreeData::try_from_slice` fails to parse makes the instruction return Err.
  - Location: `programs/shielded-pool/src/instructions/batch_update_nullifier_tree.rs:19-20` (`fn process_batch_update_nullifier_tree`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative + fuzz; harness: mollusk unit

### Success Postconditions

- [ ] **INV-BATCH-NULL-04: an invalid batch proof leaves the tree root unchanged**
  - Partial coverage: `program-tests/shielded-pool/tests/nullifier/batch.rs` `batch_update_rejects_a_proof_for_an_unready_zkp_batch` (unready batch and out-of-range zkp_batch_index both return exact 7002 with a full tree-bytes rollback compare; the tampered-proof-on-a-full-batch direction needs 250 queued nullifiers and remains covered only by `localnet/photon/forester.rs`)
  - Kind: rollback
  - Statement: when the batched-tree update rejects the supplied ZKP (wrong proof, wrong batch), the instruction returns Err and the nullifier tree root, sequence number, and queue state are unchanged.
  - Location: `programs/shielded-pool/src/instructions/batch_update_nullifier_tree.rs:37-40` (`fn process_batch_update_nullifier_tree`)
  - Error: `ShieldedPoolError::NullifierTreeUpdateFailed = 7002`
  - Severity: Critical (forged tree roots)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-BATCH-NULL-05: a successful update emits the batch event exactly when one is produced**
  - Partial coverage: `program-tests/shielded-pool/tests/localnet/photon/forester.rs` `nullifier_test_forester_batches_queued_nullifiers_with_photon_indexer` (nullifier root advances via the forester; the `EmitEvent` self-CPI itself is not asserted)
  - Kind: postcondition
  - Statement: after a successful `batch_update_nullifier_tree` that produced a `BatchAddressAppendEvent`, exactly one self-CPI `EmitEvent` inner instruction carrying that event is recorded; when the update produces no event, no self-CPI occurs.
  - Location: `programs/shielded-pool/src/instructions/batch_update_nullifier_tree.rs:43-52` (`fn process_batch_update_nullifier_tree`)
  - Severity: Medium (forester/indexer sync)
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

### Frame Conditions

- [ ] **INV-BATCH-NULL-06: only the tree account data changes; lamports move tree → recipient**
  - Partial coverage: `program-tests/shielded-pool/tests/nullifier/batch.rs` `batch_update_rejects_a_proof_for_an_unready_zkp_batch` (failing-path frame asserted; no positive batch-update path is feasible off localnet for the success-path frame); the reimbursement half is unit-tested in `shared.rs` (`reimbursement_moves_funded_lamports_and_preserves_rent`)
  - Kind: frame
  - Statement: after a successful `batch_update_nullifier_tree`, every account other than the tree account and the `reimbursement_recipient` has unchanged data and unchanged lamports; the tree's data changes and its lamports decrease by exactly `applied_batches` × `FORESTER_REIMBURSEMENT_LAMPORTS`, which the recipient gains (INV-BATCH-NULL-08); the recipient's data is unchanged.
  - Location: `programs/shielded-pool/src/instructions/batch_update_nullifier_tree.rs:15-54`
  - Severity: Medium
  - Suggested test: positive; harness: mollusk unit

### Indexer Sync

- [~] **INV-BATCH-NULL-07: Photon records a batch update only from an authenticated emitted event**
  - Cross-branch coverage: the event-sourced parser and its tests live on the security/photon-batch-event-sourcing branch, landing before this one — the `services/photon/src/ingester/parser/nullifier_tree_batch_update_parser.rs` test module there (`drops_forged_batch_update_cpi_without_event`, `drops_successful_batch_update_without_event`, `drops_event_with_foreign_parent`, `drops_event_under_non_batch_update_parent`, `parses_batch_update_from_emitted_event`, `records_event_root_not_instruction_root`; on THIS branch the parser is reverted to the instruction-intent form)
  - Kind: postcondition (indexer)
  - Statement: Photon ingests a nullifier-tree batch update only from a `BatchAddressAppendEvent` carried by an `EMIT_EVENT` inner instruction whose stack-height parent is a shielded-pool `BATCH_UPDATE_NULLIFIER_TREE` instruction (the program emits the event only when an update actually applied). A forged tag-4 CPI that fails the on-chain forester-authority check, a successful no-op update, and a forged `EMIT_EVENT` with a foreign parent all record nothing; the tree and new root are taken from the event, never from instruction data (F-04).
  - Location: `services/photon/src/ingester/parser/nullifier_tree_batch_update_parser.rs` (`fn parse_nullifier_tree_batch_update`)
  - Severity: Critical (permissionless indexer halt)
  - Suggested test: negative + positive; harness: photon parser unit tests

### Forester Reimbursement

- [x] **INV-BATCH-NULL-08: forester reimbursement preserves the tree's rent floor**
  - Covered by: `program-tests/shielded-pool/tests/tree/contract.rs` `reimbursement_moves_funded_lamports_and_preserves_rent`, `reimbursement_cannot_spend_tree_rent` (7027 leg), `reimbursement_recipient_balance_overflow_is_invalid_forester_fee` (7026 leg)
  - Kind: postcondition
  - Statement: when an update applies N batches, the tree's lamports decrease by exactly N × `FORESTER_REIMBURSEMENT_LAMPORTS` and the `reimbursement_recipient` gains exactly that amount; the transfer fails with 7027 unless the tree keeps at least its rent-exempt minimum, with 7026 on amount overflow, and with 7001 when tree == recipient; an update that applies zero batches (no event produced) skips reimbursement entirely.
  - Location: `programs/shielded-pool/src/instructions/batch_update_nullifier_tree.rs:49-52`, `shared.rs:107-143` (`fn reimburse_forester`)
  - Error: `ShieldedPoolError::InsufficientForesterFeeBalance = 7027` / `InvalidForesterFee = 7026` / `InvalidTreeAccounts = 7001`
  - Severity: High (tree-fund drainage)
  - Suggested test: positive + negative (rent floor); harness: mollusk unit

- [ ] **INV-BATCH-NULL-09: the event emit is the last fallible operation**
  - Partial coverage: photon parser tests (the consumer half: Photon records updates only from events in successful transactions); the ordering itself is a documented code invariant, untestable directly
  - Kind: state
  - Statement: every fallible step (including `reimburse_forester`) precedes the `emit_batch_address_append_event` self-CPI; Photon's parser records updates only from events in successful transactions, so an emit-then-fail shape would drop a genuine update or wedge the indexer on a forged one (F-04 companion).
  - Location: `programs/shielded-pool/src/instructions/batch_update_nullifier_tree.rs:43-52` (documented code INVARIANT)
  - Severity: Critical (indexer wedge, F-04 companion)
  - Suggested test: none possible on-chain (convention); consumer half exists as photon parser unit tests

## PauseTree

### Authorization

- [x] **INV-PAUSE-TREE-01: only the protocol authority may pause or unpause**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `pause_tree_rejects_wrong_authority_exactly`
  - Kind: precondition
  - Statement: `pause_tree` returns Err for every signer whose address differs from `protocol_config.protocol_authority`.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/pause_tree.rs:19` (`fn process_pause_tree`), `protocol_config/loader.rs:39-51`
  - Error: `ShieldedPoolError::UnauthorizedCaller = 7003` (non-signer authority: `InvalidProtocolConfig = 7012`)
  - Severity: Critical (freeze power)
  - Suggested test: negative; harness: mollusk unit

### Instruction Data Validation

- [x] **INV-PAUSE-TREE-02: payload must be exactly one byte**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `pause_tree_rejects_a_payload_that_is_not_exactly_one_byte`
  - Kind: precondition
  - Statement: every payload whose length differs from exactly `size_of::<PauseTreeData>()` (1 byte) makes `pause_tree` return Err.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/pause_tree.rs:12-13` (`fn process_pause_tree`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

### Success Postconditions

- [x] **INV-PAUSE-TREE-03: the state byte follows the paused flag exactly**
  - Covered by: `program-tests/shielded-pool/tests/tree/contract.rs` `pause_blocks_tree_mutation_and_unpause_restores_it` (extended to read the state byte: exactly 2 when paused, exactly 1 after unpause)
  - Kind: postcondition
  - Statement: after a successful `pause_tree`, the tree's state byte is exactly `PAUSED` (2) when `data.paused != 0` and exactly `INITIALIZED` (1) when `data.paused == 0`.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/pause_tree.rs:21-27` (`fn process_pause_tree`), `program-libs/tree/src/lib.rs:322-324` (`fn set_paused`)
  - Severity: High
  - Suggested test: positive both directions; harness: mollusk unit

- [x] **INV-PAUSE-TREE-04: a paused tree can always be unpaused**
  - Covered by: `program-tests/shielded-pool/tests/tree/contract.rs` `pause_blocks_tree_mutation_and_unpause_restores_it`
  - Kind: reachability
  - Statement: for every paused tree, a `pause_tree` instruction with `paused = 0` signed by the protocol authority succeeds (the loader used here accepts paused trees, unlike every other write path).
  - Location: `programs/shielded-pool/src/instructions/protocol_config/pause_tree.rs:21-26` (`from_account_view_mut_allow_paused`), `program-libs/tree/src/lib.rs:206-212`
  - Severity: Critical (permanent freeze prevention)
  - Suggested test: positive (pause then unpause then transact); harness: program-tests integration (`cargo test-sbf`)

### Frame Conditions

- [x] **INV-PAUSE-TREE-05: only the state byte changes**
  - Covered by: `program-tests/shielded-pool/tests/admin/functional.rs` `pause_tree_changes_only_the_tree_state_byte`
  - Kind: frame
  - Statement: after a successful `pause_tree`, every byte of the tree account other than the state byte is unchanged, and every other account is unchanged.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/pause_tree.rs:21-27` (`fn process_pause_tree`)
  - Severity: High
  - Suggested test: positive; harness: mollusk unit (full data compare)

## Nullifier Markers (Transact, RingTransact, RingAuthorityTransact, MergeTransact, RingMergeTransact)

Every transact-family instruction takes one writable marker PDA
(`["nullifier", tree, nullifier]`) per input right after its fixed account prefix
and creates it while queueing the nullifier. The marker replaces the bloom filter as
the pending non-inclusion check. Hermetic tests reach marker creation without a
prover because nullifiers are queued and markers created before proof verification;
the proof-backed binary `nullifier_markers_proof` covers the success path.

### Success Postconditions

- [x] **INV-TRANSACT-46: one marker per input, stamped with its queue index and canonical bump**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/markers_proof.rs` `transact_creates_one_marker_per_input` (exact `queue_index = q_before + i`, bump, owner, 9 bytes, rent), `program-tests/shielded-pool/tests/transact/functional.rs` `transact_sends_valid_proof`; localnet: `tests/localnet/photon/forester.rs` `nullifier_test_forester_batches_queued_nullifiers_with_photon_indexer` (`queue_nullifiers_once` asserts both markers after every queue transaction)
  - Kind: postcondition
  - Statement: after a successful transact-family instruction with `n` inputs, for every input `i` the account at `PDA(["nullifier", input_tree, nullifier_i])` is owned by the program, is exactly `NULLIFIER_MARKER_SIZE` (9) bytes, decodes to `NullifierMarker { queue_index, bump }` with `queue_index` equal to the queue sequence the insert reserved (`input.input_queue_seq`, the pre-transaction `queue_batches.next_index + i`) and `bump` the canonical bump, and holds at least `Rent::minimum_balance(9)` lamports (exactly that amount unless it was prefunded above it).
  - Location: `programs/shielded-pool/src/instructions/nullifier_marker/create.rs:24-99` (`fn create_nullifier_markers`, `fn create_nullifier_marker`), `transact/processor.rs:87-91`, `merge/processor.rs:123-127`
  - Severity: Critical (marker is the only pending double-spend guard)
  - Suggested test: positive; harness: program-tests integration (proofs tier)

- [x] **INV-TRANSACT-49: the tree funds only the missing marker rent and never drops below its own rent floor**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/markers.rs` `transact_rejects_a_tree_short_of_marker_rent` (bare rent and `rent + 2 * marker_rent - 1` both rejected, no marker survives), `program-tests/shielded-pool/tests/nullifier/markers_proof.rs` `transact_tops_up_prefunded_markers` (underfunded marker topped up to exactly its rent, overfunded marker keeps its surplus, tree debited only the missing rent), `transact_creates_one_marker_per_input` (`assert_tree_lamports_after_spend`: tree delta is exactly `forester_fee - n * marker_rent`)
  - Kind: postcondition + precondition
  - Statement: for every created marker the tree's lamports decrease by exactly `max(0, Rent::minimum_balance(9) - marker_lamports_before)`; if that debit would leave the tree below `Rent::minimum_balance(tree.data_len())` the instruction returns Err and no marker is created. A marker prefunded above its rent keeps the surplus and costs the tree nothing.
  - Location: `programs/shielded-pool/src/instructions/nullifier_marker/create.rs:84-99`
  - Error: `ShieldedPoolError::InsufficientNullifierMarkerRent = 7049`
  - Severity: High (tree-fund drainage, liveness once working capital is exhausted)
  - Suggested test: positive + negative boundary; harness: program-tests integration

### Preconditions

- [x] **INV-TRANSACT-47: a nullifier with a live marker cannot be queued again**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/markers.rs` `transact_rejects_a_pending_nullifier` (marker from an earlier queueing, fixture-written), `transact_rejects_the_same_nullifier_twice_in_one_instruction`; `program-tests/shielded-pool/tests/nullifier/markers_proof.rs` `transact_rejects_a_nullifier_queued_by_an_earlier_transaction` (real first spend, replay rejected, first marker unchanged); `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_a_duplicate_nullifier_within_one_instruction`
  - Kind: precondition (state: pending non-inclusion)
  - Statement: marker creation requires the marker account to be System-owned with zero data; an account at the canonical marker address that is program-owned or non-empty (a marker created by an earlier transaction, or by an earlier input of the same instruction) makes the instruction return Err. Together with the Merkle non-inclusion proof this gives INV-XC-10 (at most one successful queue insertion per nullifier); the pending half now surfaces as 7048 instead of 7002.
  - Location: `programs/shielded-pool/src/instructions/nullifier_marker/loader.rs:10-28` (`fn load_unused_nullifier_marker`)
  - Error: `ShieldedPoolError::NullifierAlreadyQueued = 7048`
  - Severity: Critical (double-spend)
  - Suggested test: negative (across transactions and within one instruction); harness: program-tests integration

- [x] **INV-TRANSACT-48: every marker slot must hold the canonical, writable marker PDA**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/markers.rs` `transact_rejects_swapped_nullifier_markers` (7051), `transact_rejects_a_foreign_account_in_a_marker_slot` (7051), `transact_rejects_a_read_only_nullifier_marker` (account-checks `AccountNotMutable` = 20002), `transact_rejects_missing_nullifier_marker_accounts` (account-checks `NotEnoughAccountKeys` = 20014)
  - Kind: precondition
  - Statement: the `n` accounts following the fixed prefix (after `system_program`, or after `ring_config` on the ring rails) are consumed as writable markers in input order; a missing account, a read-only meta, or an address that is not `find_program_address(["nullifier", input_tree, nullifier_i])` makes the instruction return Err. Marker accounts are trusted only through this derivation, never through their position.
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs` (`nullifier_markers` via `next_mut("nullifier_marker")`), `nullifier_marker/loader.rs:15-23` (`verify_pda`)
  - Error: `ShieldedPoolError::InvalidNullifierMarker = 7051` / account-checks 20002 / 20014
  - Severity: High
  - Suggested test: negative; harness: program-tests integration

### Rollback

- [x] **INV-TRANSACT-50: a rejected instruction leaves no marker behind**
  - Covered by: every rejection test in `program-tests/shielded-pool/tests/nullifier/markers.rs` (`expect_transact_rejection`: `assert_rolled_back_except(payer)` plus a full tree-account compare, and `assert_nullifier_markers_absent` where markers would have been created), `markers_proof.rs` `transact_rejects_a_nullifier_queued_by_an_earlier_transaction`
  - Kind: rollback
  - Statement: when a transact-family instruction returns Err for any reason (marker gate, rent, or a later proof failure), no marker account exists afterwards that did not exist before, existing markers are unchanged, and the tree's lamports and data are unchanged; only the fee payer's balance moves.
  - Location: runtime rollback; marker creation order in `transact/processor.rs:83-91`, `merge/processor.rs:105-127`
  - Severity: Critical
  - Suggested test: negative; harness: program-tests integration

## CloseNullifierMarkers

### Authorization

- [x] **INV-CLOSE-MARKER-01: closing markers below the reclaim watermark is permissionless**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/markers.rs` `close_returns_marker_rent_to_the_tree`, `close_honours_the_watermark_boundary` (the transaction fee payer is the unrelated test payer; the instruction takes no signer)
  - Kind: reachability
  - Statement: `close_nullifier_markers` takes no signer and no fee-payer account; for every tree and every set of markers with `queue_index < close_before_index`, any transaction submitter can close them.
  - Location: `programs/shielded-pool/src/instructions/close_nullifier_markers.rs:13-33` (`fn process_close_nullifier_markers`)
  - Severity: Medium (liveness of working-capital recovery)
  - Suggested test: positive; harness: program-tests integration

### Account Constraints

- [x] **INV-CLOSE-MARKER-02: the tree is the fixed rent recipient**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/markers.rs` `close_returns_marker_rent_to_the_tree` (tree gains exactly `n * Rent::minimum_balance(9)`), `close_honours_the_watermark_boundary`
  - Kind: postcondition
  - Statement: after a successful close of `n` markers the tree account's lamports increase by exactly the sum of the closed markers' lamports and no other account gains lamports; there is no caller-chosen recipient (deviation from the dedicated `rent_recipient` convention, accepted because the instruction is permissionless).
  - Location: `programs/shielded-pool/src/instructions/nullifier_marker/close.rs:18-24` (`fn close_nullifier_marker`)
  - Severity: High (tree working-capital drainage otherwise)
  - Suggested test: positive; harness: program-tests integration

- [x] **INV-CLOSE-MARKER-03: the first account must be the writable, unpaused pool tree**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/markers.rs` `close_rejects_a_paused_tree` (7013), `close_rejects_a_non_tree_account` (7001), `close_rejects_a_read_only_tree_meta` (account-checks `AccountNotMutable` = 20002)
  - Kind: precondition
  - Statement: the tree loads through `TreeAccount::from_account_view_mut` (owner, discriminator, and state checks); a paused tree, a non-tree account, or a read-only tree meta makes the instruction return Err. Marker cleanup is frozen together with every other tree write.
  - Location: `programs/shielded-pool/src/instructions/close_nullifier_markers.rs:20-25`
  - Error: `ShieldedPoolError::TreePaused = 7013` / `InvalidTreeAccounts = 7001` / account-checks 20002
  - Severity: High
  - Suggested test: negative; harness: program-tests integration

- [x] **INV-CLOSE-MARKER-04: each marker must be the program-owned 9-byte record whose stored bump recreates its address**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/markers.rs` `close_rejects_a_mismatched_nullifier_marker_pair`, `close_rejects_a_marker_with_a_wrong_bump`, `close_rejects_a_non_marker_account` (System-owned account; program-owned account of another size), `close_rejects_the_same_marker_twice_in_one_instruction` (already closed within the instruction: System-owned, empty), `close_rejects_a_read_only_marker_meta` (account-checks `AccountNotMutable` = 20002)
  - Kind: precondition
  - Statement: for every `(nullifier_i, marker_i)` pair the account must be writable, owned by the program, exactly `NULLIFIER_MARKER_SIZE` bytes, decode as `NullifierMarker`, and satisfy `create_program_address(["nullifier", tree, nullifier_i, bump], program) == marker_i.address`; any violation makes the instruction return Err.
  - Location: `programs/shielded-pool/src/instructions/nullifier_marker/loader.rs:31-58` (`fn load_nullifier_marker`)
  - Error: `ShieldedPoolError::InvalidNullifierMarker = 7051` / account-checks 20002
  - Severity: Critical (closing a foreign marker would re-enable a pending double spend)
  - Suggested test: negative; harness: program-tests integration

### Instruction Data Validation

- [x] **INV-CLOSE-MARKER-05: the nullifier list is non-empty and matches the marker accounts one to one**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/markers.rs` `close_rejects_an_empty_nullifier_list`, `close_rejects_a_trailing_account`
  - Kind: precondition
  - Statement: the borsh `CloseNullifierMarkersData` must decode, `nullifiers` must be non-empty, and after consuming one marker per nullifier no account may remain; otherwise the instruction returns Err.
  - Location: `programs/shielded-pool/src/instructions/close_nullifier_markers.rs:14-18, 29-31`
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative; harness: program-tests integration

### Reclaimable Batch Gate

- [x] **INV-CLOSE-MARKER-06: a marker is closable iff `queue_index < close_before_index`**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/markers.rs` `close_rejects_marker_before_batch_is_reclaimable` (fresh tree, `w = 0`), `close_honours_the_watermark_boundary` (`queue_index == w` rejected, `queue_index == w - 1` closed; `w` set by a LiteSVM fixture that writes `close_before_index` into the tree bytes because making a batch reclaimable needs `B + B/2 = 1800` queued nullifiers with the smallest supported batch); localnet: `tests/localnet/photon/forester.rs` `phase_assert_marker_cleanup` (drained but not yet reclaimable batch, `w == 0`, `close_markers` rejected with 7050 and no lamports move)
  - Kind: precondition
  - Statement: for every marker in the instruction, `marker.queue_index < tree.close_before_index` must hold; otherwise the instruction returns Err. `close_before_index` only advances in `batch_update_nullifier_tree` when a batch becomes reclaimable (`w = max(w, previous.start_index - 1 + batch_size)`), so a closable marker's nullifier is contained in every accepted nullifier-tree root (spec property "safe marker lifetime").
  - Location: `programs/shielded-pool/src/instructions/nullifier_marker/close.rs:15-17`, `program-libs/interface/src/state/nullifier_marker.rs:15-17` (`fn is_closable`), `program-libs/batched-merkle-tree/src/merkle_tree.rs` (`fn mark_previous_batch_reclaimable`)
  - Error: `ShieldedPoolError::NullifierMarkerNotClosable = 7050`
  - Severity: Critical (early close re-enables a stale non-inclusion proof)
  - Suggested test: negative boundary + positive; harness: program-tests integration; end-to-end reclaimability remains uncovered on localnet (see the note in `phase_assert_marker_cleanup`)

### Rollback

- [x] **INV-CLOSE-MARKER-07: the close is atomic across all markers**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/markers.rs` `close_is_atomic_across_markers` (two closable markers plus one at the watermark: all three survive, tree unchanged), every `expect_close_rejection` site (`assert_rolled_back_except(payer)` plus a full tree-account compare)
  - Kind: rollback
  - Statement: when any pair fails a check, the instruction returns Err, no marker is closed, and the tree's lamports and data are unchanged.
  - Location: `programs/shielded-pool/src/instructions/close_nullifier_markers.rs:26-29`
  - Severity: High
  - Suggested test: negative; harness: program-tests integration

### Frame Conditions

- [x] **INV-CLOSE-MARKER-08: only the tree's lamports and the closed markers change**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/markers.rs` `close_returns_marker_rent_to_the_tree`, `close_honours_the_watermark_boundary` (`assert_close_markers`: changed set is exactly the markers, the tree and the fee payer; the tree's data is byte-identical, so `close_before_index` and the queue are untouched; each marker ends with zero lamports and zero data)
  - Kind: frame
  - Statement: after a successful close, the tree's data is unchanged, its lamports increase by exactly the closed markers' lamports, every closed marker has zero lamports and zero data (the account disappears and can later be recreated by a fresh queue insertion of the same nullifier), and no other account changes except the transaction fee payer.
  - Location: `programs/shielded-pool/src/instructions/nullifier_marker/close.rs:18-24`
  - Severity: Medium
  - Suggested test: positive; harness: program-tests integration
