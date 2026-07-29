# Tree Invariants

Covers `CreateTree` (tag 5), `BatchUpdateNullifierTree` (tag 51), `PauseTree` (tag 8).
Shared invariants (pause semantics across write paths, rollback) live in
`cross-cutting.md`.

SPEC_DIVERGENCE (resolved 2026-07-23): the spec previously stated UTXO tree height 26
and omitted `batch_update_nullifier_tree` from the instruction table; `docs/spec.md`
now states H=32 and lists tag 51.

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

- [x] **INV-BATCH-NULL-07: Photon records a batch update only from an authenticated emitted event**
  - Covered by: the batch-update parser tests on the security/photon-batch-event-sourcing branch (services/photon nullifier_tree_batch_update_parser.rs test module, landing before this branch: drops_forged_batch_update_cpi_without_event, drops_successful_batch_update_without_event, drops_event_with_foreign_parent, drops_event_under_non_batch_update_parent, parses_batch_update_from_emitted_event, records_event_root_not_instruction_root)
  - Kind: postcondition (indexer)
  - Statement: Photon ingests a nullifier-tree batch update only from a `BatchAddressAppendEvent` carried by an `EMIT_EVENT` inner instruction whose stack-height parent is a shielded-pool `BATCH_UPDATE_NULLIFIER_TREE` instruction (the program emits the event only when an update actually applied). A forged tag-51 CPI that fails the on-chain forester-authority check, a successful no-op update, and a forged `EMIT_EVENT` with a foreign parent all record nothing; the tree and new root are taken from the event, never from instruction data (F-04).
  - Location: `services/photon/src/ingester/parser/nullifier_tree_batch_update_parser.rs` (`fn parse_nullifier_tree_batch_update`)
  - Severity: Critical (permissionless indexer halt)
  - Suggested test: negative + positive; harness: photon parser unit tests

### Forester Reimbursement

- [x] **INV-BATCH-NULL-08: forester reimbursement preserves the tree's rent floor**
  - Covered by: `programs/shielded-pool/src/instructions/shared.rs` units `reimbursement_moves_funded_lamports_and_preserves_rent`, `reimbursement_cannot_spend_tree_rent` (7027 leg)
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
