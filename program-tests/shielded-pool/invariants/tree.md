# Tree Invariants

Covers `CreateTree` (tag 2), `BatchUpdateNullifierTree` (tag 4), `PauseTree` (tag 3),
`CloseNullifierPdas` (tag 18), `SetTreeFees` (tag 19), and the nullifier-PDA
accounts the transact family creates while queueing nullifiers. Shared invariants
(pause semantics across write paths, rollback) live in `cross-cutting.md`.

Convention deviations confirmed for the PDA design (`program-libs/tree/nullifier_tree_spec.md`):
`close_nullifier_pdas` is gated to `protocol_config.forester_authority`, takes no
fee payer, and returns PDA rent to the tree (a caller-chosen `rent_recipient`
would drain the tree's PDA working capital); its `reimbursement_recipient` receives only the close reimbursement
paid out of the tree's `fee_balance`, never PDA rent; the PDA payload is a
discriminator-less 10-byte Borsh `NullifierPda { queue_index, tree_id }`; a
duplicate pending nullifier surfaces as
`ShieldedPoolError::NullifierAlreadyQueued = 7048`.

Fee model (`program-libs/tree/src/fees.rs`): the tree header stores
`fees: TreeFeeSchedule { fee_per_nullifier, append_reimbursement, close_reimbursement }`
(bytes 8..32) and `fee_balance: u64` (bytes 32..40). Every queued nullifier
charges `fee_per_nullifier` from the payer into the tree and credits
`fee_balance`; `batch_update_nullifier_tree` and `close_nullifier_pdas` pay
`min(owed, fee_balance)` to their `reimbursement_recipient` and debit
`fee_balance`. The lamport invariant `tree.lamports >= rent_minimum + fee_balance`
keeps PDA working capital and the fee pool apart (INV-TRANSACT-49).

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

- [x] **INV-CREATE-TREE-03: tree account must be the canonical tree PDA and, once allocated, program-owned**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `tree_creation_rejects_a_non_canonical_tree_address` (address derived from another tree id -> 7016), `tree_creation_rejects_a_skipped_tree_id` (a fresh allocation must use exactly `protocol_config.next_tree_id` -> 7052; no account is created)
  - Kind: precondition
  - Statement: `create_tree` returns Err unless the tree address equals `find_program_address([TREE_PDA_SEED, tree_id.to_le_bytes()], program)`; a fresh allocation (System-owned, zero-length account) is created by the program as that PDA and must carry `tree_id == protocol_config.next_tree_id`, and every continuation step on an already allocated account returns Err unless the account is writable and owned by the shielded-pool program.
  - Location: `programs/shielded-pool/src/instructions/create_tree/processor.rs` (`fn process_create_tree`: `verify_pda`, `is_unallocated`, `next_tree_id` check), `create_tree/allocate.rs` (`fn TreeAllocation::create`, `fn grow_tree`)
  - Error: `ShieldedPoolError::InvalidPda = 7016` / `InvalidTreeId = 7052` / `InvalidTreeAccounts = 7001`
  - Severity: High
  - Suggested test: negative; harness: program-tests integration

- [x] **INV-CREATE-TREE-04: the tree is initialized only when it reaches the canonical layout size**
  - Covered by: `program-tests/shielded-pool/tests/admin/functional.rs` `tree_creation_completes_in_three_steps_and_advances_next_tree_id` (three `TREE_ALLOCATION_STEP` chunks stay all-zero, the fourth step reaches exactly `tree_account_size()` and initializes); `program-tests/shielded-pool/tests/admin/rejection.rs` `partially_allocated_tree_is_not_usable` (a tree after three steps is rejected by `deposit_sol` with 7001), `tree_creation_rejects_double_initialization`
  - Kind: precondition + postcondition
  - Statement: each `create_tree` step grows the account by at most `TREE_ALLOCATION_STEP` bytes and never beyond `tree_account_size()`; while `data_len < tree_account_size()` the step returns Ok without writing the header, so the account stays `UNINITIALIZED` and every other instruction rejects it; `TreeAccount::init` runs exactly in the step that reaches the full size, and a continuation step on an account whose state byte is not `UNINITIALIZED` returns Err.
  - Location: `programs/shielded-pool/src/instructions/create_tree/processor.rs` (`fn process_create_tree`), `create_tree/allocate.rs` (`fn grow_tree`)
  - Error: `ShieldedPoolError::InvalidTreeAccounts = 7001`
  - Severity: High
  - Suggested test: negative + positive; harness: program-tests integration

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
  - Statement: `create_tree` derives root-history capacity from `input_queue_batch_size / input_queue_zkp_batch_size` and returns Err when that ratio differs from the canonical ZKP batch count.
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

### Fee Schedule

- [x] **INV-CREATE-TREE-10: the initial fee schedule is stored as submitted and the fee balance starts at zero**
  - Covered by: `program-libs/tree/tests/fees.rs` `init_writes_a_valid_schedule_with_an_empty_balance`, `init_stores_an_insolvent_schedule` (a schedule whose payouts exceed collections initializes and reads back verbatim); `program-tests/shielded-pool/tests/admin/functional.rs` `tree_creation_completes_in_three_steps_and_advances_next_tree_id` (tree bytes 8..32 equal the submitted `fees`, `tree_fees()` reads `(fees, 0)`)
  - Kind: postcondition
  - Statement: the final `create_tree` step stores `data.fees` in the tree header without checking it against `Z = nullifier_params.input_queue_zkp_batch_size`; after success `fee_balance` is exactly 0 and the schedule bytes equal the submitted `TreeFeeSchedule`. The default `default_tree_fees(Z)` (append 5_000, close 170, `fee_per_nullifier = ceil((5_000 + Z * 170) / Z)`: 190 for `Z = 250`, 670 for `Z = 10`) satisfies `fee_per_nullifier * Z >= append_reimbursement + Z * close_reimbursement` with equality; an insolvent schedule only truncates payouts to the fee balance (INV-BATCH-NULL-08, INV-CLOSE-PDA-10).
  - Location: `programs/shielded-pool/src/instructions/create_tree/processor.rs:92-103` (`fn process_create_tree`, `data.fees`), `program-libs/tree/src/lib.rs` (`fn TreeAccount::init`), `program-libs/tree/src/fees.rs` (`fn TreeFeeSchedule::at_cost`)
  - Severity: Medium (payouts are capped by `fee_balance`, so an insolvent schedule cannot overdraw the tree)
  - Suggested test: positive; harness: tree unit + mollusk unit

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
  - Partial coverage: `program-tests/shielded-pool/tests/nullifier/batch.rs` `batch_update_rejects_a_proof_for_an_unready_zkp_batch` (failing-path frame asserted; no positive batch-update path is feasible off localnet for the success-path frame); the reimbursement half is unit-tested in `program-tests/shielded-pool/tests/tree/contract.rs` (`reimbursement_moves_funded_lamports_and_preserves_rent`) and `program-libs/tree/tests/fees.rs` (`take_append_reimbursement_pays_up_to_the_balance`)
  - Kind: frame
  - Statement: after a successful `batch_update_nullifier_tree`, every account other than the tree account and the `reimbursement_recipient` has unchanged data and unchanged lamports; the tree's data changes (tree state plus the `fee_balance` debit) and its lamports decrease by exactly `min(fees.append_reimbursement * num_update, fee_balance_before)`, which the recipient gains (INV-BATCH-NULL-08); the recipient's data is unchanged.
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

- [x] **INV-BATCH-NULL-08: forester reimbursement is paid from the fee balance to a non-program recipient and preserves the tree's rent floor**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/batch.rs` `batch_update_rejects_a_program_owned_reimbursement_recipient` (tree as recipient -> exact 7055, tree bytes unchanged); `program-tests/shielded-pool/tests/tree/contract.rs` `reimbursement_recipient_must_not_be_program_owned` (7055), `reimbursement_moves_funded_lamports_and_preserves_rent`, `reimbursement_cannot_spend_tree_rent` (7027 leg), `reimbursement_recipient_balance_overflow_is_invalid_forester_fee` (7026 leg); `program-libs/tree/tests/fees.rs` `take_append_reimbursement_pays_up_to_the_balance` (owed above the balance pays exactly the balance and leaves 0; owed below pays in full), `take_reimbursement_saturates_to_the_balance` (an owed amount that overflows the multiplication is capped at the balance), `zero_schedule_charges_and_pays_nothing`
  - Kind: precondition + postcondition
  - Statement: the `reimbursement_recipient` must not be owned by the shielded-pool program (this rejects the tree itself, nullifier PDAs, and the protocol config), checked before any state change; when an update applies `num_update` batches, the tree pays exactly `paid = min(fees.append_reimbursement * num_update, fee_balance_before)` to the recipient and `fee_balance` decreases by exactly `paid`, so a short fee balance (for example right after `set_tree_fees` raised the reimbursement) pays what it holds and never fails the update; `paid == 0` skips the lamport move; the move fails with 7027 if it would leave the tree below its rent-exempt minimum (defense in depth: the lamport invariant makes this unreachable), with 7026 on an owed-amount or recipient-balance overflow; an update that applies zero batches (no event produced) pays nothing.
  - Location: `programs/shielded-pool/src/instructions/batch_update_nullifier_tree.rs` (`check_reimbursement_recipient`, `take_append_reimbursement`, `pay_reimbursement`), `shared.rs` (`fn check_reimbursement_recipient`, `fn pay_reimbursement`, `fn pay_reimbursement_with_rent_minimum`), `program-libs/tree/src/fees.rs` (`fn TreeAccount::take_append_reimbursement`, `fn take_reimbursement`)
  - Error: `ShieldedPoolError::InvalidReimbursementRecipient = 7055` / `InsufficientForesterFeeBalance = 7027` / `InvalidForesterFee = 7026`
  - Severity: High (tree-fund drainage)
  - Suggested test: positive + negative (recipient, rent floor, short balance); harness: mollusk unit + tree unit

- [ ] **INV-BATCH-NULL-09: the event emit is the last fallible operation**
  - Partial coverage: photon parser tests (the consumer half: Photon records updates only from events in successful transactions); the ordering itself is a documented code invariant, untestable directly
  - Kind: state
  - Statement: every fallible step (including `pay_reimbursement`) precedes the `emit_batch_nullifier_append_event` self-CPI; Photon's parser records updates only from events in successful transactions, so an emit-then-fail shape would drop a genuine update or wedge the indexer on a forged one (F-04 companion).
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

## Nullifier PDAs (Transact, RingTransact, RingAuthorityTransact, MergeTransact, RingMergeTransact)

Every transact-family instruction takes one writable PDA
(`["nullifier", tree, nullifier]`) per input right after its fixed account prefix
and creates it while queueing the nullifier. The PDA replaces the bloom filter as
the pending non-inclusion check. Hermetic tests reach PDA creation without a
prover because nullifiers are queued and PDAs created before proof verification;
the proof-backed binary `nullifier_pdas_proof` covers the success path.

### Success Postconditions

- [x] **INV-TRANSACT-46: one PDA per input, stamped with its queue index and canonical bump**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/nullifier_pdas_proof.rs` `transact_creates_one_nullifier_pda_per_input` (exact `queue_index = q_before + i`, bump, owner, 9 bytes, rent), `program-tests/shielded-pool/tests/transact/functional.rs` `transact_sends_valid_proof`; localnet: `tests/localnet/photon/forester.rs` `nullifier_test_forester_batches_queued_nullifiers_with_photon_indexer` (`queue_nullifiers_once` asserts both PDAs after every queue transaction)
  - Kind: postcondition
  - Statement: after a successful transact-family instruction with `n` inputs, for every input `i` the account at `PDA(["nullifier", input_tree, nullifier_i])` is owned by the program, is exactly `NULLIFIER_PDA_SIZE` (10) bytes, decodes to `NullifierPda { queue_index, tree_id }` with `queue_index` equal to the queue sequence the insert reserved (`input.input_queue_seq`, the pre-transaction `queue_next_index + i`) and `tree_id` the tree's id, and holds at least `Rent::minimum_balance(10)` lamports (exactly that amount unless it was prefunded above it).
  - Location: `programs/shielded-pool/src/instructions/nullifier_pda/create.rs:24-99` (`fn create_nullifier_pdas`, `fn create_nullifier_pda`), `transact/processor.rs:87-91`, `merge/processor.rs:123-127`
  - Severity: Critical (PDA is the only pending double-spend guard)
  - Suggested test: positive; harness: program-tests integration (proofs tier)

- [x] **INV-TRANSACT-49: the tree funds only the missing PDA rent and never drops below its rent floor plus the fee balance**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/nullifier_pdas.rs` `transact_rejects_a_tree_short_of_nullifier_pda_rent` (bare rent and `rent + 2 * nullifier_pda_rent - 1` both rejected, no PDA survives), `transact_rejects_when_working_capital_would_borrow_from_the_fee_pool` (`fee_balance = 1_000_000` written into the header and funded; tree at `rent + fee_balance + 2 * nullifier_pda_rent - 1` rejects a 2-input spend with exact 7049 and leaves no PDA), `program-tests/shielded-pool/tests/nullifier/nullifier_pdas_proof.rs` `transact_tops_up_prefunded_nullifier_pdas` (underfunded PDA topped up to exactly its rent, overfunded PDA keeps its surplus, tree debited only the missing rent), `transact_creates_one_nullifier_pda_per_input` (`assert_tree_lamports_after_spend`: tree delta is exactly `forester_fee - n * nullifier_pda_rent`)
  - Kind: postcondition + precondition
  - Statement: for every created PDA the tree's lamports decrease by exactly `max(0, Rent::minimum_balance(10) - nullifier_pda_lamports_before)`; if that debit would leave the tree below `Rent::minimum_balance(tree.data_len()) + fee_balance` (the fee balance as credited by this instruction's own insertion fee, INV-TRANSACT-42) the instruction returns Err and no PDA is created, so working capital never borrows from collected fees. A PDA prefunded above its rent keeps the surplus and costs the tree nothing.
  - Location: `programs/shielded-pool/src/instructions/nullifier_pda/create.rs` (`struct NullifierPdaRent`, `fn create_nullifier_pdas`; `tree_minimum = rent + reserved_lamports`), `transact/processor.rs` (`create_nullifier_pdas(.., input_tree_result.fee_balance)`), `merge/processor.rs`
  - Error: `ShieldedPoolError::InsufficientNullifierPdaRent = 7049`
  - Severity: High (tree-fund drainage, liveness once working capital is exhausted)
  - Suggested test: positive + negative boundary; harness: program-tests integration

### Preconditions

- [x] **INV-TRANSACT-47: a nullifier with a live PDA cannot be queued again**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/nullifier_pdas.rs` `transact_rejects_a_pending_nullifier` (PDA from an earlier queueing, fixture-written), `transact_rejects_the_same_nullifier_twice_in_one_instruction`; `program-tests/shielded-pool/tests/nullifier/nullifier_pdas_proof.rs` `transact_rejects_a_nullifier_queued_by_an_earlier_transaction` (real first spend, replay rejected, first PDA unchanged); `program-tests/shielded-pool/tests/transact/guard.rs` `transact_rejects_a_duplicate_nullifier_within_one_instruction`
  - Kind: precondition (state: pending non-inclusion)
  - Statement: PDA creation requires the PDA account to be System-owned with zero data; an account at the canonical PDA address that is program-owned or non-empty (a PDA created by an earlier transaction, or by an earlier input of the same instruction) makes the instruction return Err. Together with the Merkle non-inclusion proof this gives INV-XC-10 (at most one successful queue insertion per nullifier); the pending half now surfaces as 7048 instead of 7002.
  - Location: `programs/shielded-pool/src/instructions/nullifier_pda/loader.rs:10-28` (`fn load_unused_nullifier_pda`)
  - Error: `ShieldedPoolError::NullifierAlreadyQueued = 7048`
  - Severity: Critical (double-spend)
  - Suggested test: negative (across transactions and within one instruction); harness: program-tests integration

- [x] **INV-TRANSACT-48: every PDA slot must hold the canonical, writable PDA**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/nullifier_pdas.rs` `transact_rejects_swapped_nullifier_pdas` (7051), `transact_rejects_a_foreign_account_in_a_nullifier_pda_slot` (7051), `transact_rejects_a_read_only_nullifier_pda` (account-checks `AccountNotMutable` = 20002), `transact_rejects_missing_nullifier_pda_accounts` (account-checks `NotEnoughAccountKeys` = 20014)
  - Kind: precondition
  - Statement: the `n` accounts following the fixed prefix (after `system_program`, or after `ring_config` on the ring rails) are consumed as writable PDAs in input order; a missing account, a read-only meta, or an address that is not `find_program_address(["nullifier", input_tree, nullifier_i])` makes the instruction return Err. PDA accounts are trusted only through this derivation, never through their position.
  - Location: `programs/shielded-pool/src/instructions/transact/account.rs` (`nullifier_pdas` via `next_mut("nullifier_pda")`), `nullifier_pda/loader.rs:15-23` (`verify_pda`)
  - Error: `ShieldedPoolError::InvalidNullifierPda = 7051` / account-checks 20002 / 20014
  - Severity: High
  - Suggested test: negative; harness: program-tests integration

### Rollback

- [x] **INV-TRANSACT-50: a rejected instruction leaves no PDA behind**
  - Covered by: every rejection test in `program-tests/shielded-pool/tests/nullifier/nullifier_pdas.rs` (`expect_transact_rejection`: `assert_rolled_back_except(payer)` plus a full tree-account compare, and `assert_nullifier_pdas_absent` where PDAs would have been created), `nullifier_pdas_proof.rs` `transact_rejects_a_nullifier_queued_by_an_earlier_transaction`
  - Kind: rollback
  - Statement: when a transact-family instruction returns Err for any reason (PDA gate, rent, or a later proof failure), no PDA account exists afterwards that did not exist before, existing PDAs are unchanged, and the tree's lamports and data are unchanged; only the fee payer's balance moves.
  - Location: runtime rollback; PDA creation order in `transact/processor.rs:83-91`, `merge/processor.rs:105-127`
  - Severity: Critical
  - Suggested test: negative; harness: program-tests integration

## CloseNullifierPdas

### Authorization

- [x] **INV-CLOSE-PDA-01: only the forester authority closes PDAs below the reclaim watermark**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/nullifier_pdas.rs` `close_rejects_a_non_forester_authority` (`UnauthorizedCaller`, tree and PDA untouched), `close_rejects_an_unsigned_authority` (`AccountError::InvalidSigner`), `close_returns_nullifier_pda_rent_to_the_tree` and `close_honours_the_watermark_boundary` (the forester authority co-signs; the unrelated test payer pays the fee and receives the reimbursement)
  - Kind: precondition
  - Statement: `close_nullifier_pdas` returns Err for every `authority` that does not sign or whose address differs from `protocol_config.forester_authority`, before any PDA or recipient check; there is no permissionless flag. The instruction takes no fee-payer account. Rationale: an open close let anyone race the forester's cleanup, collect the reimbursement, and leave the forester paying for the failed transaction.
  - Location: `programs/shielded-pool/src/instructions/close_nullifier_pdas.rs` (`fn process_close_nullifier_pdas`: `next_signer("authority")`, `check_forester_authority`)
  - Severity: Medium (forester fee griefing; liveness of working-capital recovery now depends on the forester)
  - Suggested test: negative; harness: program-tests integration

### Account Constraints

- [x] **INV-CLOSE-PDA-02: the tree is the fixed rent recipient**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/nullifier_pdas.rs` `close_returns_nullifier_pda_rent_to_the_tree` (tree gains exactly `n * Rent::minimum_balance(10)`), `close_honours_the_watermark_boundary`, `close_pays_a_recipient_other_than_the_payer` (`assert_close_nullifier_pdas`: the recipient gains only the reimbursement, the PDA rent lands in the tree)
  - Kind: postcondition
  - Statement: after a successful close of `n` PDAs the tree account's lamports increase by exactly the sum of the closed PDAs' lamports minus the close reimbursement it pays out (INV-CLOSE-PDA-10); no account other than the `reimbursement_recipient` gains lamports, and the recipient never receives PDA rent. There is no caller-chosen rent recipient (deviation from the dedicated `rent_recipient` convention, accepted because a rent recipient would drain the tree's working capital).
  - Location: `programs/shielded-pool/src/instructions/nullifier_pda/close.rs:18-24` (`fn close_nullifier_pda`)
  - Severity: High (tree working-capital drainage otherwise)
  - Suggested test: positive; harness: program-tests integration

- [x] **INV-CLOSE-PDA-03: the third account must be the writable, unpaused pool tree**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/nullifier_pdas.rs` `close_rejects_a_paused_tree` (7013), `close_rejects_a_non_tree_account` (7001), `close_rejects_a_read_only_tree_meta` (account-checks `AccountNotMutable` = 20002)
  - Kind: precondition
  - Statement: the tree loads through `TreeAccount::from_account_view_mut` (owner, discriminator, and state checks); a paused tree, a non-tree account, or a read-only tree meta makes the instruction return Err. PDA cleanup is frozen together with every other tree write.
  - Location: `programs/shielded-pool/src/instructions/close_nullifier_pdas.rs` (`TreeAccount::from_account_view_mut`)
  - Error: `ShieldedPoolError::TreePaused = 7013` / `InvalidTreeAccounts = 7001` / account-checks 20002
  - Severity: High
  - Suggested test: negative; harness: program-tests integration

- [x] **INV-CLOSE-PDA-04: each PDA must be a writable, program-owned `NULLIFIER_PDA_SIZE`-byte record of this tree**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/nullifier_pdas.rs` `close_rejects_a_nullifier_pda_of_another_tree` (record with a foreign `tree_id` -> 7053), `close_rejects_a_non_nullifier_pda_account` (System-owned account; program-owned account of another size), `close_rejects_a_zero_queue_index_record` (program-owned ten-byte all-zero record -> 7051), `close_rejects_the_same_nullifier_pda_twice_in_one_instruction` (already closed within the instruction: System-owned, empty), `close_rejects_a_read_only_nullifier_pda_meta` (account-checks `AccountNotMutable` = 20002)
  - Kind: precondition
  - Statement: every PDA account must be writable, owned by the program, exactly `NULLIFIER_PDA_SIZE` bytes, decode as `NullifierPda` with `queue_index >= 1` (queue indices start at 1, so an all-zero record was never program-written), and carry `tree_id` equal to the tree's id; any violation makes the instruction return Err. The address is not re-derived: a record can only exist at a nullifier PDA address because `create_nullifier_pdas` derives it with `verify_pda` (INV-TRANSACT-46), and the record's own `queue_index` decides closability (INV-CLOSE-PDA-06).
  - Location: `programs/shielded-pool/src/instructions/nullifier_pda/loader.rs` (`fn load_nullifier_pda`)
  - Error: `ShieldedPoolError::InvalidNullifierPda = 7051` / `NullifierPdaTreeMismatch = 7053` / account-checks 20002
  - Severity: Critical (closing a foreign PDA would re-enable a pending double spend)
  - Suggested test: negative; harness: program-tests integration

### Instruction Data Validation

- [x] **INV-CLOSE-PDA-05: the instruction carries no data and at least one PDA account**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/nullifier_pdas.rs` `close_rejects_an_empty_nullifier_list` (authority, protocol config, tree and recipient only -> 7000), `close_rejects_a_trailing_non_nullifier_account` (a non-PDA account after the PDAs is consumed as a PDA and fails INV-CLOSE-PDA-04)
  - Kind: precondition
  - Statement: the instruction payload must be empty (the former borsh `CloseNullifierPdasData` nullifier list is gone; every account after `authority`, `protocol_config`, `tree` and `reimbursement_recipient` is a PDA to close, and the forester derives the addresses off-chain), and at least one PDA account must follow the four fixed accounts; a non-empty payload or a missing PDA makes the instruction return Err.
  - Location: `programs/shielded-pool/src/instructions/close_nullifier_pdas.rs` (`fn process_close_nullifier_pdas`: `data.is_empty()` check, `iterator_is_empty()` check)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative; harness: program-tests integration

- [x] **INV-CLOSE-PDA-09: the reimbursement recipient must not be program-owned**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/nullifier_pdas.rs` `close_rejects_a_program_owned_reimbursement_recipient` (the tree, an open nullifier PDA, and the protocol config each rejected with exact 7055; every PDA survives, tree bytes unchanged)
  - Kind: precondition
  - Statement: the fourth account (`reimbursement_recipient`) must not be owned by the shielded-pool program; the check runs before the tree is loaded or any PDA is touched, so the tree cannot pay itself, a live nullifier PDA cannot be credited above its rent, and the protocol config cannot absorb fees.
  - Location: `programs/shielded-pool/src/instructions/close_nullifier_pdas.rs` (`check_reimbursement_recipient`), `shared.rs` (`fn check_reimbursement_recipient`)
  - Error: `ShieldedPoolError::InvalidReimbursementRecipient = 7055`
  - Severity: High (fee-pool misdirection)
  - Suggested test: negative (three program-owned recipients); harness: program-tests integration

### Close Reimbursement

- [x] **INV-CLOSE-PDA-10: closing `n` PDAs pays `min(close_reimbursement * n, fee_balance)` to the recipient and debits the fee balance**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/nullifier_pdas.rs` `close_pays_the_closer_from_the_fee_balance` (3 PDAs at the default 170: payer gains exactly 510, `fee_balance` drops by exactly 510), `close_pays_only_what_the_fee_balance_holds` (`fee_balance = 100` pays exactly 100 and ends at 0), `close_with_a_zero_schedule_pays_nothing_and_still_closes` (zero schedule set via `set_tree_fees`: 0 paid, balance unchanged, PDAs closed), `close_pays_a_recipient_other_than_the_payer` (a separate System account gains exactly `close_reimbursement * n`, `fee_balance` drops by the same amount, PDAs gone); `program-libs/tree/tests/fees.rs` `take_close_reimbursement_pays_up_to_the_balance`
  - Kind: postcondition
  - Statement: after a successful close of `n` PDAs, the `reimbursement_recipient` gains exactly `paid = min(fees.close_reimbursement * n, fee_balance_before)`, the tree's `fee_balance` is exactly `fee_balance_before - paid`, and the tree's lamports change by exactly `sum(closed PDA lamports) - paid`; `paid == 0` skips the lamport move and still closes every PDA. The payout never fails the close (a short fee balance pays what it holds), and the tree keeps at least `rent_minimum + fee_balance_after`.
  - Location: `programs/shielded-pool/src/instructions/close_nullifier_pdas.rs` (`take_close_reimbursement`, `pay_reimbursement`), `program-libs/tree/src/fees.rs` (`fn TreeAccount::take_close_reimbursement`, `fn take_reimbursement`), `shared.rs` (`fn pay_reimbursement`)
  - Error: `ShieldedPoolError::InsufficientForesterFeeBalance = 7027` (defense-in-depth rent guard) / `InvalidForesterFee = 7026` (overflow)
  - Severity: High (fund movement; cleanup liveness incentive)
  - Suggested test: positive (full, capped, zero, foreign recipient); harness: program-tests integration

### PDA Reclaimability Gate

- [x] **INV-CLOSE-PDA-06: a PDA is closable iff `queue_index < close_before_index`**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/nullifier_pdas.rs` `close_rejects_nullifier_pda_before_batch_is_reclaimable` (fresh tree, `w = 0`), `close_honours_the_watermark_boundary` (`queue_index == w` rejected, `queue_index == w - 1` closed; `w` set by a LiteSVM fixture that writes `close_before_index` into the tree bytes because making a batch reclaimable requires two full batches to be queued and applied); localnet: `tests/localnet/photon/forester.rs` `phase_assert_nullifier_pda_cleanup` (drained but not yet reclaimable batch, `w == 0`, `close_nullifier_pdas` rejected with 7050 and no lamports move)
  - Kind: precondition
  - Statement: for every PDA in the instruction, `PDA.queue_index < tree.close_before_index` must hold; otherwise the instruction returns Err. Queue indices equal leaf indices and start at 1. `close_before_index` advances when a batch's final ZKP update lands (`w = max(w, current.start_index)`), after its full root-history window has overwritten every older accepted root, so a closable PDA's nullifier is contained in every accepted nullifier-tree root (spec property "safe PDA lifetime"). Batch storage may already have been reused; reuse does not affect the watermark or PDA lifetime.
  - Location: `programs/shielded-pool/src/instructions/nullifier_pda/close.rs:15-17`, `program-libs/interface/src/state/nullifier_pda.rs:15-17` (`fn is_closable`), `program-libs/tree/src/nullifier_tree/merkle_tree_update.rs` (`fn advance_nullifier_pda_close_watermark`)
  - Error: `ShieldedPoolError::NullifierPdaNotClosable = 7050`
  - Severity: Critical (early close re-enables a stale non-inclusion proof)
  - Suggested test: negative boundary + positive; harness: program-tests integration; end-to-end reclaimability remains uncovered on localnet (see the note in `phase_assert_nullifier_pda_cleanup`)

### Rollback

- [x] **INV-CLOSE-PDA-07: the close is atomic across all PDAs**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/nullifier_pdas.rs` `close_is_atomic_across_nullifier_pdas` (two closable PDAs plus one at the watermark: all three survive, tree unchanged), every `expect_close_rejection` site (`assert_rolled_back_except(payer)` plus a full tree-account compare)
  - Kind: rollback
  - Statement: when any pair fails a check, the instruction returns Err, no PDA is closed, and the tree's lamports and data are unchanged.
  - Location: `programs/shielded-pool/src/instructions/close_nullifier_pdas.rs` (the `while !iter.iterator_is_empty()` close loop; any Err aborts the whole instruction)
  - Severity: High
  - Suggested test: negative; harness: program-tests integration

### Frame Conditions

- [x] **INV-CLOSE-PDA-08: only the tree, the recipient, and the closed PDAs change**
  - Covered by: `program-tests/shielded-pool/tests/nullifier/nullifier_pdas.rs` `close_returns_nullifier_pda_rent_to_the_tree`, `close_honours_the_watermark_boundary`, `close_pays_the_closer_from_the_fee_balance`, `close_pays_a_recipient_other_than_the_payer` (`assert_close_nullifier_pdas`: changed set is exactly the PDAs, the tree, the recipient and the fee payer; the tree's data differs only in the `fee_balance` bytes, so `close_before_index` and the queue are untouched; each PDA ends with zero lamports and zero data)
  - Kind: frame
  - Statement: after a successful close, the tree's data is unchanged except for the `fee_balance` debit (INV-CLOSE-PDA-10), its lamports change by exactly the closed PDAs' lamports minus the paid reimbursement, the `reimbursement_recipient` gains exactly the paid reimbursement and keeps its data, every closed PDA has zero lamports and zero data (the account disappears and can later be recreated by a fresh queue insertion of the same nullifier), and no other account changes except the transaction fee payer.
  - Location: `programs/shielded-pool/src/instructions/nullifier_pda/close.rs:18-24`, `close_nullifier_pdas.rs` (`pay_reimbursement`)
  - Severity: Medium
  - Suggested test: positive; harness: program-tests integration

## SetTreeFees

`set_tree_fees` (tag 19) is the fee authority's operational lever: it rewrites
the 24 schedule bytes of a tree header (`fees`, bytes 8..32) and nothing else.
Accounts: `authority` (signer), `protocol_config`, `tree` (writable); data: the
borsh `TreeFeeSchedule` (`SetTreeFeesData`, 24 bytes). It works on paused trees
so a schedule can be fixed while writes are frozen.

### Authorization

- [x] **INV-SET-FEES-01: authority must sign**
  - Covered by: `program-tests/shielded-pool/tests/admin/set_tree_fees.rs` `mollusk_set_tree_fees_rejects_every_account_privilege_downgrade` (unsigning account 0 -> account-checks `InvalidSigner`)
  - Kind: precondition
  - Statement: `set_tree_fees` can only succeed when the first account (`authority`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/set_tree_fees.rs` (`fn process_set_tree_fees`, `next_signer("authority")`)
  - Error: account-checks signer error
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-SET-FEES-02: only the fee authority may set a schedule**
  - Covered by: `program-tests/shielded-pool/tests/admin/set_tree_fees.rs` `set_tree_fees_is_gated_by_the_fee_authority_alone` (rotate `fee_authority` via `UpdateProtocolConfigData::FeeAuthority`; the protocol authority is then rejected with exact 7003 and rolled back, the new fee authority succeeds), `set_tree_fees_rejects_wrong_authority_exactly` (unrelated signer -> exact 7003)
  - Kind: precondition
  - Statement: `set_tree_fees` returns Err for every signer whose address differs from `protocol_config.fee_authority`; neither `protocol_authority` nor `forester_authority` is accepted (the fee authority is kept apart from the forester so foresters cannot set their own reimbursement), and there is no permissionless flag.
  - Location: `programs/shielded-pool/src/instructions/set_tree_fees.rs` (`load_and_validate_fee_authority`), `protocol_config/loader.rs` (`fn load_and_validate_fee_authority`), `program-libs/interface/src/state/protocol_config.rs` (`fn check_fee_authority`)
  - Error: `ShieldedPoolError::UnauthorizedCaller = 7003`
  - Severity: Critical (schedule control decides what insertions pay and what the fee pool pays out)
  - Suggested test: negative (protocol authority, random signer) + positive after rotation; harness: mollusk unit + litesvm

### Account Constraints

- [x] **INV-SET-FEES-03: the second account must be the protocol config**
  - Covered by: `program-tests/shielded-pool/tests/admin/set_tree_fees.rs` `set_tree_fees_rejects_a_non_config_account` (System-owned impostor -> exact 7012)
  - Kind: precondition
  - Statement: the `protocol_config` account must be program-owned, exactly `ProtocolConfig::SIZE` bytes, and stamped with the protocol-config discriminator; otherwise the instruction returns Err before the tree is touched.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/loader.rs` (`fn load_and_validate_fee_authority`), `shared.rs` (`fn load_config`)
  - Error: `ShieldedPoolError::InvalidProtocolConfig = 7012`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-SET-FEES-04: the third account must be a writable tree account; a paused tree is accepted**
  - Covered by: `program-tests/shielded-pool/tests/admin/set_tree_fees.rs` `set_tree_fees_rejects_a_non_tree_account` (System-owned impostor -> exact 7001), `mollusk_set_tree_fees_rejects_every_account_privilege_downgrade` (read-only tree meta -> account-checks `AccountNotMutable`), `set_tree_fees_works_on_a_paused_tree_and_keeps_the_fee_balance` (state byte `PAUSED` before and after, schedule written)
  - Kind: precondition + reachability
  - Statement: the tree loads through `TreeAccount::from_account_view_mut_allow_paused` (owner and discriminator checks, pause state ignored); a non-tree account or a read-only tree meta makes the instruction return Err, while a paused tree is written like an initialized one and stays paused.
  - Location: `programs/shielded-pool/src/instructions/set_tree_fees.rs` (`from_account_view_mut_allow_paused`), `program-libs/tree/src/lib.rs`
  - Error: `ShieldedPoolError::InvalidTreeAccounts = 7001` / account-checks 20002
  - Severity: High
  - Suggested test: negative + positive (paused); harness: mollusk unit + litesvm

### Instruction Data Validation

- [x] **INV-SET-FEES-05: payload must be exactly the 24-byte schedule**
  - Covered by: `program-tests/shielded-pool/tests/admin/set_tree_fees.rs` `set_tree_fees_rejects_a_payload_that_is_not_exactly_the_schedule` (23 bytes after the tag and 25 bytes after the tag both -> exact 7000)
  - Kind: precondition
  - Statement: every payload that borsh `TreeFeeSchedule::try_from_slice` does not decode exactly (shorter than 24 bytes, or trailing bytes) makes `set_tree_fees` return Err.
  - Location: `programs/shielded-pool/src/instructions/set_tree_fees.rs` (`SetTreeFeesData::try_from_slice`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative (short, long); harness: mollusk unit

- [x] **INV-SET-FEES-06: any schedule is stored regardless of the tree's ZKP batch size**
  - Covered by: `program-tests/shielded-pool/tests/admin/set_tree_fees.rs` `set_tree_fees_stores_insolvent_schedules` (the default schedule with `append_reimbursement + 1`, with `close_reimbursement + 1`, and with `fee_per_nullifier - 1`: each succeeds and `tree_fees()` reads `(fees, 0)`); `program-libs/tree/tests/fees.rs` `zero_schedule_charges_and_pays_nothing`
  - Kind: postcondition
  - Statement: `set_tree_fees` performs no solvency check against `Z = tree.nullifier_tree.zkp_batch_size`; a schedule whose payouts exceed `fee_per_nullifier * Z` is stored verbatim and only truncates future payouts to `min(owed, fee_balance)`. The all-zero schedule disables fees and payouts.
  - Location: `programs/shielded-pool/src/instructions/set_tree_fees.rs` (`set_fee_schedule`), `program-libs/tree/src/fees.rs` (`fn TreeAccount::take_reimbursement`)
  - Severity: Medium (payouts are capped by `fee_balance`, so an insolvent schedule cannot overdraw the tree)
  - Suggested test: positive boundary (each term off by one); harness: litesvm

### Success Postconditions

- [x] **INV-SET-FEES-07: the schedule bytes take the supplied value and the fee balance is untouched**
  - Covered by: `program-tests/shielded-pool/tests/admin/set_tree_fees.rs` `set_tree_fees_changes_only_the_schedule_bytes` (tree bytes 8..32 equal `bytes_of(fees)`, bytes 32..40 still zero), `set_tree_fees_works_on_a_paused_tree_and_keeps_the_fee_balance` (`fee_balance` written as 777 beforehand reads back as 777 next to the new schedule); `program-libs/tree/tests/fees.rs` `set_fee_schedule_keeps_the_balance`
  - Kind: postcondition
  - Statement: after a successful `set_tree_fees`, `tree.fees` equals exactly the submitted `TreeFeeSchedule` and `tree.fee_balance` equals its value before the call; collected-but-unpaid fees are never created, destroyed, or re-priced by a schedule change (only future insertions and payouts use the new rates).
  - Location: `programs/shielded-pool/src/instructions/set_tree_fees.rs` (`set_fee_schedule`), `program-libs/tree/src/fees.rs` (`fn TreeAccount::set_fee_schedule`)
  - Severity: High
  - Suggested test: positive (full header compare); harness: mollusk unit + litesvm

### Rollback

- [x] **INV-SET-FEES-08: a rejected call leaves every account unchanged**
  - Covered by: `program-tests/shielded-pool/tests/admin/set_tree_fees.rs` `set_tree_fees_is_gated_by_the_fee_authority_alone` (`assert_rolled_back_except(payer)` plus `tree_fees()` equal to the pre-call schedule and balance)
  - Kind: rollback
  - Statement: when `set_tree_fees` returns Err for any reason (authority, accounts, payload), the tree's schedule and fee balance and every other account are unchanged; only the transaction fee payer's balance moves.
  - Location: runtime rollback; `programs/shielded-pool/src/instructions/set_tree_fees.rs` (validation precedes the single write)
  - Severity: High
  - Suggested test: negative; harness: litesvm

### Frame Conditions

- [x] **INV-SET-FEES-09: only the 24 schedule bytes of the tree change**
  - Covered by: `program-tests/shielded-pool/tests/admin/set_tree_fees.rs` `set_tree_fees_changes_only_the_schedule_bytes` (authority and config accounts byte-identical; tree lamports and owner unchanged; tree data equals the pre-call bytes with 8..32 replaced by the new schedule)
  - Kind: frame
  - Statement: after a successful `set_tree_fees`, every account other than the tree is unchanged, the tree's lamports and owner are unchanged, and every tree byte outside 8..32 (state byte, `fee_balance`, both subtrees) is unchanged. No lamports move.
  - Location: `programs/shielded-pool/src/instructions/set_tree_fees.rs` (`fn process_set_tree_fees`)
  - Severity: Medium
  - Suggested test: positive (full data compare); harness: mollusk unit

## ClaimTreeLamports

`claim_tree_lamports` (tag 20) lets the fee authority recover lamports a tree
holds above its reserve, typically after a rent reduction. Accounts:
`authority` (signer), `protocol_config`, `tree` (writable), `recipient`
(writable, not program-owned); data: empty. The reserve is
`rent_minimum(tree) + fee_balance + (NUM_BATCHES + 1) * input_queue_batch_size * rent_minimum(NULLIFIER_PDA_SIZE)`
at the current rent, so a claim never starves nullifier PDA creation and never
touches forester money. It works on paused trees.

### Authorization

- [x] **INV-CLAIM-01: authority must sign**
  - Covered by: `program-tests/shielded-pool/tests/admin/claim_tree_lamports.rs` `mollusk_claim_tree_lamports_rejects_every_account_privilege_downgrade` (unsigning account 0 -> account-checks `InvalidSigner`)
  - Kind: precondition
  - Statement: `claim_tree_lamports` can only succeed when the first account (`authority`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/claim_tree_lamports.rs` (`next_signer("authority")`)
  - Error: account-checks signer error
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CLAIM-02: only the fee authority may claim**
  - Covered by: `program-tests/shielded-pool/tests/admin/claim_tree_lamports.rs` `claim_tree_lamports_is_gated_by_the_fee_authority_alone` (rotate `fee_authority`; the protocol authority is rejected with exact 7003 and rolled back, the new fee authority succeeds), `claim_tree_lamports_rejects_wrong_authority_exactly` (unrelated signer -> exact 7003)
  - Kind: precondition
  - Statement: `claim_tree_lamports` returns Err for every signer whose address differs from `protocol_config.fee_authority`; neither `protocol_authority` nor `forester_authority` is accepted and there is no permissionless flag.
  - Location: `programs/shielded-pool/src/instructions/claim_tree_lamports.rs` (`load_and_validate_fee_authority`)
  - Error: `ShieldedPoolError::UnauthorizedCaller = 7003`
  - Severity: Critical (moves lamports out of protocol custody)
  - Suggested test: negative (protocol authority, random signer) + positive after rotation; harness: mollusk unit + litesvm

### Account Constraints

- [x] **INV-CLAIM-03: the tree must be an initialized shielded-pool tree; paused is allowed**
  - Covered by: `program-tests/shielded-pool/tests/admin/claim_tree_lamports.rs` `claim_tree_lamports_rejects_a_non_tree_account` (System-owned impostor -> exact 7001), `mollusk_claim_tree_lamports_rejects_every_account_privilege_downgrade` (read-only tree meta -> account-checks `AccountNotMutable`), `claim_tree_lamports_keeps_the_fee_balance_and_works_on_a_paused_tree` (state byte `PAUSED` before and after)
  - Kind: precondition
  - Statement: the tree account must be writable, owned by the program, carry the tree discriminator and a valid layout; a tree still in its multi-step creation has no discriminator and is rejected; a paused tree is accepted.
  - Location: `programs/shielded-pool/src/instructions/claim_tree_lamports.rs` (`from_account_view_mut_allow_paused`)
  - Error: `ShieldedPoolError::InvalidTreeAccounts = 7001`
  - Severity: High
  - Suggested test: negative + positive on paused; harness: mollusk unit + litesvm

- [x] **INV-CLAIM-04: the recipient must not be program-owned**
  - Covered by: `program-tests/shielded-pool/tests/admin/claim_tree_lamports.rs` `claim_tree_lamports_rejects_a_program_owned_recipient` (protocol config as recipient -> exact 7055, rolled back), `mollusk_claim_tree_lamports_rejects_every_account_privilege_downgrade` (read-only recipient meta -> account-checks `AccountNotMutable`)
  - Kind: precondition
  - Statement: the recipient must be writable and not owned by the shielded-pool program (this rejects the tree itself, nullifier PDAs, unallocated tree PDAs, and the protocol config), checked before any state change.
  - Location: `programs/shielded-pool/src/instructions/claim_tree_lamports.rs` (`check_reimbursement_recipient`)
  - Error: `ShieldedPoolError::InvalidReimbursementRecipient = 7055`
  - Severity: High
  - Suggested test: negative; harness: litesvm + mollusk unit

### Instruction Data Validation

- [x] **INV-CLAIM-05: the payload must be empty**
  - Covered by: `program-tests/shielded-pool/tests/admin/claim_tree_lamports.rs` `claim_tree_lamports_rejects_a_non_empty_payload` (one trailing byte -> exact 7000)
  - Kind: precondition
  - Statement: any byte after the tag makes `claim_tree_lamports` return Err.
  - Location: `programs/shielded-pool/src/instructions/claim_tree_lamports.rs` (`data.is_empty()`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

### Success Postconditions

- [x] **INV-CLAIM-06: the tree ends exactly at its reserve and the surplus reaches the recipient**
  - Covered by: `program-tests/shielded-pool/tests/admin/claim_tree_lamports.rs` `claim_tree_lamports_pays_exactly_the_surplus` (airdropped surplus moves in full; tree lamports equal the reserve), `claim_tree_lamports_keeps_the_fee_balance_and_works_on_a_paused_tree` (forged `fee_balance` stays in the tree and in the header), `claim_tree_lamports_recovers_a_rent_reduction` (halving `Rent` releases exactly the old minus the new reserve), `claim_tree_lamports_rejects_a_tree_without_surplus` (a tree at its reserve fails with exact 7062 and is rolled back)
  - Kind: postcondition
  - Statement: after a successful claim `tree.lamports == rent_minimum(tree) + fee_balance + (NUM_BATCHES + 1) * input_queue_batch_size * rent_minimum(NULLIFIER_PDA_SIZE)` at the Rent sysvar of that slot, and the recipient gains exactly the difference; a tree at or below that reserve returns `NoClaimableTreeLamports` and moves nothing. `fee_balance` and the working capital are never claimable.
  - Location: `programs/shielded-pool/src/instructions/claim_tree_lamports.rs`, `program-libs/interface/src/state/tree.rs` (`fn tree_working_capital_lamports`), `shared.rs` (`pay_reimbursement_with_rent_minimum`)
  - Error: `ShieldedPoolError::NoClaimableTreeLamports = 7062`
  - Severity: Critical (an over-claim would make nullifier PDA creation fail with 7028 and halt spends)
  - Suggested test: positive with exact balances; harness: litesvm + mollusk unit

### Frame Conditions

- [x] **INV-CLAIM-07: only lamports move**
  - Covered by: `program-tests/shielded-pool/tests/admin/claim_tree_lamports.rs` `mollusk_claim_tree_lamports_moves_only_lamports` (authority and config accounts byte-identical; tree and recipient differ from their pre-call state only in lamports), `claim_tree_lamports_is_gated_by_the_fee_authority_alone` (`assert_rolled_back_except(payer)` on rejection)
  - Kind: frame condition
  - Statement: a successful claim changes no account data and no owner; only the tree's and the recipient's lamports change, by the same amount. On any Err every account other than the transaction fee payer is unchanged.
  - Location: `programs/shielded-pool/src/instructions/claim_tree_lamports.rs` (no writes besides the lamport move)
  - Severity: Medium
  - Suggested test: positive; harness: mollusk unit
