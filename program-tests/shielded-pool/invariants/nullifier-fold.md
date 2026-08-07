# NullifierFold Invariants

Covers `BatchUpdateNullifierTreeFolded` (tag 19). The instruction settles a run
of consecutive zkp batches against one folded proof. It reuses the forester
authorization and the reimbursement path of `BatchUpdateNullifierTree`, so
`INV-BATCH-NULL-08` (reimbursement arithmetic and rent floor) and
`INV-BATCH-NULL-09` (the emit is the last fallible step) apply unchanged. The
entries here cover what only a folded run can get wrong.

The in-circuit guards, one rejection test per guard, are listed with their tests
in [`docs/RECURSION.md`](../../../docs/RECURSION.md#forester-nullifier-fold).
`INV-NULL-FOLD-15` is their single entry here.

## BatchUpdateNullifierTreeFolded

### Authorization

- [ ] **INV-NULL-FOLD-01: authority must sign**
  - Not covered: no test drives tag 19 through the program; the run is
    exercised at the tree-library level only.
  - Kind: precondition
  - Statement: `batch_update_nullifier_tree_folded` can only succeed when the first account (`authority`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/batch_update_nullifier_tree.rs:100` (`fn process_batch_update_nullifier_tree_folded`)
  - Error: account-checks signer error
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [ ] **INV-NULL-FOLD-02: only the forester authority may fold**
  - Not covered: same gap as INV-NULL-FOLD-01.
  - Kind: precondition
  - Statement: `batch_update_nullifier_tree_folded` returns Err for every signer whose address differs from `protocol_config.forester_authority`; there is no permissionless flag for this instruction.
  - Location: `programs/shielded-pool/src/instructions/batch_update_nullifier_tree.rs:105-108` (`fn process_batch_update_nullifier_tree_folded`)
  - Error: `ShieldedPoolError::UnauthorizedCaller = 7003`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Instruction Data Validation

- [ ] **INV-NULL-FOLD-03: malformed borsh payload is rejected**
  - Not covered: same gap as INV-NULL-FOLD-01.
  - Kind: precondition
  - Statement: every payload that `<(u32, BatchUpdateNullifierTreeFoldedData)>::try_from_slice` fails to parse makes the instruction return Err.
  - Location: `programs/shielded-pool/src/instructions/batch_update_nullifier_tree.rs:97-98` (`fn process_batch_update_nullifier_tree_folded`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative + fuzz; harness: mollusk unit

- [ ] **INV-NULL-FOLD-04: a run below two is rejected**
  - Partial coverage: `prover/server/circuits/nullifier_fold/fold_test.go` `TestNewCircuitRejectsAnUnamortizedRun` (the circuit constructor half; the program-side gate is untested)
  - Kind: precondition
  - Statement: `update_tree_from_address_queue_folded` returns Err for every `run` strictly less than 2, because a run of one amortizes nothing and no key exists for it.
  - Location: `program-libs/batched-merkle-tree/src/merkle_tree_update.rs:89-91` (`fn update_tree_from_address_queue_folded`)
  - Error: `ShieldedPoolError::NullifierTreeUpdateFailed = 7002`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

### Preconditions

- [ ] **INV-NULL-FOLD-05: the run must be available at the head of the pending batch**
  - Partial coverage: `program-libs/batched-merkle-tree/tests/nullifier_tree.rs` `nullifier_tree_folded_run_matches_sequential_appends` (drives a run whose zkp batches are all full and uninserted; the rejection of a run longer than the available batches is untested)
  - Kind: precondition
  - Statement: the fold succeeds only when the pending batch holds at least `run` zkp batches that are full and not yet inserted, so a run never claims batches the queue has not closed.
  - Location: `program-libs/batched-merkle-tree/src/merkle_tree_update.rs:104-110` (`fn update_tree_from_address_queue_folded`)
  - Error: `ShieldedPoolError::NullifierTreeUpdateFailed = 7002`
  - Severity: Critical (forged tree roots)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-NULL-FOLD-06: the run must start at the account tree root**
  - Partial coverage: `program-libs/batched-merkle-tree/tests/nullifier_tree.rs` `nullifier_tree_folded_run_matches_sequential_appends` (asserts the positive direction, that the submitted `old_root` equals the account root; a mismatching `old_root` is untested)
  - Kind: precondition
  - Statement: the fold returns Err whenever `instruction_data.old_root` differs from the tree account's current root, and the comparison precedes proof verification, so a run against another tree state costs no pairing.
  - Location: `program-libs/batched-merkle-tree/src/merkle_tree_update.rs:112-117` (`fn update_tree_from_address_queue_folded`)
  - Error: `ShieldedPoolError::NullifierTreeUpdateFailed = 7002`
  - Severity: Critical (forged tree roots)
  - Suggested test: negative; harness: mollusk unit

- [ ] **INV-NULL-FOLD-07: the element chain comes from account state**
  - Not covered: no test submits a fold whose claimed elements differ from the queued ones.
  - Kind: precondition
  - Statement: every leg's element hash chain is read from the pending batch's stored hash chains, so no caller-supplied value enters the public input for the elements the run claims to have appended.
  - Location: `program-libs/batched-merkle-tree/src/merkle_tree_update.rs:119-142` (`fn update_tree_from_address_queue_folded`)
  - Severity: Critical (forged appends)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

### Success Postconditions

- [x] **INV-NULL-FOLD-08: the tree advances by exactly the whole span**
  - Covered by: `program-libs/batched-merkle-tree/tests/nullifier_tree.rs` `nullifier_tree_folded_run_matches_sequential_appends`
  - Kind: postcondition
  - Statement: after a successful fold, the tree's `next_index` is exactly the value before plus `run` × `zkp_batch_size`.
  - Location: `program-libs/batched-merkle-tree/src/merkle_tree_update.rs:150-166` (`fn update_tree_from_address_queue_folded`)
  - Severity: Critical (tree state)
  - Suggested test: positive; harness: host unit

- [x] **INV-NULL-FOLD-09: a run appends exactly one root**
  - Covered by: `program-libs/batched-merkle-tree/tests/nullifier_tree.rs` `nullifier_tree_folded_run_matches_sequential_appends`
  - Kind: postcondition
  - Statement: after a successful fold, `root_history` holds exactly one new entry and that entry equals the run's final root; no intermediate root of the run is present. The intermediate roots never existed on chain, so no client could have bound a proof to one.
  - Location: `program-libs/batched-merkle-tree/src/merkle_tree_update.rs:161-167` (`fn update_tree_from_address_queue_folded`)
  - Severity: Critical (root history semantics)
  - Suggested test: positive; harness: host unit

- [x] **INV-NULL-FOLD-10: every zkp batch in the run is marked inserted**
  - Covered by: `program-libs/batched-merkle-tree/tests/nullifier_tree.rs` `nullifier_tree_folded_run_matches_sequential_appends`
  - Kind: postcondition
  - Statement: after a successful fold, the pending batch's inserted-zkp count increases by exactly `run`, so the same batches cannot be settled a second time.
  - Location: `program-libs/batched-merkle-tree/src/merkle_tree_update.rs:169-184` (`fn update_tree_from_address_queue_folded`)
  - Severity: Critical (double settlement)
  - Suggested test: positive; harness: host unit

- [x] **INV-NULL-FOLD-11: the event reports the whole run**
  - Covered by: `program-libs/batched-merkle-tree/tests/nullifier_tree.rs` `nullifier_tree_folded_run_matches_sequential_appends`
  - Kind: postcondition
  - Statement: the emitted `BatchAddressAppendEvent` carries `num_update` exactly equal to `run` and `new_root` exactly equal to the run's final root. A consumer reads those fields instead of counting root-history entries.
  - Location: `program-libs/batched-merkle-tree/src/merkle_tree_update.rs:186-196` (`fn update_tree_from_address_queue_folded`)
  - Severity: Critical (indexer sync)
  - Suggested test: positive; harness: host unit

### Frame Conditions

- [ ] **INV-NULL-FOLD-12: only the tree and the reimbursement recipient change**
  - Not covered: no program-level test drives tag 19.
  - Kind: frame
  - Statement: after a successful fold, every account other than the tree account and the `reimbursement_recipient` has unchanged data and unchanged lamports.
  - Location: `programs/shielded-pool/src/instructions/batch_update_nullifier_tree.rs:93-126` (`fn process_batch_update_nullifier_tree_folded`)
  - Severity: Medium
  - Suggested test: positive; harness: mollusk unit

### Rollback

- [ ] **INV-NULL-FOLD-13: a rejected fold leaves the tree unchanged**
  - Not covered: the host test exercises the success path only.
  - Kind: rollback
  - Statement: when the fold returns Err, the tree's root, `next_index`, sequence number, and queue state are exactly the values before the instruction.
  - Location: `programs/shielded-pool/src/instructions/batch_update_nullifier_tree.rs:111-119` (`fn process_batch_update_nullifier_tree_folded`)
  - Error: `ShieldedPoolError::NullifierTreeUpdateFailed = 7002`
  - Severity: Critical (forged tree roots)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

### Indexer Sync

- [x] **INV-NULL-FOLD-14: the folded payload is decoded as its own shape**
  - Covered by: `services/photon/src/ingester/parser/nullifier_tree_batch_update_parser.rs` `parses_folded_batch_update_instruction`, `folded_payload_is_not_read_as_an_unfolded_one`
  - Kind: postcondition (indexer)
  - Statement: Photon reads a tag-19 payload as `(run, inputs)` and a tag-4 payload as the plain shape, and neither payload is read at the other's offsets.
  - Location: `services/photon/src/ingester/parser/nullifier_tree_batch_update_parser.rs` (`fn parse_nullifier_tree_batch_update`)
  - Severity: High (indexer sync)
  - Suggested test: positive + negative; harness: photon parser unit tests

### Circuit

- [x] **INV-NULL-FOLD-15: the fold circuit rejects a run its legs do not form**
  - Covered by: the per-guard rejection tests in `prover/server/circuits/nullifier_fold/fold_test.go`, listed against their guards in [`docs/RECURSION.md`](../../../docs/RECURSION.md#forester-nullifier-fold)
  - Kind: state transition
  - Statement: the fold proves a run only when every adjacent pair shares a root and advances the start index by exactly one batch, and only under the pinned inner key.
  - Location: `prover/server/circuits/nullifier_fold/fold.go` (`fn Define`)
  - Error: proof verification fails
  - Severity: Critical (forged tree roots)
  - Suggested test: negative; harness: Go circuit tests
