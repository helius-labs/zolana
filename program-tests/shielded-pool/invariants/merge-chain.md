# MergeChain Invariants

Covers `MergeChainTransact` (tag 20). A chain collapses more UTXOs than the
fixed 8-in/1-out merge shape by feeding an intermediate merge output straight
into the next level inside one recursive proof.

The instruction reuses `MergeTransactAccounts::validate_and_parse` and
`load_user_record`, so `INV-MERGE-01`, `INV-MERGE-02`, `INV-MERGE-03`,
`INV-MERGE-04`, `INV-MERGE-05`, and `INV-MERGE-18` apply unchanged. Shared
invariants (expiry, pause, stale root, double-spend, rollback, external-hash
domain separation) live in `cross-cutting.md`. The entries here cover what only
a chain can get wrong.

The in-circuit guards, one rejection test per guard, are listed with their tests
in [`docs/RECURSION.md`](../../../docs/RECURSION.md#merge-chain).
`INV-MERGE-CHAIN-09` is their single entry here.

## MergeChainTransact

### Instruction Data Validation

- [x] **INV-MERGE-CHAIN-01: the level shape must close**
  - Covered by: `program-libs/interface/src/instruction/instruction_data/merge_chain_transact.rs` `rejects_a_tree_that_does_not_close`
  - Kind: precondition
  - Statement: parsing succeeds only for a `levels` vector in which every level but the top consumes exactly the level below at an arity of at most eight and the top level holds exactly one leg.
  - Location: `program-libs/interface/src/instruction/instruction_data/merge_chain_transact.rs` (`fn validate_shape`)
  - Error: `ShieldedPoolError::InvalidMergeShape = 7019`
  - Severity: High
  - Suggested test: negative; harness: host unit

- [x] **INV-MERGE-CHAIN-02: every vector matches the level shape**
  - Covered by: `program-libs/interface/src/instruction/instruction_data/merge_chain_transact.rs` `rejects_vectors_that_disagree_with_the_shape`
  - Kind: precondition
  - Statement: parsing succeeds only when `private_tx_hashes` holds exactly one entry per leg and `nullifiers`, `utxo_tree_root_index`, and `nullifier_tree_root_index` each hold exactly one entry per tree-backed slot. The shape is attacker-controlled and selects the verifying key, so it is resolved before any length is trusted.
  - Location: `program-libs/interface/src/instruction/instruction_data/merge_chain_transact.rs` (`fn validate_shape`)
  - Error: `ShieldedPoolError::InvalidMergeShape = 7019`
  - Severity: Critical (proof and state disagreement)
  - Suggested test: negative; harness: host unit

- [ ] **INV-MERGE-CHAIN-03: the level shape must name a generated verifying key**
  - Not covered: no test submits a chain whose shape parses but has no committed key.
  - Kind: precondition
  - Statement: `merge_chain_transact` returns Err whenever `merge_chain_verifying_key(levels)` resolves to no committed key, and the resolution precedes the pairing.
  - Location: `programs/shielded-pool/src/instructions/merge_chain/verify.rs:39-40` (`fn verify`)
  - Error: `ShieldedPoolError::UnsupportedMergeChainShape = 7051`
  - Severity: Critical (unproved statement)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

### Success Postconditions

- [x] **INV-MERGE-CHAIN-04: every tree-backed slot publishes its nullifier**
  - Covered by: `program-tests/shielded-pool/tests/merge_chain/functional.rs` `merge_chain_collapses_fifteen_utxos_in_one_transaction`
  - Kind: postcondition
  - Statement: after a successful chain, the nullifier queue's next index increases by exactly the number of tree-backed slots the level shape implies, and each inserted value is the proof-bound nullifier of that slot.
  - Location: `programs/shielded-pool/src/instructions/merge_chain/processor.rs:117-149` (`fn apply_input_tree`)
  - Severity: Critical (double-spend)
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-MERGE-CHAIN-05: only the top leg's output is appended**
  - Covered by: `program-tests/shielded-pool/tests/merge_chain/functional.rs` `merge_chain_collapses_fifteen_utxos_in_one_transaction`
  - Kind: postcondition
  - Statement: after a successful chain, the UTXO tree's next index increases by exactly one and the appended leaf is `output_utxo_hash`; no intermediate leg output reaches the tree.
  - Location: `programs/shielded-pool/src/instructions/merge_chain/processor.rs:78-95` (`fn process_merge_chain_transact_ix`)
  - Severity: Critical (unbacked value)
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-MERGE-CHAIN-06: the chain collects the forester fee for every queued nullifier**
  - Partial coverage: `program-tests/shielded-pool/tests/merge_chain/functional.rs` `merge_chain_collapses_fifteen_utxos_in_one_transaction` (the transaction succeeds, so the fee transfer runs; the exact lamport delta is not asserted)
  - Kind: postcondition
  - Statement: after a successful chain, the payer's lamports decrease by exactly the forester fee for the number of nullifiers the chain queued, which the tree account gains.
  - Location: `programs/shielded-pool/src/instructions/merge_chain/processor.rs:108-113` (`fn process_merge_chain_transact_ix`)
  - Error: `ShieldedPoolError::InvalidForesterFee = 7026`
  - Severity: Medium
  - Suggested test: positive; harness: mollusk unit

### Proof Binding

- [ ] **INV-MERGE-CHAIN-07: the external data hash binds tag 20**
  - Not covered: no test replays a plain merge proof as a chain or the reverse.
  - Kind: precondition
  - Statement: the recomputed `external_data_hash` folds the discriminator 20, so a proof produced for a chain does not verify under `merge_transact` and a plain merge proof does not verify here.
  - Location: `programs/shielded-pool/src/instructions/merge_chain/processor.rs:49-55` (`fn process_merge_chain_transact_ix`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (proof replay)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

- [ ] **INV-MERGE-CHAIN-08: the proof verifies against the state the program resolved**
  - Partial coverage: `program-tests/shielded-pool/tests/merge_chain/functional.rs` `merge_chain_collapses_fifteen_utxos_in_one_transaction` (a valid chain settles; no tampered public-input leg is submitted)
  - Kind: state transition
  - Statement: the outer proof verifies against the chain over the per-slot nullifiers, `output_utxo_hash`, the per-slot roots the tree resolved, the chained private tx hashes, `external_data_hash`, `allow_dummy_inputs`, and the registry-derived owner `pk_field`, so a chain cannot settle a statement the proof does not cover.
  - Location: `programs/shielded-pool/src/instructions/merge_chain/verify.rs:104-116` (`fn public_input_hash`)
  - Error: `ShieldedPoolError::TransactProofVerificationFailed = 7008`
  - Severity: Critical (unbacked value)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

### Circuit

- [x] **INV-MERGE-CHAIN-09: the chain circuit rejects a tree its legs do not form**
  - Covered by: the per-guard rejection tests in `prover/server/circuits/spp_merge_chain/chain_test.go`, listed against their guards in [`docs/RECURSION.md`](../../../docs/RECURSION.md#merge-chain)
  - Kind: state transition
  - Statement: the chain proves a level tree only when every chained slot spends the output the level below produced, every leg agrees on the shared identity, no UTXO is spent by two legs, and every leg verifies under the pinned inner key.
  - Location: `prover/server/circuits/spp_merge_chain/chain.go` (`fn Define`)
  - Error: proof verification fails
  - Severity: Critical (unbacked value)
  - Suggested test: negative; harness: Go circuit tests

### Rollback

- [ ] **INV-MERGE-CHAIN-10: a rejected chain applies no part of the collapse**
  - Not covered: no test submits a chain that fails after the tree writes.
  - Kind: rollback
  - Statement: the tree writes precede the proof verification, so when `merge_chain_transact` returns Err, the UTXO tree, the nullifier queue, and every account's lamports are exactly the values before the instruction.
  - Location: `programs/shielded-pool/src/instructions/merge_chain/processor.rs:57-107` (`fn process_merge_chain_transact_ix`)
  - Severity: Critical (unbacked value)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

### Frame Conditions

- [ ] **INV-MERGE-CHAIN-11: the chain modifies only the two trees and the payer**
  - Not covered: no test asserts the frame of a successful chain.
  - Kind: frame
  - Statement: after a successful chain, every account other than `input_tree`, `output_tree`, and `payer` has unchanged data and unchanged lamports; `user_record` in particular is read-only.
  - Location: `programs/shielded-pool/src/instructions/merge_chain/processor.rs:34-115` (`fn process_merge_chain_transact_ix`)
  - Severity: Medium
  - Suggested test: positive; harness: mollusk unit
