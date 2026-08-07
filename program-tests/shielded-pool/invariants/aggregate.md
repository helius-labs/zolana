# AggregateTransact invariants

`aggregate_transact` settles a batch of `transact` legs against one recursive
proof. Every leg runs the `transact` pipeline except its own pairing, so the
`transact.md` invariants apply per leg. The entries here cover what only a
batch can get wrong: binding the batch to the key that proved it, splitting the
account list, and keeping leg data constrained.

- [x] **INV-AGGREGATE-01: selector must name a generated verifying key**
  - Covered by: `program-tests/shielded-pool/tests/aggregate/guard.rs` `aggregate_rejects_a_batch_size_with_no_key`
  - Kind: precondition
  - Statement: `aggregate_transact` can only succeed when `AggregateCircuitId` is supported and resolves to a committed outer verifying key.
  - Location: `programs/shielded-pool/src/instructions/aggregate_transact/processor.rs` (`fn validate_batch`)
  - Error: `InvalidAggregateBatch` (7048)
  - Severity: Critical

- [x] **INV-AGGREGATE-02: leg count must equal the selector's batch**
  - Covered by: `program-tests/shielded-pool/tests/aggregate/guard.rs` `aggregate_rejects_a_leg_count_that_disagrees_with_the_selector`
  - Kind: precondition
  - Statement: the number of legs equals `AggregateCircuitId::batch`, so the chain the program builds has the length the outer key proved.
  - Location: `programs/shielded-pool/src/instructions/aggregate_transact/processor.rs` (`fn validate_batch`)
  - Error: `InvalidAggregateBatch` (7048)
  - Severity: Critical

- [x] **INV-AGGREGATE-03: every leg is on the selector's rail**
  - Covered by: `program-tests/shielded-pool/tests/aggregate/guard.rs` `aggregate_rejects_a_leg_from_another_rail`
  - Kind: precondition
  - Statement: each leg's `CircuitId` names the same rail as the selector, so a batch cannot settle a leg the outer key never proved.
  - Location: `programs/shielded-pool/src/instructions/aggregate_transact/processor.rs` (`fn validate_batch`)
  - Error: `MismatchedCircuitType` (7039)
  - Severity: Critical

- [x] **INV-AGGREGATE-04: every leg has the selector's shape**
  - Covered by: `program-tests/shielded-pool/tests/aggregate/guard.rs` `aggregate_rejects_a_leg_of_another_shape`
  - Kind: precondition
  - Statement: each leg's input, output, and public asset slot counts equal the selector's, and match the leg's own vectors.
  - Location: `programs/shielded-pool/src/instructions/aggregate_transact/processor.rs` (`fn validate_batch`)
  - Error: `MismatchedCircuitType` (7039) or `InvalidTransactShape` (7006)
  - Severity: Critical

- [x] **INV-AGGREGATE-05: a leg carries no proof**
  - Covered by: `program-tests/shielded-pool/tests/aggregate/guard.rs` `aggregate_rejects_a_leg_that_carries_a_proof`
  - Kind: precondition
  - Statement: each leg's `proof` is zero. The batch verifies one outer proof, so leg proof bytes are outside the statement and would be unconstrained instruction data.
  - Location: `programs/shielded-pool/src/instructions/aggregate_transact/processor.rs` (`fn validate_batch`)
  - Error: `AggregateLegCarriesProof` (7049)
  - Severity: High

- [x] **INV-AGGREGATE-06: a leg carries no BSB22 commitment**
  - Covered by: `program-tests/shielded-pool/tests/aggregate/guard.rs` `aggregate_rejects_a_leg_that_carries_a_commitment`
  - Kind: precondition
  - Statement: a P256 leg's `bsb22_commitment` is zero. The inner commitment is a witness of the outer proof and never reaches the chain.
  - Location: `programs/shielded-pool/src/instructions/aggregate_transact/processor.rs` (`fn validate_batch`)
  - Error: `AggregateLegCarriesProof` (7049)
  - Severity: High

- [x] **INV-AGGREGATE-07: declared account counts total the account list**
  - Covered by: `program-tests/shielded-pool/tests/aggregate/guard.rs` `aggregate_rejects_an_account_list_that_does_not_split`
  - Kind: precondition
  - Statement: each leg declares at least the five fixed accounts and the counts sum to the account list length, checked before any leg settles so a list that does not split leaves no leg applied.
  - Location: `programs/shielded-pool/src/instructions/aggregate_transact/processor.rs` (`fn process_aggregate_transact_ix`)
  - Error: `InvalidAggregateBatch` (7048)
  - Severity: Critical

- [x] **INV-AGGREGATE-08: batch order binds the statement**
  - Covered by: `prover/server/circuits/spp_aggregate/aggregate_test.go` `TestAggregateRejectsAReorderedBatch`
  - Kind: state transition
  - Statement: the public input is a Poseidon left fold over the leg hashes, so a batch settled in a different order than it was proved does not verify.
  - Location: `prover/server/circuits/spp_aggregate/aggregate.go` (`fn Define`)
  - Error: proof verification fails
  - Severity: High

- [~] **INV-AGGREGATE-09: the outer proof verifies against the settled legs**
  - Cross-branch coverage: `program-tests/shielded-pool/tests/aggregate/guard.rs` `aggregate_rejects_a_tampered_outer_proof`, `aggregate_rejects_a_proof_for_another_batch_size` land with the aggregate rejection-test branch. `prover/server/circuits/spp_aggregate/aggregate_test.go` `TestAggregateRejectsAWrongAggregateHash` covers the circuit half today. The earlier citation, `program-tests/shielded-pool/tests/aggregate/cu.rs` `aggregate_reports_compute`, asserts a state root and prints the rest, so it does not cover a rejection.
  - Kind: state transition
  - Statement: the program chains the public input hash it recomputes for each settled leg and verifies the outer proof against that chain, so a batch cannot settle legs the proof does not cover.
  - Location: `programs/shielded-pool/src/instructions/aggregate_transact/processor.rs` (`fn process_aggregate_transact_ix`)
  - Error: `AggregateProofVerificationFailed` (7050)
  - Severity: Critical

- [x] **INV-AGGREGATE-10: a leg keeps its solo instruction discriminator**
  - Covered by: `program-libs/interface/tests/aggregate_circuit.rs` `a_leg_keeps_its_solo_instruction_tag`
  - Kind: precondition
  - Statement: a leg's `external_data_hash` binds the discriminator it would carry alone, so one proof is valid both on its own and inside a batch.
  - Location: `programs/shielded-pool/src/instructions/aggregate_transact/processor.rs` (`fn settle_leg`)
  - Error: proof verification fails
  - Severity: High

### Rollback

- [ ] **INV-AGGREGATE-11: a batch that fails at one leg leaves no leg applied**
  - Not covered: no test settles part of a batch and then fails. The rejection
    tests fail before the first leg settles, so they do not exercise a partial
    run.
  - Kind: rollback
  - Statement: legs settle in order and the outer proof verifies after the last one, so when `aggregate_transact` returns Err at any leg or at the pairing, every tree, every settlement account, and every account's lamports are exactly the values before the instruction, and no leg's `GeneralEvent` is recorded.
  - Location: `programs/shielded-pool/src/instructions/aggregate_transact/processor.rs` (`fn process_aggregate_transact_ix`)
  - Error: `AggregateProofVerificationFailed` (7050), or the failing leg's own error
  - Severity: Critical (partial settlement)
  - Suggested test: negative; harness: program-tests integration (`cargo test-sbf`)

### Frame Conditions

- [ ] **INV-AGGREGATE-12: a batch modifies only the accounts its leg runs name**
  - Not covered: no test asserts the frame of a settled batch.
  - Kind: frame
  - Statement: after a successful batch, every account outside the concatenated leg runs has unchanged data and unchanged lamports, and the optional trailing registry account is unchanged in every run.
  - Location: `programs/shielded-pool/src/instructions/aggregate_transact/processor.rs` (`fn process_aggregate_transact_ix`)
  - Severity: Medium
  - Suggested test: positive; harness: mollusk unit
