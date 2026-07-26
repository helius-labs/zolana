# Event Invariants

Covers `EmitEvent` (tag 14). The event-emission postconditions of the
state-changing instructions live in their own files and in INV-XC-23.

## EmitEvent

### Behavior

- [x] **INV-EMIT-EVENT-01: direct invocation modifies no account**
  - Covered by: `program-tests/shielded-pool/tests/dispatch/functional.rs` `direct_emit_event_leaves_attached_writable_accounts_untouched`
  - Kind: frame
  - Statement: an `EmitEvent` instruction invoked by any caller returns Ok and leaves every account's data and lamports unchanged (the dispatch returns immediately without reading accounts).
  - Location: `programs/shielded-pool/src/lib.rs:51` (`fn process_instruction`, `InstructionTag::EmitEvent` arm)
  - Severity: High (a state change here would be an arbitrary-write primitive)
  - Suggested test: positive (invoke with arbitrary writable accounts and assert no change); harness: mollusk unit

- [x] **INV-EMIT-EVENT-02: every payload is accepted**
  - Covered by: `program-tests/shielded-pool/tests/dispatch/functional.rs` `direct_emit_event_accepts_every_payload_shape`
  - Kind: postcondition
  - Statement: `EmitEvent` returns Ok for every payload byte string after the tag byte, including an empty payload (the payload is never parsed on-chain; it exists to be read from the inner-instruction log).
  - Location: `programs/shielded-pool/src/lib.rs:51` (`fn process_instruction`)
  - Severity: Medium
  - Suggested test: positive + fuzz; harness: mollusk unit

- [x] **INV-EMIT-EVENT-03: no account is required**
  - Covered by: `program-tests/shielded-pool/tests/dispatch/functional.rs` `direct_emit_event_is_a_noop_and_is_not_indexed`
  - Kind: precondition
  - Statement: `EmitEvent` succeeds with an empty account list (the program's own self-CPI passes zero accounts).
  - Location: `programs/shielded-pool/src/lib.rs:51`, `programs/shielded-pool/src/instructions/event.rs:11-19` (`fn emit_encoded_event`)
  - Severity: Medium
  - Suggested test: positive; harness: mollusk unit

### Reachability

- [x] **INV-EMIT-EVENT-04: state-changing instructions can always record their event**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/functional.rs` `spl_deposit_moves_tokens_emits_the_exact_output_and_updates_the_indexer`
  - Kind: reachability
  - Statement: for every state-changing instruction that reaches its event-emission step, the self-CPI `EmitEvent` succeeds (it passes no accounts, so no borrow or writability conflict with the tree account can block it).
  - Location: `programs/shielded-pool/src/instructions/event.rs:11-35` (`fn emit_encoded_event`, `fn emit_general_event`, `fn emit_batch_address_append_event`)
  - Severity: Medium (indexer liveness)
  - Suggested test: positive (covered implicitly by every successful-flow test asserting the event); harness: litesvm
