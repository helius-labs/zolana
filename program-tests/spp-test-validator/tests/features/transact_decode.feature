Feature: The transact emitted event decodes
  After a shielded transfer the client has sent a `transact` instruction on chain,
  which emits a `GeneralEvent` through an `emit_event` self-CPI. This scenario
  re-parses that event from the transaction's inner instructions and prints it so a
  reader can inspect what was emitted.

  Background:
    Given a fresh shielded pool
    Given sender with shielded solana keypair

  Scenario: A SOL transfer's emitted event decodes
    Given sender deposits 1000000000 lamports of SOL
    Then sender holds a 1000000000 lamport SOL UTXO
    Given sender deposits 1000000000 lamports of SOL
    Then sender holds a 1000000000 lamport SOL UTXO
    When sender transfers 400000000 lamports of SOL to recipient
    Then the emitted event decodes
