Feature: The transact instruction data and accounts decode over the instruction decoder
  After a shielded transfer the client has sent a `transact` instruction on chain.
  This scenario re-parses that exact instruction with the shared shielded-pool
  instruction decoder (light_instruction_decoder) and prints the named data fields
  and accounts, alongside the transaction signature, so a reader can inspect what
  was sent. It asserts the decoder recognizes the instruction and names every
  account it carries.

  Background:
    Given a fresh shielded pool
    Given sender with shielded solana keypair

  Scenario: A SOL transfer's instruction data and accounts decode
    Given sender deposits 1000000000 lamports of SOL
    Then sender holds a 1000000000 lamport SOL UTXO
    Given sender deposits 1000000000 lamports of SOL
    Then sender holds a 1000000000 lamport SOL UTXO
    When sender transfers 400000000 lamports of SOL to recipient
    Then the transact instruction data decodes
    Then the emitted event decodes
