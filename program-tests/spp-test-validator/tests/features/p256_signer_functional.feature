Feature: P256 signer authorizes shielded spends over Photon
  On the P256 rail the UTXO owner proves ownership inside the proof; the owner never
  signs the transaction and only the relayer (here, the payer) signs and pays. This
  is the contrast with the eddsa rail, where an ed25519 owner signs the transaction.
  One scenario drives a SOL, an SPL, and a mixed SOL+SPL transfer; each asserts it
  took the P256 rail, and Wallet::sync recovers every output.

  Background:
    Given a fresh shielded pool
    Given an SPL asset exists

  Scenario: The P256 proof authorizes SOL, SPL, and mixed transfers
    # SOL transfer, authorized by the proof
    Given sender deposits 1000000000 lamports of SOL
    Then sender holds a 1000000000 lamport SOL UTXO
    Given sender deposits 1000000000 lamports of SOL
    Then sender holds a 1000000000 lamport SOL UTXO
    When sender transfers 400000000 lamports of SOL to recipient
    Then the proof authorized the transfer
    When recipient syncs
    Then recipient's UTXOs match
    When sender syncs
    Then sender's UTXOs match

    # SPL transfer, authorized by the proof
    Given sender deposits 1000000000 tokens
    Then sender holds a 1000000000 token UTXO
    Given sender deposits 1000000000 tokens
    Then sender holds a 1000000000 token UTXO
    When sender transfers 400000000 tokens to recipient
    Then the proof authorized the transfer
    When recipient syncs
    Then recipient's UTXOs match
    When sender syncs
    Then sender's UTXOs match

    # Mixed SOL+SPL transfer, authorized by the proof
    Given sender deposits 1000000000 lamports of SOL
    Then sender holds a 1000000000 lamport SOL UTXO
    Given sender deposits 1000000000 tokens
    Then sender holds a 1000000000 token UTXO
    When sender transfers 400000000 tokens to recipient with SOL and SPL inputs
    Then the proof authorized the transfer
    When sender syncs
    Then sender's UTXOs match

    # Single-input SOL transfer, padded to the (2,3) shape with a dummy input
    Given sender deposits 1000000000 lamports of SOL
    Then sender holds a 1000000000 lamport SOL UTXO
    When sender transfers 600000000 lamports of SOL to recipient from a single UTXO
    Then the proof authorized the transfer
    When recipient syncs
    Then recipient's UTXOs match
    When sender syncs
    Then sender's UTXOs match

    # Single-input SPL transfer, padded to the (2,3) shape with a dummy input
    Given sender deposits 1000000000 tokens
    Then sender holds a 1000000000 token UTXO
    When sender transfers 600000000 tokens to recipient from a single UTXO
    Then the proof authorized the transfer
    When recipient syncs
    Then recipient's UTXOs match
    When sender syncs
    Then sender's UTXOs match

    # Change-only SOL transfer (no recipient): the only output is the sender's change
    Given sender deposits 1000000000 lamports of SOL
    Then sender holds a 1000000000 lamport SOL UTXO
    When sender consolidates a SOL UTXO
    Then the proof authorized the transfer
    When sender syncs
    Then sender's UTXOs match

    # Change-only SPL transfer (no recipient)
    Given sender deposits 1000000000 tokens
    Then sender holds a 1000000000 token UTXO
    When sender consolidates a token UTXO
    Then the proof authorized the transfer
    When sender syncs
    Then sender's UTXOs match

    # bystander shares no view tags, so it decrypts nothing
    Then bystander has no UTXOs
