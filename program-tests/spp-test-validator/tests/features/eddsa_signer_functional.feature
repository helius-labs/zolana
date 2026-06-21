Feature: eddsa signer authorizes shielded spends over Photon
  On the Solana-only eddsa rail (transfer_2_3) the UTXO owner is an ed25519 key and
  authorizes each spend by signing the transaction, checked by the program at the
  eddsa signer index. This is the contrast with the P256 rail, where ownership is
  proven inside the proof and the owner never signs the transaction. One scenario
  drives a SOL, an SPL, and a mixed SOL+SPL transfer; each asserts it took the
  eddsa rail, and Wallet::sync recovers every output.

  Background:
    Given a fresh shielded pool
    Given an SPL asset exists
    Given sender with shielded solana keypair

  Scenario: The eddsa signer authorizes SOL, SPL, and mixed transfers
    # SOL transfer, authorized by the eddsa signer
    Given sender deposits 1000000000 lamports of SOL
    Then sender holds a 1000000000 lamport SOL UTXO
    Given sender deposits 1000000000 lamports of SOL
    Then sender holds a 1000000000 lamport SOL UTXO
    When sender transfers 400000000 lamports of SOL to recipient
    Then the eddsa signer authorized the transfer
    When recipient syncs
    Then recipient's UTXOs match
    When sender syncs
    Then sender's UTXOs match

    # SPL transfer, authorized by the eddsa signer
    Given sender deposits 1000000000 tokens
    Then sender holds a 1000000000 token UTXO
    Given sender deposits 1000000000 tokens
    Then sender holds a 1000000000 token UTXO
    When sender transfers 400000000 tokens to recipient
    Then the eddsa signer authorized the transfer
    When recipient syncs
    Then recipient's UTXOs match
    When sender syncs
    Then sender's UTXOs match

    # Mixed SOL+SPL transfer, authorized by the eddsa signer
    Given sender deposits 1000000000 lamports of SOL
    Then sender holds a 1000000000 lamport SOL UTXO
    Given sender deposits 1000000000 tokens
    Then sender holds a 1000000000 token UTXO
    When sender transfers 400000000 tokens to recipient with SOL and SPL inputs
    Then the eddsa signer authorized the transfer
    When sender syncs
    Then sender's UTXOs match

    # Single-input SOL transfer, padded to the (2,3) shape with a dummy input
    Given sender deposits 1000000000 lamports of SOL
    Then sender holds a 1000000000 lamport SOL UTXO
    When sender transfers 600000000 lamports of SOL to recipient from a single UTXO
    Then the eddsa signer authorized the transfer
    When recipient syncs
    Then recipient's UTXOs match
    When sender syncs
    Then sender's UTXOs match

    # Single-input SPL transfer, padded to the (2,3) shape with a dummy input
    Given sender deposits 1000000000 tokens
    Then sender holds a 1000000000 token UTXO
    When sender transfers 600000000 tokens to recipient from a single UTXO
    Then the eddsa signer authorized the transfer
    When recipient syncs
    Then recipient's UTXOs match
    When sender syncs
    Then sender's UTXOs match

    # Change-only SOL transfer (no recipient): the only output is the sender's change
    Given sender deposits 1000000000 lamports of SOL
    Then sender holds a 1000000000 lamport SOL UTXO
    When sender consolidates a SOL UTXO
    Then the eddsa signer authorized the transfer
    When sender syncs
    Then sender's UTXOs match

    # Change-only SPL transfer (no recipient)
    Given sender deposits 1000000000 tokens
    Then sender holds a 1000000000 token UTXO
    When sender consolidates a token UTXO
    Then the eddsa signer authorized the transfer
    When sender syncs
    Then sender's UTXOs match
