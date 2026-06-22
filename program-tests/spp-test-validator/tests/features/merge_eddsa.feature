Feature: Merge service consolidates a Solana-owned owner's UTXOs over Photon
  The eddsa-rail analog of merge.feature. A Solana (ed25519) owner registers on the
  user-registry under its own signing key and opts into the merge service. The
  configured merge authority then consolidates several of the owner's same-asset,
  Solana-owned UTXOs into one output, proving on the 8-in/1-out merge circuit with
  the owner identity selected from the registry account owner (the `eddsa_owner`
  rail). The owner recovers the merged UTXO by decrypting the published ciphertext
  with its viewing key. The merge fails for an owner who never opted in.

  Background:
    Given a fresh shielded pool
    And sender with shielded solana keypair

  Scenario Outline: Merge service consolidates <count> of the Solana owner's SOL UTXOs
    Given sender registers for the merge service
    And sender deposits <count> SOL UTXOs of 1000000000 lamports
    When the merge service consolidates <count> of sender's SOL UTXOs
    Then sender holds one consolidated SOL UTXO

    Examples:
      | count |
      | 1 |
      | 2 |
      | 3 |
      | 4 |
      | 5 |
      | 6 |
      | 7 |
      | 8 |

  Scenario: Merge service cannot consolidate a Solana owner who never opted in
    Given sender registers without the merge service
    And sender deposits 3 SOL UTXOs of 1000000000 lamports
    Then the merge service cannot consolidate 3 of sender's SOL UTXOs
