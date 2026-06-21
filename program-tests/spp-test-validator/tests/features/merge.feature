Feature: Merge service consolidates an owner's UTXOs over Photon
  A UTXO owner registers on the user-registry and opts into the merge service. The
  configured merge authority then consolidates several of the owner's same-asset,
  P256-owned UTXOs into one output, proving on the 8-in/1-out merge circuit, and the
  owner recovers the merged UTXO by decrypting the published ciphertext with its
  viewing key. The merge fails for an owner who never opted in.

  Background:
    Given a fresh shielded pool

  Scenario Outline: Merge service consolidates <count> of the owner's SOL UTXOs
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

  Scenario: Merge service cannot consolidate an owner who never opted in
    Given sender registers without the merge service
    And sender deposits 3 SOL UTXOs of 1000000000 lamports
    Then the merge service cannot consolidate 3 of sender's SOL UTXOs
