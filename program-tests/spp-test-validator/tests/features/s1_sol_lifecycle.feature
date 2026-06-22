Feature: SOL decrypt-and-spend lifecycle over Photon
  A note that Photon indexed is recovered by Wallet::sync (decryption) and then
  spent, closing the loop end to end. Recovery is checked with a full-struct
  assert over the wallet's recovered note set (tracked in the World).

  Only the transfer_p256_2_3 proving key is available and the client does not pad
  inputs to the shape, so every transfer consolidates exactly two SOL notes.

  Background:
    Given a fresh shielded pool

  Scenario: Transfer recipient and sender change are decrypted, and the change is spent
    Given sender deposits 1000000000 lamports of SOL
    And sender deposits 1000000000 lamports of SOL
    When sender transfers 400000000 lamports of SOL to recipient
    When recipient syncs
    Then recipient's UTXOs match
    When sender syncs
    Then sender's UTXOs match
    Given sender deposits 1000000000 lamports of SOL
    When sender spends 500000000 lamports of SOL to sink
    When sender syncs
    Then sender's UTXOs match
    And bystander has no UTXOs
