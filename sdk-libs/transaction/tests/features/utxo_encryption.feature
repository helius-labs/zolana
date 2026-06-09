Feature: UTXO encryption round-trips

  Scenario: A standard transfer round-trips all outputs (2 inputs, 3 outputs)
    Given a shielded keypair "sender"
    And a shielded keypair "alice"
    Then a transfer from "sender" to "alice" round-trips the change and recipient utxos

  Scenario: A split round-trips through UTXOs
    Given a shielded keypair "owner"
    Then a split by "owner" round-trips through utxos
