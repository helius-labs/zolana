Feature: UTXO encryption round-trips

  Scenario: A standard transfer round-trips all outputs (2 inputs, 3 outputs)
    Given a shielded keypair "sender"
    And a shielded keypair "alice"
    Then a transfer from "sender" to "alice" round-trips the change and recipient utxos

  Scenario: A split round-trips through UTXOs
    Given a shielded keypair "owner"
    Then a split by "owner" round-trips through utxos

  Scenario: A zone-owned recipient UTXO with data is rejected
    Given a shielded keypair "owner"
    Then a zone-owned recipient utxo with data for "owner" is rejected

  Scenario: Zone data without a zone program id is rejected
    Given a shielded keypair "owner"
    Then zone data without a zone program id is rejected for "owner"

  Scenario: A zone program id without zone data is not set
    Given a shielded keypair "owner"
    Then a zone program id without zone data is not set for "owner"

  Scenario: Sender data on a zero-amount output is rejected
    Given a shielded keypair "owner"
    Then sender data on a zero-amount output is rejected for "owner"
