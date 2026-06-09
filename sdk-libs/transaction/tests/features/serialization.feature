Feature: UTXO serialization

  Scenario: A recipient plaintext round-trips with and without program data
    Given a shielded keypair "alice"
    Then a recipient plaintext for "alice" round-trips with and without program data

  Scenario: A sender plaintext round-trips
    Given a shielded keypair "sender"
    And a shielded keypair "alice"
    Then a sender plaintext for "sender" to "alice" round-trips

  Scenario: A transfer blob round-trips and rejects a wrong discriminator
    Then a transfer blob round-trips and rejects a wrong discriminator

  Scenario: A split bundle round-trips with distinct output blindings
    Given a shielded keypair "owner"
    Then a split bundle for "owner" round-trips with distinct output blindings

  Scenario: A split blob round-trips and rejects a wrong discriminator
    Then a split blob round-trips and rejects a wrong discriminator
