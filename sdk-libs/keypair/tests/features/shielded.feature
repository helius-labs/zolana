Feature: Shielded keypair facade

  Scenario: The shielded address exposes the three public keys and owner hash
    Given a random P256 shielded keypair "alice"
    Then the shielded address of "alice" is consistent

  Scenario: from_keys derives the nullifier key from the signing key
    Given a random P256 signing key "s"
    And a random viewing key "v"
    Then a shielded keypair from "s" and "v" matches the standalone nullifier key

  Scenario: The facade signs and computes nullifiers
    Given a random P256 shielded keypair "alice"
    Then the facade of "alice" signs and computes nullifiers consistently

  Scenario: The facade derives symmetric shared view tags
    Given a random P256 shielded keypair "sender"
    And a random P256 shielded keypair "recipient"
    Then "sender" and "recipient" derive matching shared view tags through the facade

  Scenario: An end-to-end transfer round-trips through the facade
    Given a random P256 shielded keypair "sender"
    And a random P256 shielded keypair "recipient"
    Then a transfer from "sender" to "recipient" round-trips through the facade
