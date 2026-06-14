Feature: Plaintext transfer output UTXO serialization

  Scenario: A plaintext transfer round-trips through serialization
    Given a shielded keypair "alice"
    And a shielded keypair "bob"
    And a shielded keypair "carol"
    When "alice" builds a plaintext transfer to "bob" and "carol"
    Then the plaintext transfer blob deserializes back unchanged

  Scenario: Plaintext transfer outputs derive sequential blindings and bootstrap tags
    Given a shielded keypair "alice"
    And a shielded keypair "bob"
    And a shielded keypair "carol"
    When "alice" builds a plaintext transfer to "bob" and "carol"
    Then the plaintext transfer derives four sequential output blindings
    And the plaintext sender change is indexed by "alice"
    And plaintext recipient output 0 is indexed by "bob"
    And plaintext recipient output 1 is indexed by "carol"
    And the plaintext transfer outputs have amounts 100, 50, 40, 10

  Scenario: A plaintext transfer rejects a wrong discriminator
    Given a shielded keypair "alice"
    And a shielded keypair "bob"
    And a shielded keypair "carol"
    When "alice" builds a plaintext transfer to "bob" and "carol"
    Then the plaintext transfer rejects a wrong discriminator

  Scenario: Plaintext sender data without an output is rejected
    Given a shielded keypair "alice"
    Then plaintext sender data without an output is rejected for "alice"

  Scenario: An Ed25519 recipient is indexed by its raw key
    Then an ed25519 plaintext recipient is indexed by its raw key
