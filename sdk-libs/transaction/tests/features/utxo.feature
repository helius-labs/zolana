Feature: UTXO hash and nullifier

  Scenario: The UTXO hash is deterministic and binds the amount
    Given a shielded keypair "alice"
    Then the utxo hash for "alice" is deterministic and changes with the amount

  Scenario: The UTXO hash nests the owner commitment per spec
    Given a shielded keypair "alice"
    Then the utxo hash for "alice" nests the owner commitment per spec

  Scenario: The UTXO nullifier matches the keypair nullifier
    Given a shielded keypair "alice"
    Then the utxo nullifier for "alice" matches the keypair nullifier
