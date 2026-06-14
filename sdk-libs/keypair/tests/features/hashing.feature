Feature: Hash primitives

  Scenario: sha256_be zeroes the most significant byte
    Then sha256_be of "abc" has a zero first byte and matches SHA-256

  Scenario: sha256 keeps the full digest for the P256 signature message
    Then sha256 of "abc" is the full SHA-256 digest and its limbs reconstruct it

  Scenario: pubkey_field of the P256 generator matches the golden vector
    Given a P256 signing key "g" from scalar 1
    Then pubkey_field of signing key "g" is "044773b2681cec700fdb631cf2ca84410447986764b430e88ac2e83e81b4a665"

  Scenario: pubkey_field is stable across calls
    Given a P256 signing key "g" from scalar 1
    Then pubkey_field of signing key "g" is stable

  Scenario: owner_hash binds the signing key and nullifier key
    Given a random P256 shielded keypair "alice"
    Then the owner hash of "alice" is stable
    And the owner hash of "alice" changes when the nullifier key changes

  Scenario: P256 and Ed25519 owners hash differently
    Then a P256 owner and an Ed25519 owner hash differently
