Feature: Spend-authorizing signatures

  Scenario: A P256 signing key signs and verifies
    Given a random P256 signing key "k"
    When "k" signs "private_tx_hash" as "sig"
    Then "k" verifies "sig" over "private_tx_hash"
    And signing key "k" has scheme P256

  Scenario: A P256 signature is rejected for a wrong message or tampered bytes
    Given a random P256 signing key "k"
    When "k" signs "a" as "sig"
    Then "k" does not verify "sig" over "b"
    And "k" does not verify a tampered "sig" over "a"

  Scenario: P256 signing is deterministic
    Given a random P256 signing key "k"
    Then "k" signs "same" identically twice

  Scenario: An Ed25519 signing key signs and verifies
    Given a random Ed25519 signing key "k"
    When "k" signs "private_tx_hash" as "sig"
    Then "k" verifies "sig" over "private_tx_hash"
    And "k" does not verify "sig" over "other"
    And signing key "k" has scheme Ed25519

  Scenario: A P256 signing key round-trips through its secret bytes
    Given a random P256 signing key "k"
    Then signing key "k" round-trips through P256 secret bytes

  Scenario: An Ed25519 signing key round-trips through its seed
    Given a random Ed25519 signing key "k"
    Then signing key "k" round-trips through an Ed25519 seed
