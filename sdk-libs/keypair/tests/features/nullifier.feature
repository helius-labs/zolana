Feature: Nullifier derivation

  Scenario: The nullifier key is deterministic from the signing key
    Given a random P256 signing key "k"
    Then the nullifier key derived from "k" is deterministic

  Scenario: Distinct signing keys yield distinct nullifier secrets
    Given a random P256 signing key "a"
    And a random P256 signing key "b"
    Then "a" and "b" derive different nullifier secrets

  Scenario: A nullifier binds the utxo hash, blinding, and secret
    Then a nullifier changes with the utxo hash, the blinding, and the secret

  Scenario: The nullifier public key matches the golden vector
    Then the nullifier public key for secret 7 is "2ece7cecb48850fb1762bea0a87c4f8290c40f90ac43b9dae85eed13b2e9af8c"
