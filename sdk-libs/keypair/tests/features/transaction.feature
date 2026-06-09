Feature: Transaction slot encryption

  Scenario: A slot round-trips for recipient and sender
    Given a random viewing key "sender"
    And a random viewing key "alice"
    Then "sender" encrypts a slot to "alice" and both can read it

  Scenario: Distinct slots get distinct ciphertexts
    Given a random viewing key "sender"
    And a random viewing key "alice"
    Then "sender" encrypts the same payload to "alice" in two slots with distinct ciphertexts

  Scenario: A stranger cannot decrypt a slot
    Given a random viewing key "sender"
    And a random viewing key "alice"
    And a random viewing key "stranger"
    Then "stranger" cannot decrypt a slot from "sender" to "alice"

  Scenario: A tampered slot is rejected
    Given a random viewing key "sender"
    And a random viewing key "alice"
    Then a tampered slot from "sender" to "alice" is rejected

  Scenario: The golden ciphertext decrypts
    Given a viewing key "eph" from scalar 1
    And a viewing key "rcpt" from scalar 2
    Then "rcpt" decrypts the golden ciphertext from "eph"
