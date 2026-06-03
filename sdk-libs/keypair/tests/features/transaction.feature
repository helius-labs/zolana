Feature: Transaction encryption

  Scenario: A transaction round-trips for the sender across recipients
    Given a random viewing key "sender"
    And a random viewing key "alice"
    And a random viewing key "bob"
    Then "sender" encrypts and decrypts a transaction to "alice" and "bob"

  Scenario: A duplicate recipient gets a distinct nonce per slot
    Given a random viewing key "sender"
    And a random viewing key "alice"
    Then "sender" encrypts a transaction to "alice" twice with distinct ciphertexts

  Scenario: A stranger cannot decrypt a transaction
    Given a random viewing key "sender"
    And a random viewing key "alice"
    And a random viewing key "stranger"
    Then "stranger" cannot decrypt a transaction from "sender" to "alice"

  Scenario: A tampered transaction ciphertext is rejected
    Given a random viewing key "sender"
    And a random viewing key "alice"
    Then a tampered transaction from "sender" to "alice" is rejected

  Scenario: Encrypting an empty transaction fails
    Given a random viewing key "sender"
    Then "sender" fails to encrypt an empty transaction

  Scenario: Encrypting a transaction with a truncated sender bundle fails
    Given a random viewing key "sender"
    Then "sender" fails to encrypt a transaction with a truncated sender bundle

  Scenario: The golden transaction ciphertext decrypts
    Given a viewing key "eph" from scalar 1
    And a viewing key "rcpt" from scalar 2
    Then "rcpt" decrypts the golden ciphertext from "eph"
