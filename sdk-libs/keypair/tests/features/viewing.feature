Feature: Viewing keys and view tags

  Scenario: ECDH is symmetric between two viewing keys
    Given a random viewing key "alice"
    And a random viewing key "bob"
    Then "alice" and "bob" agree on a shared secret

  Scenario: A viewing key round-trips through its secret bytes
    Given a random viewing key "alice"
    Then viewing key "alice" round-trips through its secret bytes

  Scenario: Derived view-tag secrets are deterministic and distinct
    Given a random viewing key "alice"
    Then viewing key "alice" derives four distinct, stable secrets

  Scenario: Distinct viewing keys derive distinct secrets
    Given a random viewing key "alice"
    And a random viewing key "bob"
    Then "alice" and "bob" derive different sender view-tag secrets

  Scenario: Sender and request view tags advance with their counters
    Given a random viewing key "alice"
    Then sender and request view tags for "alice" advance with their counters

  Scenario: Merge view tags are namespaced by authority and counter
    Given a random viewing key "alice"
    Then merge view tags for "alice" are namespaced by authority and counter

  Scenario: Shared view tags match across the pair and differ per index
    Given a random viewing key "sender"
    And a random viewing key "recipient"
    Then "sender" and "recipient" derive the same shared view tag at index 0
    And "sender" derives different shared view tags toward "recipient" at indices 0 and 1

  Scenario: The bootstrap view tag is the viewing public key x-coordinate
    Given a random viewing key "alice"
    Then the bootstrap tag of "alice" is its viewing public key x-coordinate

  Scenario: A transaction viewing key is deterministic per first nullifier
    Given a random viewing key "alice"
    Then the transaction viewing key of "alice" is deterministic per first nullifier

  Scenario: A transfer ciphertext round-trips to the recipient
    Given a random viewing key "sender"
    And a random viewing key "recipient"
    When "sender" derives a transaction viewing key "tx" from nullifier 7
    And "tx" encrypts "recipient utxo plaintext" to "recipient" as "ct"
    Then "recipient" decrypts "ct" from "tx" as "recipient utxo plaintext"

  Scenario: A stranger cannot decrypt a transfer ciphertext
    Given a random viewing key "sender"
    And a random viewing key "recipient"
    And a random viewing key "stranger"
    When "sender" derives a transaction viewing key "tx" from nullifier 7
    And "tx" encrypts "secret" to "recipient" as "ct"
    Then "stranger" cannot decrypt "ct" from "tx"

  Scenario: A tampered ciphertext is rejected
    Given a random viewing key "sender"
    And a random viewing key "recipient"
    When "sender" derives a transaction viewing key "tx" from nullifier 7
    And "tx" encrypts "hello" to "recipient" as "ct"
    Then a tampered "ct" cannot be decrypted by "recipient" from "tx"

  Scenario: Decryption fails under a different info label
    Given a random viewing key "sender"
    And a random viewing key "recipient"
    When "sender" derives a transaction viewing key "tx" from nullifier 7
    And "tx" encrypts "hello" to "recipient" with info "TSPP/tx" as "ct"
    Then "recipient" cannot decrypt "ct" from "tx" with info "TSPP/merge"

  Scenario: Decryption fails under a different AAD
    Given a random viewing key "sender"
    And a random viewing key "recipient"
    When "sender" derives a transaction viewing key "tx" from nullifier 7
    And "tx" encrypts "hello" to "recipient" with aad "aad1" as "ct"
    Then "recipient" cannot decrypt "ct" from "tx" with aad "aad2"

  Scenario: The HKDF KEM ciphertext matches the golden vector
    Given a viewing key "eph" from scalar 1
    And a viewing key "rcpt" from scalar 2
    Then "eph" encrypting "deterministic" to "rcpt" yields ciphertext "82a9987a69b9627d60fe544fbadf2f1e4d0b19034284b0269b36410fb9"
