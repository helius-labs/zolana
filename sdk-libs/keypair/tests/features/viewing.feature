Feature: Viewing keys and view tags

  Scenario: ECDH is symmetric between two viewing keys
    Given a random viewing key "alice"
    And a random viewing key "bob"
    Then "alice" and "bob" agree on a shared secret

  Scenario: A viewing key round-trips through its secret bytes
    Given a random viewing key "alice"
    Then viewing key "alice" round-trips through its secret bytes

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
