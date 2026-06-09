Feature: Transfer output UTXO serialization

  Scenario: A single-recipient transfer round-trips end to end
    Given a shielded keypair "sender"
    And a shielded keypair "alice"
    When "sender" builds a transfer paying 1000 to "alice"
    Then the transfer blob deserializes back unchanged
    And the slot view tag of "alice" is their bootstrap tag
    And "sender" recovers the transfer
    And "alice" syncs the transfer and reads amount 1000
    And a stranger cannot read the slot of "alice"

  Scenario: A two-recipient transfer round-trips end to end
    Given a shielded keypair "sender"
    And a shielded keypair "alice"
    And a shielded keypair "bob"
    When "sender" builds a transfer paying 1000 to "alice" and 2000 to "bob"
    Then the transfer blob deserializes back unchanged
    And "sender" recovers the transfer
    And "alice" syncs the transfer and reads amount 1000
    And "bob" syncs the transfer and reads amount 2000

  Scenario: A transfer with no recipients still encodes the sender change
    Given a shielded keypair "sender"
    When "sender" builds a transfer with no recipients
    Then the transfer blob deserializes back unchanged
    And "sender" recovers the transfer

  Scenario: A recipient cannot read another recipient's slot
    Given a shielded keypair "sender"
    And a shielded keypair "alice"
    And a shielded keypair "bob"
    When "sender" builds a transfer paying 1000 to "alice" and 2000 to "bob"
    Then "alice" can read their slot but not the slot of "bob"

  Scenario: A tampered recipient slot count is rejected
    Given a shielded keypair "sender"
    And a shielded keypair "alice"
    When "sender" builds a transfer paying 1000 to "alice"
    Then a tampered recipient slot count is rejected for "sender"
