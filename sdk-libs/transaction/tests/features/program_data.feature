Feature: Program data

  Scenario: Program data round-trips inside a transfer
    Given a shielded keypair "sender"
    And a shielded keypair "alice"
    When "sender" builds a transfer to "alice" with program data
    Then "sender" recovers the transfer
    And "alice" recovers the program data
