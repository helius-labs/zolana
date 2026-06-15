Feature: Zone config admin
  Creating and updating policy-zone configs through the test zone wrapper.

  Scenario: Create and update a zone config
    Given a booted shielded pool
    And the zone test program is loaded
    And a funded payer
    When the payer creates an enabled zone config
    Then the zone config is owned by the authority and enabled
    When the authority disables zone authority transact
    Then the zone config is disabled and still owned by the authority
    When the authority rotates the zone config owner
    Then the zone config is owned by the new owner
    When the old owner tries to update the zone config
    Then the new owner can update the zone config

  Scenario: Creating a zone config rejects a fake zone authority
    Given a booted shielded pool
    And a funded payer
    When a payer tries to create a zone config with a fake zone authority
    Then the operation is rejected as an invalid zone config
