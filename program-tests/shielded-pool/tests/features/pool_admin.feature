Feature: Shielded pool admin
  Protocol config creation, tree creation, authority rotation, and pause
  authority, exercised against the litesvm-loaded shielded-pool program.

  Scenario: Creating the protocol config succeeds exactly once
    Given a booted shielded pool
    When the authority creates the protocol config
    Then the protocol config has the authority
    And creating the protocol config again is rejected as invalid

  Scenario: Protocol config creation survives donated lamports
    Given a booted shielded pool
    When lamports are donated to the protocol config address
    And the authority creates the protocol config on the pre-funded address
    Then the protocol config has the authority

  Scenario: Protocol config persists the merge authority across rotation
    Given a booted shielded pool
    When the authority creates the protocol config with one merge authority
    Then the protocol config records that merge authority
    When the authority rotates to a new authority with a new merge authority
    Then the protocol config records that merge authority

  Scenario: Creating the protocol config rejects a mismatched authority
    Given a booted shielded pool
    When a signer creates a protocol config naming a different authority
    Then the operation is rejected as unauthorized

  Scenario: Creating a tree rejects a non-authority
    Given a booted shielded pool
    And a protocol config
    When a non-authority tries to create a tree
    Then the operation is rejected as unauthorized

  Scenario: Updating the protocol config rotates the authority
    Given a pool with a tree
    When the authority rotates to a new authority
    Then the old authority can no longer update the config
    And the new authority can update the config and create trees

  Scenario: Updating the protocol config rejects a non-authority
    Given a pool with a tree
    When a non-authority tries to update the config
    Then the operation is rejected as unauthorized

  Scenario: Pausing a tree rejects a non-authority
    Given a pool with a tree
    When a non-authority tries to pause the tree
    Then the operation is rejected as unauthorized

  Scenario: Pausing a tree requires an existing protocol config
    Given a booted shielded pool
    When someone tries to pause a tree without a protocol config
    Then the operation is rejected as invalid protocol config

  Scenario: Creating a tree rejects an undersized account
    Given a booted shielded pool
    And a protocol config
    When the authority tries to create an undersized tree
    Then the operation is rejected as invalid tree accounts
