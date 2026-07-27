Feature: User registry program

  Background:
    Given a funded user registry test rig

  # === register ===

  Scenario: Register creates an owner record
    Given owner "alice" with p256 keys
    When "alice" registers on-chain
    Then "alice" has a user record

  Scenario: Register without an owner p256 key for Solana-only signers
    Given owner "alice" with p256 keys
    When "alice" registers on-chain without an owner p256 key
    Then "alice" has a user record without an owner p256 key

  Scenario: Owner updates registered shielded keys
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    When "alice" updates registry keys
    Then "alice" has a user record

  Scenario: Owner updates to Solana-only signing keys
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    When "alice" updates registry keys without an owner p256 key
    Then "alice" has a user record without an owner p256 key

  Scenario: Key updates preserve merge-service state
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And owner "alice" enables merge service
    When "alice" updates registry keys
    Then "alice" has merge service enabled

  Scenario: Register succeeds when the record address was pre-funded
    Given owner "alice" with p256 keys
    And the record address of "alice" is pre-funded
    When "alice" registers on-chain
    Then "alice" has a user record

  Scenario: Registering twice fails
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    When "alice" tries to register again
    Then the transaction fails with "AccountAlreadyInitialized"

  # === set_merge_service ===

  Scenario: Merge service defaults off and the owner can toggle it
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    Then "alice" has merge service disabled
    When owner "alice" enables merge service
    Then "alice" has merge service enabled
    When owner "alice" disables merge service
    Then "alice" has merge service disabled

  Scenario: A stranger cannot enable merge service
    Given owner "alice" with p256 keys
    And "alice" registers on-chain
    And a stranger "mallory"
    When "mallory" tries to enable merge service for "alice"
    Then the transaction fails with "UnauthorizedSigner"
