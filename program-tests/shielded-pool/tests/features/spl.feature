Feature: SPL asset registration and deposits
  Registering SPL interfaces (registry + vault) and public SPL deposits through
  the proofless-shield settlement path.

  Background:
    Given a pool with a tree

  Scenario: Registering an SPL interface initializes the registry and vault
    When the authority registers an SPL interface for a mint
    Then the registry and vault are initialized with indices 2 and 3
    When the authority registers the same SPL interface again
    Then the operation is rejected as an invalid SPL asset registry
    When the authority registers an SPL interface for a second mint
    Then the registry and vault are initialized with indices 3 and 4

  Scenario: Registering an SPL interface rejects a non-authority
    When a non-authority registers an SPL interface for a mint
    Then the operation is rejected as unauthorized

  Scenario: An SPL deposit succeeds and the event is faithful
    Given an SPL depositor holding 1000000 tokens
    When the SPL depositor shields 400000 tokens to a fresh recipient
    Then a proofless shield event is emitted
    And the recipient owns 1 UTXO

  Scenario: A deposit from a foreign token account is rejected
    Given an SPL depositor holding 1000000 tokens
    When the SPL depositor shields from a foreign token account
    Then the operation is rejected as invalid settlement accounts

  Scenario: A deposit through a non-canonical vault is rejected
    Given an SPL depositor holding 1000000 tokens
    When the SPL depositor shields through a non-canonical vault
    Then the operation is rejected as invalid settlement accounts

  Scenario: A deposit with a mismatched mint is rejected
    Given an SPL depositor holding 1000000 tokens
    When the SPL depositor shields with a mismatched mint
    Then the operation is rejected as invalid settlement accounts

  Scenario: An unaffordable SPL deposit fails
    Given an SPL depositor holding 1000 tokens
    When the SPL depositor shields 5000 tokens it cannot afford
    Then the SPL deposit fails with insufficient token funds
