Feature: Proofless SOL shield
  Public SOL deposits into the shielded pool through the proofless-shield
  instruction, including the negative shape and account checks.

  Background:
    Given a pool with a tree
    And a depositor funded with 5000000000 lamports

  Scenario: A SOL deposit succeeds and the event is faithful
    When the depositor shields 750000000 lamports to a fresh recipient
    Then a proofless deposit event is emitted
    And the recipient owns 1 UTXO

  Scenario: Bad amount shapes are rejected and leave the indexer unchanged
    Given the indexer UTXO count is recorded
    When the depositor shields zero lamports
    And the depositor shields zero SPL tokens
    Then the indexer UTXO count is unchanged

  Scenario: Account shape violations are rejected
    When the depositor shields with the program account missing
    Then the operation fails with not enough account keys
    When the depositor shields with the wrong vault
    Then the operation is rejected as invalid settlement accounts
    When the depositor shields with an extra account
    Then the operation is rejected as invalid settlement accounts
    When the depositor shields with a foreign source account
    Then the operation is rejected as invalid settlement accounts
    When the depositor shields with a foreign tree account
    Then the operation is rejected as invalid tree accounts

  Scenario: Deposits into a paused tree are rejected until unpaused
    When the authority pauses the tree
    And the depositor shields 1000000 lamports into the paused tree
    Then the deposit is rejected because the tree is paused
    When the authority unpauses the tree
    Then the depositor can shield 1000000 lamports after unpause

  Scenario: An unaffordable deposit fails
    When the depositor shields 100000000000 lamports it cannot afford
    Then the deposit fails with insufficient lamports

  Scenario: Repeat deposits create distinct leaves
    When the depositor shields 1000000 lamports twice with the same data
    Then the two deposits create distinct leaves and the indexer tracks them

  Scenario: Truncated instruction data is rejected
    When the depositor sends truncated instruction data
    Then the operation is rejected as invalid instruction data

  Scenario: Directly invoking emit-event is ignored by the indexer
    When the payer invokes emit-event directly
    Then no event is indexed

  Scenario: Too few accounts is rejected
    When the depositor shields with too few accounts
    Then the operation fails with not enough account keys
