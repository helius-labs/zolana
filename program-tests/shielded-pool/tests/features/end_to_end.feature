Feature: End-to-end shielded pool
  Happy-path coverage of the shielded-pool program against a real .so loaded by
  litesvm: deposits land in the vault, append leaves, and are discoverable
  through the indexer and recipient wallet.

  Background:
    Given a pool with a tree

  Scenario: A proofless SOL deposit lands in the pool vault
    When the depositor shields 1000000000 lamports into the pool
    Then the deposit lands in the pool vault and grows the tree

  Scenario: The indexer matches the on-chain root and locates deposits
    When the depositor makes the bootstrap deposit run
    Then the indexer matches the on-chain root and the recipient owns 3 UTXOs
