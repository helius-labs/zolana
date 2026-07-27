Feature: Batched deposit
  One `deposit` instruction appends several output UTXOs. Entries naming the same
  asset are summed and settled with a single transfer, and one event carries every
  output. Entries may name different assets, up to five per instruction.

  Background:
    Given a pool with a tree
    And a depositor funded with 5000000000 lamports

  Scenario: A single-asset batch settles once and appends every output
    When the depositor batch-shields 3 SOL outputs of 1000000 lamports
    Then the batch appends 3 distinct leaves

  Scenario: An empty batch is rejected
    When the depositor sends a batch with no entries
    Then the batch is rejected as an empty deposit batch

  Scenario: An entry naming a missing asset is rejected
    When the depositor sends a batch entry naming an out-of-range asset
    Then the batch is rejected as an invalid deposit asset index

  Scenario: Summed amounts that overflow are rejected
    When the depositor sends a batch whose amounts overflow
    Then the batch is rejected as a deposit amount overflow

  Scenario: A multi-asset batch settles each asset once
    Given an SPL depositor holding 1000000 tokens
    When the depositor batch-shields 1000000 lamports and 1000 tokens together
    Then the batch appends 3 distinct leaves

  Scenario: A declared asset that no entry funds is rejected
    Given an SPL depositor holding 1000000 tokens
    When the depositor sends a batch leaving a declared asset unfunded
    Then the batch is rejected as an unreferenced deposit asset

  Scenario: Declaring the same mint twice is rejected
    Given an SPL depositor holding 1000000 tokens
    When the depositor sends a batch declaring the same mint twice
    Then the batch is rejected as a duplicate deposit asset

  Scenario: The builder derives asset indices from each entry's asset
    Given an SPL depositor holding 1000000 tokens
    Then the builder assigns each entry the index of its own asset
