Feature: Zone proofless deposit
  Policy-zone proofless deposits routed through the test zone wrapper program.

  Background:
    Given a pool with a tree

  Scenario: A zone proofless deposit succeeds and the event is faithful
    When the depositor zone-shields 750000000 lamports to a fresh recipient
    Then an encrypted zone deposit event is emitted
    And the recipient owns 1 UTXO

  Scenario: A zone proofless SPL deposit succeeds and the event is faithful
    Given an SPL depositor holding 1000000 tokens
    When the SPL depositor zone-shields 1000 tokens to a fresh recipient
    Then an encrypted zone deposit event is emitted
    And the recipient owns 1 UTXO

  Scenario: A same-asset zone batch preserves every output's policy data
    When the depositor zone-batch-shields 3 SOL outputs of 1000000 lamports
    Then the zone batch appends 3 distinct leaves

  Scenario: A multi-asset zone batch settles each asset once
    Given an SPL depositor holding 1000000 tokens
    When the SPL depositor zone-batch-shields 1000000 lamports and 1000 tokens
    Then the zone batch appends 3 distinct leaves

  Scenario: A zone proofless deposit with the wrong signer is rejected
    When a zone proofless deposit is sent straight to the pool with the wrong signer
    Then the operation is rejected as an invalid zone config
