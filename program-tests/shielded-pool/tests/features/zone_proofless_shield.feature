Feature: Zone proofless shield
  Policy-zone proofless deposits routed through the test zone wrapper program.

  Background:
    Given a pool with a tree

  Scenario: A zone proofless deposit succeeds and the event is faithful
    When the depositor zone-shields 750000000 lamports to a fresh recipient

  Scenario: A zone proofless deposit with the wrong signer is rejected
    When a zone proofless deposit is sent straight to the pool with the wrong signer
    Then the operation is rejected as invalid settlement accounts
