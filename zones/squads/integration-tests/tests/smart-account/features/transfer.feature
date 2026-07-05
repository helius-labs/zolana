Feature: Squads smart-account transfers keep funds inside the pool

  Scenario: transact transfer of SOL to another recipient
    Given a fresh squads shielded pool
    And wanda has a viewing key account
    And wendy has a viewing key account
    When wanda transfers 1000000000 lamports of SOL to wendy funded by 3000000000 and 2000000000
    Then the backend auditor decrypts wendy's SOL balance as 1000000000 lamports
    And the backend auditor decrypts wanda's SOL balance as 4000000000 lamports

  Scenario: execute_proposal transfer of SOL to another recipient
    Given a fresh squads shielded pool
    And wanda has a viewing key account
    And wendy has a viewing key account
    When wanda creates a proposal to transfer 1000000000 lamports of SOL to wendy funded by 3000000000 and 2000000000
    And the crank settles the transfer proposal
    Then the backend auditor decrypts wendy's SOL balance as 1000000000 lamports
    And the backend auditor decrypts wanda's SOL balance as 4000000000 lamports
