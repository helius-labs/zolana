Feature: Squads smart-account withdrawals move real funds out of SPP

  Scenario: transact withdrawal of SOL leaves the pool
    Given a fresh squads shielded pool
    And wanda has a viewing key account
    When wanda deposits 5000000000 lamports of SOL
    Then wanda holds a 5000000000 lamport SOL zone UTXO
    When wanda withdraws 2000000000 lamports of SOL
    Then wanda received 2000000000 lamports of SOL from the pool
    And the backend auditor decrypts wanda's SOL balance as 3000000000 lamports

  Scenario: execute_proposal withdrawal of SOL leaves the pool
    Given a fresh squads shielded pool
    And wade has a viewing key account
    When wade deposits 5000000000 lamports of SOL
    Then wade holds a 5000000000 lamport SOL zone UTXO
    When wade creates a SOL withdrawal proposal
    And the crank settles the withdrawal proposal
    Then the backend auditor decrypts wade's SOL balance as 3000000000 lamports

  Scenario: transact withdrawal of SPL leaves the pool
    Given a fresh squads shielded pool
    And an SPL asset exists
    And walt has a viewing key account
    When walt deposits 1000 tokens
    Then walt holds a 1000 token zone UTXO
    When walt withdraws 400 tokens
    Then walt received 400 tokens from the pool
    And the backend auditor decrypts walt's SPL balance as 600 tokens
