Feature: Squads zone withdrawals move real funds out of SPP

  Scenario: transact withdrawal of SOL leaves the pool
    Given a fresh squads shielded pool
    And wanda has a viewing key account
    When wanda deposits 5000000000 lamports of SOL
    Then wanda holds a 5000000000 lamport SOL zone UTXO
    When wanda withdraws 2000000000 lamports of SOL
    Then wanda received 2000000000 lamports of SOL from the pool

  Scenario: transact withdrawal of SPL leaves the pool
    Given a fresh squads shielded pool
    And an SPL asset exists
    And walt has a viewing key account
    When walt deposits 1000 tokens
    Then walt holds a 1000 token zone UTXO
    When walt withdraws 400 tokens
    Then walt received 400 tokens from the pool
