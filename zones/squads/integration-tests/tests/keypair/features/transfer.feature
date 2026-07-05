Feature: Squads zone transfers keep funds inside the pool

  Scenario: transact transfer of SOL to another recipient
    Given a fresh squads shielded pool
    And wanda has a viewing key account
    And wendy has a viewing key account
    When wanda transfers 1000000000 lamports of SOL to wendy funded by 3000000000 and 2000000000
    Then wendy holds a 1000000000 lamport SOL zone UTXO from the transfer
    And wanda holds a 4000000000 lamport SOL change UTXO
