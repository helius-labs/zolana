Feature: The Squads zone crank auto-merges fragmented balances

  Scenario: the crank consolidates two SOL deposits into one UTXO
    Given a fresh squads shielded pool
    And alice has a viewing key account
    When alice deposits 3000000000 lamports of SOL
    And alice deposits 2000000000 lamports of SOL
    Then the crank consolidates alice into a 5000000000 lamport SOL UTXO

  Scenario: a transfer recipient consolidates its credits
    Given a fresh squads shielded pool
    And sam has a viewing key account
    And rachel has a viewing key account
    When rachel deposits 1000000000 lamports of SOL
    And sam transfers 2000000000 lamports of SOL to rachel funded by 3000000000 and 2000000000
    Then the crank consolidates rachel into a 3000000000 lamport SOL UTXO
