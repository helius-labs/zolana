Feature: The squads crank auto-merges fragmented balances into one UTXO

  Scenario: two deposits to one account auto-merge into a single UTXO
    Given a fresh squads shielded pool
    And alice has a viewing key account
    When alice deposits 1000000000 lamports of SOL
    And alice deposits 2000000000 lamports of SOL
    Then alice consolidates into a 3000000000 lamport SOL UTXO

  Scenario: a recipient's transferred UTXOs auto-merge after settlement
    Given a fresh squads shielded pool
    And wanda has a viewing key account
    And wendy has a viewing key account
    When wanda transfers 1000000000 lamports of SOL to wendy funded by 3000000000 and 2000000000
    And wanda transfers 1000000000 lamports of SOL to wendy funded by 3000000000 and 2000000000
    Then wendy consolidates into a 2000000000 lamport SOL UTXO
