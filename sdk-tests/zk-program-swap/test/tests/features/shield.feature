Feature: swap maker shields source funds into SPP

  Scenario: the maker shields SOL and holds a spendable confidential UTXO
    Given the maker alice shields 1000000000 lamports of SOL
    Then alice holds a spendable 1000000000 lamport SOL UTXO
