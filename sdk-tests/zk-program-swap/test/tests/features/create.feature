Feature: swap create_swap escrows source funds via SPP transact

  Scenario: the maker opens an order and the escrow UTXO is appended to the SPP tree
    Given the maker alice shields 1000000000 lamports of SOL
    Then alice holds a spendable 1000000000 lamport SOL UTXO
    When the maker alice creates a swap with taker bob: 400000000 lamports SOL for 250000000 of asset 2 expiring at 4000000000
    Then the escrow for alice's order is indexed
