Feature: swap cancel reclaims the escrow to the maker after expiry

  Scenario: after expiry, any holder of the order opening reclaims the escrow to maker_address
    Given the maker alice shields 1000000000 lamports of SOL
    Then alice holds a spendable 1000000000 lamport SOL UTXO
    When the maker alice creates a swap with taker bob: 400000000 lamports SOL for 250000000 of asset 2 expiring at 1
    Then the escrow for alice's order is indexed
    When alice cancels the order after expiry
    Then alice reclaims a spendable 400000000 lamport SOL UTXO
