Feature: swap fill fills the order before expiry

  Scenario: the taker fills the order, paying the destination asset to the maker and taking the source asset
    Given the maker alice shields 1000000000 lamports of SOL
    Then alice holds a spendable 1000000000 lamport SOL UTXO
    When the maker alice creates a swap with taker bob: 400000000 lamports SOL for 250000000 of asset 1 expiring at 4000000000
    Then the escrow for alice's order is indexed
    When the taker bob shields 250000000 lamports of SOL
    When taker bob fills alice's order
    Then alice holds a spendable 250000000 lamport SOL UTXO from fill
    Then bob holds a spendable 400000000 lamport SOL UTXO from fill
