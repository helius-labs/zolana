Feature: Squads ring deposits move real funds through SPP

  Scenario: deposit SOL through the ring
    Given a fresh squads shielded pool
    And alice has a viewing key account
    When alice deposits 1000000 lamports of SOL
    Then alice holds a 1000000 lamport SOL ring UTXO

  Scenario: deposit SPL through the ring
    Given a fresh squads shielded pool
    And an SPL asset exists
    And bob has a viewing key account
    When bob deposits 500 tokens
    Then bob holds a 500 token ring UTXO
