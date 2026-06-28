Feature: Zone config admin and proofless zone deposits

  Scenario: create, update, and rotate a zone config, then zone-shield SOL and SPL
    Given a fresh shielded pool
    When the authority creates an enabled zone config
    Then the zone config is owned by the authority and enabled
    When the authority disables zone authority transact
    Then the zone config is disabled and still owned by the authority
    When the authority rotates the zone config owner
    Then the zone config is owned by the new owner
    Then the old owner cannot update the zone config
    Then a zone config with an invalid zone authority cannot be created
    Given an SPL asset exists
    When Alice zone-shields 1000000 lamports of SOL
    Then Alice holds a 1000000 lamport SOL zone UTXO
    When Bob zone-shields 500 tokens
    Then Bob holds a 500 token zone UTXO
    Then a zone proofless deposit with the wrong signer is rejected
