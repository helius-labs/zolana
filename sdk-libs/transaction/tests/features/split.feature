Feature: Split output UTXO serialization

  Scenario: Splitting a balance into equal parts round-trips
    Given a shielded keypair "owner"
    When "owner" splits into 4 outputs of 200
    Then the split blob deserializes back unchanged
    And the split has 4 distinct output blindings
    And "owner" decrypts the split and reads 4 outputs of 200

  Scenario: Splitting into the maximum of eight outputs round-trips
    Given a shielded keypair "owner"
    When "owner" splits into 8 outputs of 125
    Then the split blob deserializes back unchanged
    And the split has 8 distinct output blindings
    And "owner" decrypts the split and reads 8 outputs of 125
