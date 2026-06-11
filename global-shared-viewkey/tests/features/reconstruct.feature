Feature: Shared view key reconstruction

  Scenario: Every entity meets its inner threshold
    Given a global shared view key authority
    When the authority splits the key 3-of-3 with inner policies "2-of-5, 2-of-5, 2-of-5"
    And each entity returns "2, 2, 2" sub-shares
    Then the key is reconstructed

  Scenario: One entity returns too few sub-shares
    Given a global shared view key authority
    When the authority splits the key 3-of-3 with inner policies "2-of-5, 2-of-5, 2-of-5"
    And each entity returns "1, 2, 2" sub-shares
    Then reconstruction fails

  Scenario: One entity returns no sub-shares
    Given a global shared view key authority
    When the authority splits the key 3-of-3 with inner policies "2-of-5, 2-of-5, 2-of-5"
    And each entity returns "0, 2, 2" sub-shares
    Then reconstruction fails

  Scenario: Mixed inner policies all meet their thresholds
    Given a global shared view key authority
    When the authority splits the key 3-of-3 with inner policies "2-of-5, 1-of-3, 2-of-5"
    And each entity returns "2, 1, 2" sub-shares
    Then the key is reconstructed

  Scenario: Outer 2-of-3 tolerates one missing entity
    Given a global shared view key authority
    When the authority splits the key 2-of-3 with inner policies "2-of-5, 2-of-5, 2-of-5"
    And each entity returns "2, 2, 0" sub-shares
    Then the key is reconstructed
