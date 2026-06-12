Feature: Asset registry

  Scenario: SOL always resolves to the default address
    Then the asset registry resolves SOL to the default address

  Scenario: A registered SPL mint resolves by id and by mint
    Then a registered SPL mint resolves both ways

  Scenario: An unknown asset id is rejected
    Then resolving an unknown asset id fails

  Scenario: An unknown mint is rejected
    Then resolving an unknown mint fails

  Scenario: The SOL asset id cannot be overridden
    Then a SOL entry is rejected as reserved

  Scenario: A duplicate asset id is rejected
    Then a duplicate asset id is rejected

  Scenario: A duplicate mint is rejected
    Then a duplicate mint is rejected
