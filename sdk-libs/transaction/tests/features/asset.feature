Feature: Asset registry

  Scenario: SOL always resolves to the default address
    Then the asset registry resolves SOL to the default address

  Scenario: A registered SPL mint resolves by id and by mint
    Then a registered SPL mint resolves both ways

  Scenario: An unknown asset id is rejected
    Then resolving an unknown asset id fails

  Scenario: An unknown mint is rejected
    Then resolving an unknown mint fails

  Scenario: SOL stays canonical even when overridden
    Then SOL stays canonical when a bogus SOL entry is supplied
