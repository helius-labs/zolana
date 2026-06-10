Feature: Blinding derivation

  Scenario: Per-output blindings are deterministic and position-dependent
    Then output blindings are deterministic and differ by position

  Scenario: A blinding drops the top byte to fit the field
    Then a blinding equals the sha256-be digest tail
