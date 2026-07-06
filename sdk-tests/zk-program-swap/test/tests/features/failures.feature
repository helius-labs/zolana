Feature: swap program guards reject expired and invalid orders

  Scenario: fill is rejected after the order expiry
    Then a fill after the order expiry is rejected as expired

  Scenario: cancel is rejected before the order expiry
    Then a cancel before the order expiry is rejected as not yet expired

  Scenario: fill is rejected when the order proof does not verify
    Then a fill carrying an invalid order proof is rejected
