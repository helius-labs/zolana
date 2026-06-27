Feature: First time wallet sync

  Scenario: A fresh wallet restores utxos, counters, and contacts from chain history
    Given a shielded keypair "alice"
    And a shielded keypair "bob"
    And a shielded keypair "carol"
    And a recorded bootstrap transfer of 40 sol from "bob" to "alice"
    And a recorded transfer of 25 sol from "alice" to "carol" spending her latest utxo
    And a recorded shared transfer of 10 sol from "bob" to "alice" at index 0
    When a fresh wallet for "alice" is synced from the recorded transactions
    Then the wallet holds 3 utxos of which 1 is spent
    And the unspent sol balance is 25
    And the wallet tx count is 1 and request count is 0
    And the wallet knows sender "bob" with next index 1
    And the wallet knows recipient "carol" with next index 0
    And the wallet has 3 private transactions
    And an inbound private transfer of 40 sol from "bob" is recorded
    And an outbound private transfer of 25 sol to "carol" is recorded
    And an inbound private transfer of 10 sol from "bob" is recorded

  Scenario: A fresh wallet restores split outputs and payment request transfers
    Given a shielded keypair "alice"
    And a shielded keypair "bob"
    And a shielded keypair "carol"
    And a recorded bootstrap transfer of 40 sol from "bob" to "alice"
    And a recorded split of "alice"'s latest utxo into 4 parts
    And a recorded request transfer of 5 sol from "carol" to "alice" at request index 0
    When a fresh wallet for "alice" is synced from the recorded transactions
    Then the wallet holds 6 utxos of which 1 is spent
    And the unspent sol balance is 45
    And the wallet tx count is 1 and request count is 1
    And the wallet knows sender "carol" with next index 0
    And the wallet has 3 private transactions
    And an inbound private transfer of 40 sol from "bob" is recorded
    And a split of 40 sol is recorded
    And an inbound private transfer of 5 sol from "carol" is recorded
