Feature: Transaction proving with mixed eddsa and P256 inputs at shape (2,3)
  Each scenario spends one Solana-owned and one P256-owned input. Any P256 input
  selects the P256 rail (transfer_p256_2_3), so these are the two-input cases the
  pure-rail features cannot express as a mix. The single-input value shapes are
  covered by eddsa_transaction.feature and p256_transaction.feature.

  Scenario: Consolidate a P256 and a Solana SOL input into change and a recipient
    Given a P256 SOL input worth 100
    Given a Solana SOL input worth 50
    When the sender sends 60 SOL to a fresh recipient
    Then the proof verifies

  Scenario: Consolidate a P256 and a Solana SOL input with no recipient
    Given a P256 SOL input worth 100
    Given a Solana SOL input worth 50
    Then the proof verifies

  Scenario: Withdraw from a P256 and a Solana SOL input with change
    Given a P256 SOL input worth 100
    Given a Solana SOL input worth 50
    When the sender withdraws 30 SOL to an external account
    Then the proof verifies

  Scenario: Consolidate a P256 and a Solana SPL input to change
    Given a P256 SPL input worth 100
    Given a Solana SPL input worth 50
    Then the proof verifies

  Scenario: Mixed-owner SOL and SPL with both change slots and a recipient
    Given a P256 SOL input worth 100
    Given a Solana SPL input worth 100
    When the sender sends 60 SPL to a fresh recipient
    Then the proof verifies

  Scenario: Mixed-owner SOL and SPL with both change slots and no recipient
    Given a P256 SOL input worth 100
    Given a Solana SPL input worth 100
    Then the proof verifies

  Scenario: Mixed-owner withdraw all SOL keeping SPL change and an SPL recipient
    Given a P256 SOL input worth 100
    Given a Solana SPL input worth 100
    When the sender sends 60 SPL to a fresh recipient
    When the sender withdraws 100 SOL to an external account
    Then the proof verifies

  Scenario: Mixed-owner withdraw all SPL keeping SOL change and a SOL recipient
    Given a P256 SOL input worth 100
    Given a Solana SPL input worth 100
    When the sender sends 60 SOL to a fresh recipient
    When the sender withdraws 100 SPL to an external account
    Then the proof verifies
