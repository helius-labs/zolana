Feature: Transaction proving at shape (2,3)
  Build a shielded transfer with the Transaction builder, resolve state and
  nullifier proofs via the indexer, prove it on the prover server, and verify
  the proof against the committed verifying key for the selected rail. The rail
  follows input ownership: any P256-owned input proves on transfer_2_3, all
  Solana-owned inputs prove on transfer_2_3.

  Scenario: P256 SOL transfer with one real input padded to a dummy slot
    Given a P256 SOL input worth 100
    When the sender sends 60 SOL to a fresh recipient
    Then the proof verifies

  Scenario: P256 SOL transfer consolidating two inputs into change and one recipient
    Given a P256 SOL input worth 100
    Given a P256 SOL input worth 50
    When the sender sends 60 SOL to a fresh recipient
    Then the proof verifies

  Scenario: P256 SOL transfer with an exact spend and no change
    Given a P256 SOL input worth 100
    When the sender sends 100 SOL to a fresh recipient
    Then the proof verifies

  Scenario: P256 SOL consolidation with no recipients
    Given a P256 SOL input worth 100
    Given a P256 SOL input worth 50
    Then the proof verifies

  Scenario: P256 SOL withdrawal returns change to the owner
    Given a P256 SOL input worth 100
    When the sender withdraws 30 SOL to an external account
    Then the proof verifies

  Scenario: P256 SOL transfer combined with a withdrawal
    Given a P256 SOL input worth 100
    When the sender sends 60 SOL to a fresh recipient
    When the sender withdraws 30 SOL to an external account
    Then the proof verifies

  Scenario: P256 SPL transfer
    Given a P256 SPL input worth 100
    When the sender sends 60 SPL to a fresh recipient
    Then the proof verifies

  Scenario: P256 SPL withdrawal pins the public asset
    Given a P256 SPL input worth 100
    When the sender withdraws 30 SPL to an external account
    Then the proof verifies

  Scenario: P256 mixed SOL and SPL filling all three output slots
    Given a P256 SPL input worth 100
    Given a P256 SOL input worth 50
    When the sender sends 60 SPL to a fresh recipient
    Then the proof verifies

  Scenario: P256 rail with one P256-owned and one Solana-owned input
    Given a P256 SOL input worth 100
    Given a Solana SOL input worth 50
    When the sender sends 60 SOL to a fresh recipient
    Then the proof verifies

  Scenario: P256 SOL transfer with the shape declared explicitly
    Given a P256 SOL input worth 100
    Given the (2,3) shape is declared
    When the sender sends 60 SOL to a fresh recipient
    Then the proof verifies

  Scenario: Solana-only SOL transfer on the eddsa rail
    Given a Solana SOL input worth 100
    When the sender sends 60 SOL to a fresh recipient
    Then the proof verifies

  Scenario: Solana-only SOL withdrawal on the eddsa rail
    Given a Solana SOL input worth 100
    When the sender withdraws 30 SOL to an external account
    Then the proof verifies
