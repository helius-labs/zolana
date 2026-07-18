Feature: Transaction proving on the eddsa (Solana-only) rail at shape (2,3)
  Every input is Solana-owned, so each scenario proves on transfer_2_3 (vanilla
  Groth16, no commitment). Coverage mirrors p256_transaction.feature one-to-one:
  the SOL/SPL/mixed-asset, public-amount, change, and dummy-slot combinations are
  identical; only input ownership differs.

  # SOL only
  Scenario: SOL send with change and one recipient
    Given a Solana SOL input worth 100
    When the sender sends 60 SOL to a fresh recipient
    Then the proof verifies

  Scenario: SOL consolidate two inputs into change and one recipient
    Given a Solana SOL input worth 100
    Given a Solana SOL input worth 50
    When the sender sends 60 SOL to a fresh recipient
    Then the proof verifies

  Scenario: SOL exact send with no change
    Given a Solana SOL input worth 100
    When the sender sends 100 SOL to a fresh recipient
    Then the proof verifies

  Scenario: SOL single input with no recipient
    Given a Solana SOL input worth 100
    Then the proof verifies

  Scenario: SOL consolidate two inputs with no recipient
    Given a Solana SOL input worth 100
    Given a Solana SOL input worth 50
    Then the proof verifies

  Scenario: SOL withdrawal returns change to the owner
    Given a Solana SOL input worth 100
    When the sender withdraws 30 SOL to an external account
    Then the proof verifies

  Scenario: SOL withdrawal with an exact send and no change
    Given a Solana SOL input worth 100
    When the sender sends 70 SOL to a fresh recipient
    When the sender withdraws 30 SOL to an external account
    Then the proof verifies

  Scenario: SOL withdrawal combined with a send and change
    Given a Solana SOL input worth 100
    When the sender sends 40 SOL to a fresh recipient
    When the sender withdraws 30 SOL to an external account
    Then the proof verifies

  Scenario: SOL withdrawal of the full input leaves every output a dummy
    Given a Solana SOL input worth 100
    When the sender withdraws 100 SOL to an external account
    Then the proof verifies

  Scenario: SOL two-input withdrawal with change
    Given a Solana SOL input worth 100
    Given a Solana SOL input worth 50
    When the sender withdraws 30 SOL to an external account
    Then the proof verifies

  # SPL only
  Scenario: SPL send with change and one recipient
    Given a Solana SPL input worth 100
    When the sender sends 60 SPL to a fresh recipient
    Then the proof verifies

  Scenario: SPL exact send with no change
    Given a Solana SPL input worth 100
    When the sender sends 100 SPL to a fresh recipient
    Then the proof verifies

  Scenario: SPL consolidate two inputs to change
    Given a Solana SPL input worth 100
    Given a Solana SPL input worth 50
    Then the proof verifies

  Scenario: SPL withdrawal with change pins the public asset
    Given a Solana SPL input worth 100
    When the sender withdraws 30 SPL to an external account
    Then the proof verifies

  Scenario: SPL withdrawal of the full input leaves every output a dummy
    Given a Solana SPL input worth 100
    When the sender withdraws 100 SPL to an external account
    Then the proof verifies

  Scenario: SPL withdrawal combined with a send
    Given a Solana SPL input worth 100
    When the sender sends 40 SPL to a fresh recipient
    When the sender withdraws 30 SPL to an external account
    Then the proof verifies

  # SOL + SPL
  Scenario: Mixed SOL and SPL with both change slots and a recipient
    Given a Solana SOL input worth 100
    Given a Solana SPL input worth 100
    When the sender sends 60 SPL to a fresh recipient
    Then the proof verifies

  Scenario: Mixed SOL and SPL with both change slots and no recipient
    Given a Solana SOL input worth 100
    Given a Solana SPL input worth 100
    Then the proof verifies

  Scenario: Mixed withdraw all SOL keeping SPL change and an SPL recipient
    Given a Solana SOL input worth 100
    Given a Solana SPL input worth 100
    When the sender sends 60 SPL to a fresh recipient
    When the sender withdraws 100 SOL to an external account
    Then the proof verifies

  Scenario: Mixed withdraw all SPL keeping SOL change and a SOL recipient
    Given a Solana SOL input worth 100
    Given a Solana SPL input worth 100
    When the sender sends 60 SOL to a fresh recipient
    When the sender withdraws 100 SPL to an external account
    Then the proof verifies

  # Builder config
  Scenario: SOL send with the shape declared explicitly
    Given a Solana SOL input worth 100
    Given the (2,3) shape is declared
    When the sender sends 60 SOL to a fresh recipient
    Then the proof verifies

  # A declared shape wider than the real output set forces true output padding:
  # two change slots plus one dummy slot whose owner tag comes from
  # `dummy_view_tag`. With no recipient the dummy tag rail falls back to the
  # sender's rail (ed25519 here), so this exercises the ed25519 dummy tag through a
  # real proof; the p256 feature's counterpart exercises the P256 dummy tag. The
  # proof must still verify, confirming the padded dummy tag does not perturb the
  # witness or public inputs.
  Scenario: SOL change-only with the shape declared pads a dummy output slot
    Given a Solana SOL input worth 100
    Given the (2,3) shape is declared
    Then the proof verifies
