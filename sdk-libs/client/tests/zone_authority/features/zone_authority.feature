Feature: Zone-authority proving (zone_authority_transact)

  The zone authority controls its zone-owned UTXOs, so owners do not sign: there is
  no in-circuit signature and input owner pk_fields stay private. Every scenario
  builds a zone-owned state transition, proves it on the transfer-zone-authority
  circuit (vanilla Groth16, Solana-only rail), and verifies against the committed
  transfer_zone_authority_<shape> verifying key. Supported shapes: 1x1, 2x2, 3x3, 4x4.

  Scenario Outline: All supported shapes prove and verify
    Given a <n>x<n> zone-authority transfer
    Then the zone-authority proof verifies

    Examples:
      | n |
      | 1 |
      | 2 |
      | 3 |
      | 4 |

  Scenario: Multi-input consolidation with dummy padding
    Given a zone-authority consolidation of 2 real inputs at shape 3x3
    Then the zone-authority proof verifies

  Scenario: P256-owned input (pubkey-agnostic, no signature)
    Given a 1x1 zone-authority transfer with a P256-owned input
    Then the zone-authority proof verifies

  Scenario: Mixed ed25519 and P256 owned inputs
    Given a 2x2 zone-authority transfer with mixed owners
    Then the zone-authority proof verifies

  Scenario: Built through the PreparedZoneAuthority boundary
    Given a 2x2 zone-authority transfer built via the prepared boundary
    Then the zone-authority proof verifies
