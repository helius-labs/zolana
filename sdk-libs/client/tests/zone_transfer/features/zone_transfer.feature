Feature: Zone-transfer proving (zone_transact)

  A zone transfer is a state transition over zone-owned UTXOs bound to a shared
  zone_program_id on the ed25519 (Solana-only) rail: vanilla Groth16, with the
  input and output owner pk_field chains in the public-input preimage. Each
  scenario builds a zone-owned witness (one real input + dummy padding,
  zero-value so it balances; zone outputs as dummies) and verifies against the committed
  transfer_zone_<shape> verifying key. Supported shapes: 1x1, 1x2, 2x2, 2x3,
  3x3, 4x3, 4x4, 5x3, 5x4, 1x8.

  Scenario Outline: All supported shapes prove and verify on the eddsa rail
    Given a <n_in>x<n_out> eddsa zone transfer
    Then the zone-transfer proof verifies

    Examples:
      | n_in | n_out |
      | 1    | 1     |
      | 1    | 2     |
      | 2    | 2     |
      | 2    | 3     |
      | 3    | 3     |
      | 4    | 3     |
      | 4    | 4     |
      | 5    | 3     |
      | 5    | 4     |
      | 1    | 8     |

  Scenario: Multi-input consolidation into a real recipient (eddsa rail)
    Given a 3x3 eddsa zone transfer consolidating 2 real inputs
    Then the zone-transfer proof verifies
