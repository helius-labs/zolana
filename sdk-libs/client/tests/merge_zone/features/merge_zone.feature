Feature: Merge-zone proving at shape (8,1)
  Each scenario consolidates N zone-owned SOL inputs (1..8) sharing one owner and
  one zone program into a single zone-owned merged output; the remaining 8-N input
  slots are dummies. Every shape proves on merge_zone_8_1 (Groth16 with a BSB22
  commitment over the owner witness) and verifies against the committed merge-zone
  verifying key. The only delta vs the default merge is that every input and the
  merged output are bound to a shared zone_program_id.

  Scenario Outline: Merge-zone <n> P256-owned inputs with <dummies> dummy slots
    Given <n> P256 SOL inputs to merge-zone
    Then the merge-zone proof verifies

    Examples:
      | n | dummies |
      | 1 | 7       |
      | 4 | 4       |
      | 8 | 0       |

  Scenario Outline: Merge-zone <n> Solana-owned inputs with <dummies> dummy slots
    Given <n> Solana SOL inputs to merge-zone
    Then the merge-zone proof verifies

    Examples:
      | n | dummies |
      | 1 | 7       |
      | 4 | 4       |
      | 8 | 0       |
