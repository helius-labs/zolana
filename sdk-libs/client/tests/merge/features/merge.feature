Feature: Merge proving at shape (8,1)
  Each scenario consolidates N P256-owned SOL inputs (1..8) sharing one owner into
  a single merged output; the remaining 8-N input slots are dummies. Every shape
  proves on merge_8_1 (Groth16 with a BSB22 commitment over the P256 owner
  witness) and verifies against the committed merge verifying key.

  Scenario Outline: Merge <n> real inputs with <dummies> dummy slots
    Given <n> P256 SOL inputs to merge
    Then the merge proof verifies

    Examples:
      | n | dummies |
      | 1 | 7       |
      | 2 | 6       |
      | 3 | 5       |
      | 4 | 4       |
      | 5 | 3       |
      | 6 | 2       |
      | 7 | 1       |
      | 8 | 0       |

  Scenario Outline: Merge <n> Solana-owned inputs with <dummies> dummy slots
    Given <n> Solana SOL inputs to merge
    Then the merge proof verifies

    Examples:
      | n | dummies |
      | 1 | 7       |
      | 4 | 4       |
      | 8 | 0       |
