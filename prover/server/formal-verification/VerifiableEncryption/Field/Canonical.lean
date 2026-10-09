import VerifiableEncryption.Field.CheckPolynomial

/-!
`Field.AssertCanonical` (`emfield/canonical.go`): a reduced element is below
the modulus. Two strategies, chosen by the modulus shape: a limbwise
lexicographic comparison against `m - 1` (P-256 `p`), or a hinted gap to
`m - 1` checked with one carry between the two halves (P-256 `n`).
-/

namespace ZolanaVE.Field

structure CanonicalCheckParams where
  m : ℕ
  limbwise : Bool
  widths : List ℕ
  lo : List ℤ
  hi : List ℤ
deriving Inhabited, Repr

/-- The element is reduced: limbs `[0, 2^w - 1]` for the field widths. -/
def CanonicalCheckParams.sound (c : CanonicalCheckParams) : Bool :=
  c.widths.length == limbCount &&
  c.lo == List.replicate limbCount 0 &&
  c.hi == c.widths.map (fun w => (2 : ℤ) ^ w - 1)

end ZolanaVE.Field
