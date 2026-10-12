import VerifiableEncryption.Curve.Native

/-!
Exact native-field obstruction for the ladder slope guard. This identifies
what a constructive run still has to exclude. It is not a proof that all
valid recipients satisfy these conditions, nor an actual rejected-key example.
-/

namespace ZolanaVE.P256.Completeness

variable [Fact (Nat.Prime Order)]

theorem slopeFactor_zero_iff (d : F) :
    slopeFactor d = 0 ↔ d = 0 ∨ d = (p : F) ∨ d = -(p : F) := by
  have factorization : slopeFactor d = (d * (d - (p : F))) * (d + (p : F)) := by
    unfold slopeFactor
    ring
  rw [factorization, mul_eq_zero, mul_eq_zero]
  simp only [sub_eq_zero, add_eq_zero_iff_eq_neg, or_assoc]

theorem slopeFactor_nonzero_iff (d : F) :
    slopeFactor d ≠ 0 ↔ d ≠ 0 ∧ d ≠ (p : F) ∧ d ≠ -(p : F) := by
  rw [ne_eq, slopeFactor_zero_iff]
  push_neg <;> rfl

/-- Six native residue exclusions, beyond inequality of emulated Fp slopes. -/
theorem nativeSlope_nonzero_iff (tangent half : F) :
    slopeFactor (tangent - half) * slopeFactor (tangent + half) ≠ 0 ↔
      (tangent - half ≠ 0 ∧ tangent - half ≠ (p : F) ∧ tangent - half ≠ -(p : F)) ∧
      (tangent + half ≠ 0 ∧ tangent + half ≠ (p : F) ∧ tangent + half ≠ -(p : F)) := by
  rw [mul_ne_zero_iff, slopeFactor_nonzero_iff, slopeFactor_nonzero_iff]

end ZolanaVE.P256.Completeness
