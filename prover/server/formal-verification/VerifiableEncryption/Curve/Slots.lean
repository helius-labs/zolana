import VerifiableEncryption.Curve.Ladder

/-!
x-coordinate collisions and the ladder's slot points.
-/

namespace ZolanaVE.P256

theorem x_ne_iff {x1 y1 x2 y2 : Fp} (h1 : OnCurve x1 y1) (h2 : OnCurve x2 y2) :
    x1 ≠ x2 ↔ (mkPoint h1 ≠ mkPoint h2 ∧ mkPoint h1 ≠ -mkPoint h2) := by
  constructor
  · intro hx
    constructor
    · intro he; exact hx (mkPoint_inj.mp he).1
    · intro he
      obtain ⟨hn, hne⟩ := neg_mkPoint h2
      rw [hne] at he
      exact hx (mkPoint_inj.mp he).1
  · rintro ⟨h1', h2'⟩ hx
    rcases eq_or_eq_neg_of_x_eq h1 h2 hx with he | he
    · exact h1' he
    · exact h2' he

theorem three_ne {A B : P} (h1 : A ≠ B) (h2 : A ≠ -B) : 3 • A ≠ 3 • B ∧ 3 • A ≠ -(3 • B) := by
  constructor
  · intro he
    apply h1
    have : 3 • (A - B) = 0 := by rw [nsmul_sub, he, sub_self]
    exact sub_eq_zero.mp (Ladder.three_smul_eq_zero this)
  · intro he
    apply h2
    have : 3 • (A + B) = 0 := by rw [nsmul_add, he, neg_add_cancel]
    exact eq_neg_of_add_eq_zero_left (Ladder.three_smul_eq_zero this)

theorem neg_ne {A B : P} (h1 : A ≠ B) (h2 : A ≠ -B) : A ≠ -(-B) ∧ A ≠ -B := by
  rw [neg_neg]; exact ⟨h1, h2⟩

/-- The chord addition of two on-curve points with distinct x, from the
integer constraints of `curve.add`. -/
theorem chord_point {xp yp xq yq xs ys : ℤ} (hP : OnCurve (xp : Fp) (yp : Fp))
    (hQ : OnCurve (xq : Fp) (yq : Fp)) (hx : (xp : Fp) ≠ (xq : Fp))
    (h1 : (xs + xp + xq) * (xq - xp) ^ 2 - (yq - yp) ^ 2 ≡ 0 [ZMOD p])
    (h2 : (yq - yp) * (xs - xp) + (ys + yp) * (xq - xp) ≡ 0 [ZMOD p]) :
    ∃ hS : OnCurve (xs : Fp) (ys : Fp), mkPoint hS = mkPoint hP + mkPoint hQ := by
  obtain ⟨hS, he⟩ := chord_add_int hP hQ hx h1 h2
  exact ⟨hS, he.symm⟩

end ZolanaVE.P256
