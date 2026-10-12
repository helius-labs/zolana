import VerifiableEncryption.Curve.CompletenessQuadMath

/-! Mathematical witnesses for both extracted triple gadgets. Their return
slope denominator follows from the proven prime curve order; it does not
require a successful tangent or chord hint as an input assumption. -/

namespace ZolanaVE.P256.Completeness

theorem triple_slopes_exist {x y : Fp} (hP : OnCurve x y) :
    ∃ l dx r x3 y3 : Fp,
      2 * l * y = 3 * x ^ 2 - 3 ∧
      dx = l ^ 2 - 2 * x ∧ r * (x - dx) = 2 * y ∧
      x3 = (r - l) ^ 2 - x - dx ∧
      y3 = (r - l) * (x - x3) - y ∧
      (∃ hT : OnCurve x3 y3, mkPoint hT = 3 • mkPoint hP) := by
  let l : Fp := (3 * x ^ 2 - 3) / (2 * y)
  have hl : 2 * l * y = 3 * x ^ 2 - 3 := by
    calc
      _ = l * (2 * y) := by ring
      _ = _ := div_mul_cancel₀ _ (mul_ne_zero two_ne_zero_Fp (y_ne_zero_of_onCurve hP))
  let dx : Fp := l ^ 2 - 2 * x
  let dy : Fp := l * (x - dx) - y
  obtain ⟨hD, hpD⟩ := tangent_double hP hl (show dx = _ from rfl) (show dy = _ from rfl)
  have hpair : mkPoint hD ≠ mkPoint hP ∧ mkPoint hD ≠ -mkPoint hP := by
    rw [← hpD]
    constructor
    · intro he
      have hs := (scalar_faithful (mkPoint_ne_zero hP) 2 1).mp
        (by simpa only [ofNat_zsmul, one_zsmul] using he)
      exact (by decide +kernel : (2 : ScalarField) ≠ 1) hs
    · intro he
      have hs := (scalar_faithful (mkPoint_ne_zero hP) 2 (-1)).mp
        (by simpa only [ofNat_zsmul, neg_one_zsmul] using he)
      exact (by decide +kernel : (2 : ScalarField) ≠ -1) hs
  have hx : x ≠ dx := ((x_ne_iff hD hP).mpr hpair).symm
  let r : Fp := 2 * y / (x - dx)
  have hr : r * (x - dx) = 2 * y := div_mul_cancel₀ _ (sub_ne_zero.mpr hx)
  let x3 : Fp := (r - l) ^ 2 - x - dx
  let y3 : Fp := (r - l) * (x - x3) - y
  obtain ⟨hT, hpT⟩ := triple hP hl (show dx = _ from rfl) hr
    (show x3 = _ from rfl) (show y3 = _ from rfl)
  exact ⟨l, dx, r, x3, y3, hl, rfl, hr, rfl, rfl, hT, hpT.symm⟩

end ZolanaVE.P256.Completeness
