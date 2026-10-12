import VerifiableEncryption.Curve.CompletenessLadderChords
import VerifiableEncryption.Curve.CompletenessLadderRepair
import VerifiableEncryption.Curve.Slots

/-! Construct all three mathematical slopes of a quadruple-and-add step.
The primitive ladder prefix theorems discharge the local first-chord and
output-finiteness conditions. Native hint values, range pieces and arithmetic
checks are separate constructions; no gadget-success premise occurs here. -/

namespace ZolanaVE.P256.Completeness

theorem quad_add_slopes_exist {xA yA xT yT : Fp}
    (hA : OnCurve xA yA) (hT : OnCurve xT yT)
    (hfirst : 2 • mkPoint hA ≠ mkPoint hT ∧ 2 • mkPoint hA ≠ -mkPoint hT)
    (hout : 4 • mkPoint hA + mkPoint hT ≠ 0) :
    ∃ l dX dY m v iX oX oY : Fp,
      QuadAddCons xA yA xT yT l dX dY m v iX oX oY ∧
      LastSlope xT yT dX dY m ∧
      (∃ hO : OnCurve oX oY, mkPoint hO = 4 • mkPoint hA + mkPoint hT) := by
  let l : Fp := (3 * xA ^ 2 - 3) / (2 * yA)
  have htan : 2 * l * yA = 3 * xA ^ 2 - 3 := by
    calc
      _ = l * (2 * yA) := by ring
      _ = _ := div_mul_cancel₀ _ (mul_ne_zero two_ne_zero_Fp (y_ne_zero_of_onCurve hA))
  let dX : Fp := l ^ 2 - 2 * xA
  let dY : Fp := l * (xA - dX) - yA
  obtain ⟨hD, pD⟩ := tangent_double hA htan (show dX = _ from rfl) (show dY = _ from rfl)
  have hpair : mkPoint hD ≠ mkPoint hT ∧ mkPoint hD ≠ -mkPoint hT := by
    rw [← pD]
    exact hfirst
  have hx : dX ≠ xT := (x_ne_iff hD hT).mpr hpair
  let m : Fp := (yT - dY) / (xT - dX)
  have hm : m * (xT - dX) = yT - dY := div_mul_cancel₀ _ (sub_ne_zero.mpr hx.symm)
  let iX : Fp := m ^ 2 - dX - xT
  let iY : Fp := m * (dX - iX) - dY
  obtain ⟨hI, pI⟩ := slope_add hD hT hx hm (show iX = _ from rfl) (show iY = _ from rfl)
  have h2D : 2 • mkPoint hD = 4 • mkPoint hA := by
    rw [← pD, smul_smul]
    norm_num
  have hfinite : (2 : ℤ) • mkPoint hD + mkPoint hT ≠ 0 := by
    rw [ofNat_zsmul, h2D]
    exact hout
  have hsecond := second_addition_noncollision (mkPoint_ne_zero hT) hfinite
  have hpairI : mkPoint hI ≠ mkPoint hD ∧ mkPoint hI ≠ -mkPoint hD := by
    rw [← pI]
    exact hsecond
  have hxI : iX ≠ dX := (x_ne_iff hI hD).mpr hpairI
  let v : Fp := 2 * dY / (iX - dX)
  have hv : v * (iX - dX) = 2 * dY := div_mul_cancel₀ _ (sub_ne_zero.mpr hxI)
  let oX : Fp := v * (v + 2 * m) + xT
  let oY : Fp := (m + v) * (oX - dX) + m * (xT - dX) - yT
  have cons : QuadAddCons xA yA xT yT l dX dY m v iX oX oY := by
    refine ⟨htan, rfl, rfl, ?_, rfl, ?_, rfl, rfl⟩
    · linear_combination hm
    · linear_combination hv + 2 * hm
  have hlast : LastSlope xT yT dX dY m := lastSlope_of_chord hD hT hx cons.chord
  exact ⟨l, dX, dY, m, v, iX, oX, oY, cons, hlast, quad_add_correct hA hT cons (Or.inl hx)⟩

end ZolanaVE.P256.Completeness
