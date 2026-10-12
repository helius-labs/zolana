import VerifiableEncryption.Curve.CompletenessCanonical
import VerifiableEncryption.Curve.CompletenessCoordinates

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field

theorem sameX_fp_iff (PX QX : ElemVal 8)
    (hPX : PX.bnd = reducedC) (hQX : QX.bnd = reducedC)
    (hcPX : limbNat PX.limbs < p) (hcQX : limbNat QX.limbs < p)
    (b : Bool) (hb : b = true ↔ limbNat PX.limbs = limbNat QX.limbs) :
    b = true ↔ (PX.value : Fp) = (QX.value : Fp) := by
  rw [hb, ← (reduced_vals hPX).2, ← (reduced_vals hQX).2,
    Int.cast_natCast, Int.cast_natCast, ZMod.natCast_eq_natCast_iff',
    Nat.mod_eq_of_lt hcPX, Nat.mod_eq_of_lt hcQX]

theorem affineSlope_given_flag {xp yp xq yq : Fp} (b : Bool)
    (hflag : b = true ↔ xp = xq) (hP : OnCurve xp yp) (hQ : OnCurve xq yq)
    (hne : mkPoint hP ≠ -mkPoint hQ) : ∃ l : Fp,
      (if b then (1 : Fp) else 0) * (xq - xp) = 0 ∧
      (if b then (1 : Fp) else 0) * (yq - yp) = 0 ∧
      l * (xq - xp) + 2 * l * (if b then 1 else 0) * yp -
        3 * (if b then 1 else 0) * xp ^ 2 + 3 * (if b then 1 else 0) - (yq - yp) = 0 := by
  cases b
  · have hx : xp ≠ xq := by intro he; have := hflag.mpr he; contradiction
    let l := (yq - yp) / (xq - xp)
    have hl : l * (xq - xp) = yq - yp := div_mul_cancel₀ _ (sub_ne_zero.mpr hx.symm)
    refine ⟨l, by simp, by simp, ?_⟩
    simp only [Bool.false_eq_true, if_false]
    linear_combination hl
  · have hx := hflag.mp rfl
    have he := (eq_or_eq_neg_of_x_eq hP hQ hx).resolve_right hne
    have hy := (mkPoint_inj.mp he).2
    let l := (3 * xp ^ 2 - 3) / (2 * yp)
    have hd : 2 * yp ≠ 0 := mul_ne_zero two_ne_zero_Fp (y_ne_zero_of_onCurve hP)
    have hl : 2 * l * yp = 3 * xp ^ 2 - 3 := by
      calc 2 * l * yp = l * (2 * yp) := by ring
           _ = 3 * xp ^ 2 - 3 := div_mul_cancel₀ _ hd
    refine ⟨l, by simp [hx], by simp [hy], ?_⟩
    simp only [if_true]
    rw [← hx, ← hy]
    linear_combination hl


end ZolanaVE.P256.Completeness
