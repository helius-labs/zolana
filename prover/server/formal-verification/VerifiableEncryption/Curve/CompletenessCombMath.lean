import VerifiableEncryption.Curve.CompletenessCoordinates
import VerifiableEncryption.Curve.CombChain

/-! Uniform mathematics used by each literal fixed-base chain constructor.
This helper constructs the slope, not a satisfying-gadget premise. Actual
per-certificate checks and lazy outputs must be constructed independently. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem combChainSlope_zero (L X L0 PWX PWY WX WY : ElemVal 8) (l : Fp)
    (hL : (L.value : Fp) = l)
    (hl : l * ((WX.value : Fp) - (X.value : Fp)) = (WY.value : Fp) -
      ((L0.value * (PWX.value - X.value) - PWY.value : ℤ) : Fp)) :
    L.value * (WX.value - X.value) + L0.value * (PWX.value - X.value) -
      WY.value - PWY.value ≡ 0 [ZMOD p] := by
  rw [modEq_p_iff]
  push_cast
  rw [hL]
  push_cast at hl
  linear_combination hl

theorem combChain_slope_math (X L0 PWX PWY WX WY : ElemVal 8)
    (hA : OnCurve (X.value : Fp) ((L0.value * (PWX.value - X.value) - PWY.value : ℤ) : Fp))
    (hW : OnCurve (WX.value : Fp) (WY.value : Fp))
    (hne : mkPoint hA ≠ mkPoint hW ∧ mkPoint hA ≠ -mkPoint hW) :
    ∃ l : Fp,
      (slopeElem l).value * (WX.value - X.value) +
        L0.value * (PWX.value - X.value) - WY.value - PWY.value ≡ 0 [ZMOD p] ∧
      ∀ NX : ElemVal 8,
        NX.value ≡ (slopeElem l).value * (slopeElem l).value - X.value - WX.value [ZMOD p] →
        ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value (slopeElem l).value NX.value ∧
        (∃ hN : OnCurve (NX.value : Fp)
            (((slopeElem l).value * (WX.value - NX.value) - WY.value : ℤ) : Fp),
          mkPoint hN = mkPoint hA + mkPoint hW) := by
  have hx : (X.value : Fp) ≠ (WX.value : Fp) := (x_ne_iff hA hW).mpr hne
  let yA : Fp := ((L0.value * (PWX.value - X.value) - PWY.value : ℤ) : Fp)
  let l : Fp := ((WY.value : Fp) - yA) / ((WX.value : Fp) - (X.value : Fp))
  have hl : l * ((WX.value : Fp) - (X.value : Fp)) = (WY.value : Fp) - yA :=
    div_mul_cancel₀ _ (sub_ne_zero.mpr hx.symm)
  have hzero := combChainSlope_zero (slopeElem l) X L0 PWX PWY WX WY l (slopeElem_cast l) hl
  refine ⟨l, hzero, ?_⟩
  intro NX hnx
  have rel : ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value
      (slopeElem l).value NX.value := ⟨hzero, hnx⟩
  exact ⟨rel, chain_group hA hW hne rel⟩

theorem combChain_slope_expr (c : PlainCheckParams)
    (hterms : c.terms = [⟨1, [0, 1]⟩, ⟨1, [2, 3]⟩, ⟨-1, [4]⟩, ⟨-1, [5]⟩])
    (hm : c.m = p) (L X L0 PWX WY PWY WX : ElemVal 8)
    (hzero : L.value * (WX.value - X.value) +
      L0.value * (PWX.value - X.value) - WY.value - PWY.value ≡ 0 [ZMOD p]) :
    c.exprValue (values [⟨8, L⟩, ⟨8, linElem [(1, WX), (-1, X)]⟩,
      ⟨8, L0⟩, ⟨8, linElem [(1, PWX), (-1, X)]⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) ≡ 0 [ZMOD (c.m : ℤ)] := by
  have ee : c.exprValue (values [⟨8, L⟩, ⟨8, linElem [(1, WX), (-1, X)]⟩,
      ⟨8, L0⟩, ⟨8, linElem [(1, PWX), (-1, X)]⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
      L.value * (WX.value - X.value) + L0.value * (PWX.value - X.value) - WY.value - PWY.value := by
    simp [PolyShape.exprValue, values, hterms, linElem_value]
    ring
  rw [ee, hm]
  exact hzero

end ZolanaVE.P256.Completeness
