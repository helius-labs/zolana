import VerifiableEncryption.Curve.CompletenessCombFirstNative
import VerifiableEncryption.Curve.CombChain
import VerifiableEncryption.Field.CompletenessChainSlope
import VerifiableEncryption.Field.CompletenessLazy

/-! Bounded arithmetic witnesses for the first fixed-base chain step.
All layout, certificate and value identities are proved on abstract elements
before the outer point construction substitutes its balanced slope. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem combFirstSlope_layout (L X WX WY FY : ElemVal 8) :
    limbLists [⟨8, L⟩, ⟨8, linElem [(1, WX), (-1, X)]⟩, ⟨8, WY⟩, ⟨8, FY⟩] =
      chainCheckInputs (combFirstSlopeInput L.limbs
        (combFirstDifference WX.limbs X.limbs) WY.limbs FY.limbs) := by
  simp only [limbLists, List.map_cons, List.map_nil]
  rw [vec8_toList L.limbs, vec8_toList (linElem [(1, WX), (-1, X)]).limbs,
    vec8_toList WY.limbs, vec8_toList FY.limbs]
  simp only [chainCheckInputs, combFirstSlopeInput, combFirstDifference_get,
    linDiff_limb, List.Vector.get_cons_zero, List.Vector.get_cons_succ,
    Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod]
  rfl

theorem combLazy_native (L X WX : ElemVal 8) :
    vec3 L X WX = chainCompositionLazyInput L.limbs X.limbs WX.limbs := rfl

theorem combFirstSlope_match (L X WX WY FY : ElemVal 8)
    (hL : L.bnd = balC) (hX : X.bnd = reducedC) (hWX : WX.bnd = reducedC)
    (hWY : WY.bnd = packC) (hFY : FY.bnd = packC) :
    ElemsMatch [⟨8, L⟩, ⟨8, linElem [(1, WX), (-1, X)]⟩, ⟨8, WY⟩, ⟨8, FY⟩]
      cert_hb838cae4.elems := by
  apply elemsMatch_of
  show [L.bnd, (linElem [(1, WX), (-1, X)]).bnd, WY.bnd, FY.bnd] = _
  rw [linElem_bnd]
  simp only [List.map]
  rw [hL, hX, hWX, hWY, hFY]
  rfl

theorem combFirstSlope_expr (L X WX WY FY : ElemVal 8) :
    cert_hb838cae4.exprValue (values
      [⟨8, L⟩, ⟨8, linElem [(1, WX), (-1, X)]⟩, ⟨8, WY⟩, ⟨8, FY⟩]) =
      L.value * (WX.value - X.value) - WY.value + FY.value := by
  simp [PolyShape.exprValue, values, cert_hb838cae4, linElem_value]
  ring

theorem combFirstSlope_complete (hr : RangeComplete) (L X WX WY FY : ElemVal 8)
    (hL : L.bnd = balC) (hX : X.bnd = reducedC) (hWX : WX.bnd = reducedC)
    (hWY : WY.bnd = packC) (hFY : FY.bnd = packC)
    (hz : L.value * (WX.value - X.value) - WY.value + FY.value ≡ 0 [ZMOD p]) :
    CheckPolynomial_32_hb838cae4 (combFirstSlopeInput L.limbs
      (combFirstDifference WX.limbs X.limbs) WY.limbs FY.limbs) := by
  apply firstSlope_complete _ (combFirstSlope_match L X WX WY FY hL hX hWX hWY hFY)
    _ (combFirstSlope_layout L X WX WY FY) hr
  rw [combFirstSlope_expr, show (cert_hb838cae4.m : ℤ) = p from rfl]
  exact hz

theorem combFirstLazy_match (L X WX : ElemVal 8)
    (hL : L.bnd = balC) (hX : X.bnd = reducedC) (hWX : WX.bnd = reducedC) :
    ElemsMatch [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩] lazy_h4ef94fb8.elems :=
  elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hL, hX, hWX]; rfl)

theorem combFirstLazy_expr (L X WX : ElemVal 8) :
    lazy_h4ef94fb8.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
      L.value * L.value - X.value - WX.value := by
  simp [PolyShape.exprValue, values, lazy_h4ef94fb8]
  ring

theorem combFirstLazy_complete (L X WX : ElemVal 8)
    (hL : L.bnd = balC) (hX : X.bnd = reducedC) (hWX : WX.bnd = reducedC) :
    ∃ NX : ElemVal 8, NX.bnd = lazyOut lazy_h4ef94fb8 ∧
      NX.value ≡ L.value * L.value - X.value - WX.value [ZMOD p] ∧
      ∀ k : List.Vector F 8 → Prop, k NX.limbs →
        Lazy_24_h4ef94fb8 (chainCompositionLazyInput L.limbs X.limbs WX.limbs) k := by
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hactual, hv⟩ := lazyFirst_complete _
    (combFirstLazy_match L X WX hL hX hWX) (vec3 L X WX) (vec3_inputs L X WX)
  rw [combFirstLazy_expr, show (lazy_h4ef94fb8.m : ℤ) = p from rfl] at hv
  exact ⟨NX, lazy_bnd hlo hhi hvlo hvhi, hv, by
    simpa only [combLazy_native] using hactual⟩

theorem combFirstSlope_zero (L X WX WY FY : ElemVal 8) (l : Fp)
    (hL : (L.value : Fp) = l)
    (hl : l * ((WX.value : Fp) - (X.value : Fp)) = (WY.value : Fp) - (FY.value : Fp)) :
    L.value * (WX.value - X.value) - WY.value + FY.value ≡ 0 [ZMOD p] := by
  rw [modEq_p_iff]
  push_cast
  rw [hL]
  linear_combination hl

theorem combFirst_slope_math (X WX WY FY : ElemVal 8)
    (hA : OnCurve (X.value : Fp) (FY.value : Fp))
    (hW : OnCurve (WX.value : Fp) (WY.value : Fp))
    (hne : mkPoint hA ≠ mkPoint hW ∧ mkPoint hA ≠ -mkPoint hW) :
    ∃ l : Fp,
      (slopeElem l).value * (WX.value - X.value) - WY.value + FY.value ≡ 0 [ZMOD p] ∧
      ∀ NX : ElemVal 8,
        NX.value ≡ (slopeElem l).value * (slopeElem l).value - X.value - WX.value [ZMOD p] →
        FirstRel X.value WX.value WY.value FY.value (slopeElem l).value NX.value ∧
        (∃ hN : OnCurve (NX.value : Fp)
          (((slopeElem l).value * (WX.value - NX.value) - WY.value : ℤ) : Fp),
          mkPoint hN = mkPoint hA + mkPoint hW) := by
  have hx : (X.value : Fp) ≠ (WX.value : Fp) := (x_ne_iff hA hW).mpr hne
  let l : Fp := ((WY.value : Fp) - (FY.value : Fp)) / ((WX.value : Fp) - (X.value : Fp))
  have hl : l * ((WX.value : Fp) - (X.value : Fp)) = (WY.value : Fp) - (FY.value : Fp) :=
    div_mul_cancel₀ _ (sub_ne_zero.mpr hx.symm)
  have hz := combFirstSlope_zero (slopeElem l) X WX WY FY l (slopeElem_cast l) hl
  refine ⟨l, hz, ?_⟩
  intro NX hn
  have rel : FirstRel X.value WX.value WY.value FY.value (slopeElem l).value NX.value :=
    ⟨hz, hn⟩
  exact ⟨rel, chain_first_group hA hW hne rel⟩

end ZolanaVE.P256.Completeness
