import VerifiableEncryption.Curve.CompletenessCombSecondNative
import VerifiableEncryption.Curve.CompletenessCombFirstArithmetic
import VerifiableEncryption.Curve.CompletenessCombMath
import VerifiableEncryption.Curve.CompletenessCombLayout
import VerifiableEncryption.Field.CompletenessGeneratedLazy_13

/-! Construct the second comb step's actual six-element slope assertion and
bounded Lazy output. Layout and matching proofs use abstract elements. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem combSecondSlope_match (L X L0 PWX PWY WX WY : ElemVal 8)
    (hL : L.bnd = balC) (hX : X.bnd = lazyOut lazy_h4ef94fb8) (hL0 : L0.bnd = balC)
    (hPWX : PWX.bnd = reducedC) (hPWY : PWY.bnd = packC)
    (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC) :
    ElemsMatch [⟨8, L⟩, ⟨8, linElem [(1, WX), (-1, X)]⟩, ⟨8, L0⟩,
      ⟨8, linElem [(1, PWX), (-1, X)]⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
      cert_hd6f972c2.elems := by
  apply elemsMatch_of
  show [L.bnd, (linElem [(1, WX), (-1, X)]).bnd, L0.bnd,
    (linElem [(1, PWX), (-1, X)]).bnd, WY.bnd, PWY.bnd] = _
  rw [linElem_bnd, linElem_bnd]
  simp only [List.map]
  rw [hL, hX, hL0, hPWX, hPWY, hWX, hWY]
  rfl

theorem combSecondSlope_complete (hr : RangeComplete) (L X L0 PWX PWY WX WY : ElemVal 8)
    (hL : L.bnd = balC) (hX : X.bnd = lazyOut lazy_h4ef94fb8) (hL0 : L0.bnd = balC)
    (hPWX : PWX.bnd = reducedC) (hPWY : PWY.bnd = packC)
    (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    (hz : L.value * (WX.value - X.value) + L0.value * (PWX.value - X.value) -
      WY.value - PWY.value ≡ 0 [ZMOD p]) :
    CheckPolynomial_48_hd6f972c2 (chainCompositionSlopeInput L.limbs X.limbs L0.limbs
      PWX.limbs WX.limbs WY.limbs PWY.limbs) := by
  exact secondChainSlope_complete _
    (combSecondSlope_match L X L0 PWX PWY WX WY hL hX hL0 hPWX hPWY hWX hWY) _
    (combSecondSlope_layout L X L0 PWX PWY WX WY) hr
    (combChain_slope_expr cert_hd6f972c2 rfl rfl L X L0 PWX WY PWY WX hz)

theorem combSecondLazy_match (L X WX : ElemVal 8)
    (hL : L.bnd = balC) (hX : X.bnd = lazyOut lazy_h4ef94fb8) (hWX : WX.bnd = reducedC) :
    ElemsMatch [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩] lazy_h33616364.elems :=
  elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hL, hX, hWX]; rfl)

theorem combSecondLazy_expr (L X WX : ElemVal 8) :
    lazy_h33616364.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
      L.value * L.value - X.value - WX.value := by
  simp [PolyShape.exprValue, values, lazy_h33616364]
  ring

theorem combSecondLazy_complete (L X WX : ElemVal 8)
    (hL : L.bnd = balC) (hX : X.bnd = lazyOut lazy_h4ef94fb8) (hWX : WX.bnd = reducedC) :
    ∃ NX : ElemVal 8, NX.bnd = lazyOut lazy_h33616364 ∧
      NX.value ≡ L.value * L.value - X.value - WX.value [ZMOD p] ∧
      ∀ k : List.Vector F 8 → Prop, k NX.limbs →
        Lazy_24_h33616364 (chainCompositionLazyInput L.limbs X.limbs WX.limbs) k := by
  obtain ⟨NX, hNX, hv, ha⟩ := Lazy_24_h33616364_complete _
    (combSecondLazy_match L X WX hL hX hWX) (vec3 L X WX) (vec3_inputs L X WX)
  rw [combSecondLazy_expr, show (lazy_h33616364.m : ℤ) = p from rfl] at hv
  exact ⟨NX, hNX, hv, by simpa only [combLazy_native] using ha⟩

end ZolanaVE.P256.Completeness
