import VerifiableEncryption.Curve.CompletenessQuadTransitionArithmetic
import VerifiableEncryption.Curve.CompletenessGeneratedQuadComposition

/-! Constructive completeness of the actual transition quadruple-and-add step.
Validation is recorded separately. -/

namespace ZolanaVE.P256.Completeness
open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem quadAdd_h8a920ea3_complete (hr : RangeComplete) (AX AY SX SY : ElemVal 8)
    (hAX : AX.bnd = lazyOut lazy_h9c68f146) (hAY : AY.bnd = lazyOut lazy_h57fc266d)
    (hSX : SX.bnd = reducedC) (hSY : SY.bnd = unpackC) (hs : F)
    (hA : OnCurve (AX.value : Fp) (AY.value : Fp))
    (hT : OnCurve (SX.value : Fp) (SY.value : Fp))
    (hfirst : 2 • mkPoint hA ≠ mkPoint hT ∧ 2 • mkPoint hA ≠ -mkPoint hT)
    (hout : 4 • mkPoint hA + mkPoint hT ≠ 0) :
    ∃ OX OY : ElemVal 8, OX.bnd = lazyOut lazy_h9c68f146 ∧ OY.bnd = lazyOut lazy_hee995b41 ∧
      (∃ hO : OnCurve (OX.value : Fp) (OY.value : Fp),
        mkPoint hO = 4 • mkPoint hA + mkPoint hT) ∧
      ∀ k : List.Vector (List.Vector F 8) 2 → Prop,
        k (OX.limbs ::ᵥ OY.limbs ::ᵥ List.Vector.nil) →
        QuadrupleAndAddLazy_8_8_8_8_h8a920ea3 AX.limbs AY.limbs SX.limbs SY.limbs hs k := by
  obtain ⟨l, dx, dy, m, v, ix, ox, oy, cons, last, ⟨hOut, pOut⟩⟩ :=
    quad_add_slopes_exist hA hT hfirst hout
  obtain ⟨w⟩ := quadTransition_arithmetic_complete hr (slopeElem l) (slopeElem m) (slopeElem v)
    AX AY SX SY rfl rfl rfl hAX hAY hSX hSY hs hA hT l dx dy m v ix ox oy
    (slopeElem_cast l) (slopeElem_cast m) (slopeElem_cast v) cons last hOut pOut
  obtain ⟨hO, hp⟩ := w.outputPoint
  refine ⟨w.OX, w.OY, w.oxBound, w.oyBound, ⟨hO, hp hA hT⟩, ?_⟩
  intro k hk
  exact QuadrupleAndAddLazy_8_8_8_8_h8a920ea3_compose
    AX.limbs AY.limbs SX.limbs SY.limbs hs
    (slopeElem l).limbs (slopeElem m).limbs (slopeElem v).limbs
    w.DX.limbs w.DY.limbs w.IX.limbs w.OX.limbs w.OY.limbs w.b
    (rawSlopePieces l) (rawSlopePieces m) (rawSlopePieces v)
    (slopePieces l) (slopePieces m) (slopePieces v)
    (slopePieces_ranges hr l) (slopePieces_ranges hr m) (slopePieces_ranges hr v)
    (slopePieces_limb l) (slopePieces_limb m) (slopePieces_limb v)
    w.nativeFlag w.tangent w.chord w.flagCheck w.second
    w.doubleX w.doubleY w.intermediateX w.outX w.outY k hk

end ZolanaVE.P256.Completeness
