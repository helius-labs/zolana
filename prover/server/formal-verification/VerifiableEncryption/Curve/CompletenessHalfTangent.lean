import VerifiableEncryption.Curve.CompletenessHalfTangentNative

/-! Construct the actual half-tangent gadget on all finite reduced inputs,
using the mathematical half point and checked arithmetic/native constructors. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem halfTangent_complete (hr : RangeComplete) (X Y : ElemVal 8)
    (hX : X.bnd = reducedC) (hY : Y.bnd = reducedC)
    (hP : OnCurve (X.value : Fp) (Y.value : Fp)) :
    ∃ L : ElemVal 8, L.bnd = balC ∧
      halfQuartic (X.value : Fp) (Y.value : Fp) (L.value : Fp) = 0 ∧
      ∀ k : List.Vector F 8 → Prop, k L.limbs →
        HalfTangentSlope_8_8_habd58e5e X.limbs Y.limbs k := by
  obtain ⟨l, hl⟩ := half_tangent_exists hP
  have hMath : halfQuartic (X.value : Fp) (Y.value : Fp) l = 0 := by
    unfold halfQuartic
    linear_combination hl
  let L := slopeElem l
  have hRoot : halfQuartic (X.value : Fp) (Y.value : Fp) (L.value : Fp) = 0 :=
    (congrArg (fun z : Fp => halfQuartic (X.value : Fp) (Y.value : Fp) z)
      (slopeElem_cast l)).trans hMath
  obtain ⟨S, hS, hv, hsquare⟩ := halfSquare_complete L rfl
  have hc := halfQuartic_complete hr S X L Y hS hX rfl hY hv hRoot
  refine ⟨L, rfl, hRoot, ?_⟩
  intro k hk
  exact halfTangent_native X Y L S (rawSlopePieces l) (slopePieces l)
    (slopePieces_ranges hr l) (slopePieces_limb l) hsquare hc k hk

end ZolanaVE.P256.Completeness
