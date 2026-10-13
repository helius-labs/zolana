import VerifiableEncryption.Curve.CompletenessCombFirstArithmetic

/-! Construct the actual first fixed-base chain witness from finite selected
points. The chord denominator follows from the local point noncollision;
all arithmetic witnesses, slopes and hint pieces are constructed. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem combFirst_complete (hr : RangeComplete) (X WX WY FY : ElemVal 8)
    (hX : X.bnd = reducedC) (hWX : WX.bnd = reducedC)
    (hWY : WY.bnd = packC) (hFY : FY.bnd = packC)
    (hA : OnCurve (X.value : Fp) (FY.value : Fp))
    (hW : OnCurve (WX.value : Fp) (WY.value : Fp))
    (hne : mkPoint hA ≠ mkPoint hW ∧ mkPoint hA ≠ -mkPoint hW) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h4ef94fb8 ∧ L.bnd = balC ∧
      FirstRel X.value WX.value WY.value FY.value L.value NX.value ∧
      (∃ hN : OnCurve (NX.value : Fp) ((L.value * (WX.value - NX.value) - WY.value : ℤ) : Fp),
        mkPoint hN = mkPoint hA + mkPoint hW) ∧
      ∀ (previousSlope previousX previousY : List.Vector F 8)
        (k : List.Vector (List.Vector F 8) 2 → Prop),
        k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) →
        CombChainStep_8_8_8_8_8_8_8_h14296507 X.limbs previousSlope previousX previousY
          WX.limbs WY.limbs FY.limbs k := by
  obtain ⟨l, hz, next⟩ := combFirst_slope_math X WX WY FY hA hW hne
  let L := slopeElem l
  have hs := combFirstSlope_complete hr L X WX WY FY rfl hX hWX hWY hFY hz
  obtain ⟨NX, hNX, hv, ha⟩ := combFirstLazy_complete L X WX rfl hX hWX
  obtain ⟨rel, hp⟩ := next NX hv
  refine ⟨NX, L, hNX, rfl, rel, hp, ?_⟩
  intro previousSlope previousX previousY k hk
  exact combFirst_native X.limbs previousSlope previousX previousY WX.limbs WY.limbs FY.limbs L.limbs
    (rawSlopePieces l) (slopePieces l) (slopePieces_ranges hr l) (slopePieces_limb l) k hs
    (ha (fun out => k (out ::ᵥ L.limbs ::ᵥ List.Vector.nil)) hk)

end ZolanaVE.P256.Completeness
