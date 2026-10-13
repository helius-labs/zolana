import VerifiableEncryption.Curve.CompletenessCombSecondArithmetic

/-! Construct the actual second fixed-base chain step, including its six-element
slope assertion, balanced hint pieces and bounded Lazy output. The local point
noncollision is discharged by the supported-domain comb prefix geometry. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem combSecond_complete (hr : RangeComplete) (X L0 PWX PWY WX WY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h4ef94fb8) (hL0 : L0.bnd = balC)
    (hPWX : PWX.bnd = reducedC) (hPWY : PWY.bnd = packC)
    (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    (hA : OnCurve (X.value : Fp) ((L0.value * (PWX.value - X.value) - PWY.value : ℤ) : Fp))
    (hW : OnCurve (WX.value : Fp) (WY.value : Fp))
    (hne : mkPoint hA ≠ mkPoint hW ∧ mkPoint hA ≠ -mkPoint hW) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h33616364 ∧ L.bnd = balC ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value ∧
      (∃ hN : OnCurve (NX.value : Fp) ((L.value * (WX.value - NX.value) - WY.value : ℤ) : Fp),
        mkPoint hN = mkPoint hA + mkPoint hW) ∧
      ∀ (firstY : List.Vector F 8) (k : List.Vector (List.Vector F 8) 2 → Prop),
        k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) →
        CombChainStep_8_8_8_8_8_8_8_hd0a2e1d5 X.limbs L0.limbs PWX.limbs PWY.limbs
          WX.limbs WY.limbs firstY k := by
  obtain ⟨l, hz, next⟩ := combChain_slope_math X L0 PWX PWY WX WY hA hW hne
  let L := slopeElem l
  have hs := combSecondSlope_complete hr L X L0 PWX PWY WX WY rfl hX hL0 hPWX hPWY hWX hWY hz
  obtain ⟨NX, hNX, hv, ha⟩ := combSecondLazy_complete L X WX rfl hX hWX
  obtain ⟨rel, hp⟩ := next NX hv
  refine ⟨NX, L, hNX, rfl, rel, hp, ?_⟩
  intro firstY k hk
  exact combSecond_native X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs firstY L.limbs
    (rawSlopePieces l) (slopePieces l) (slopePieces_ranges hr l) (slopePieces_limb l) k hs
    (ha (fun out => k (out ::ᵥ L.limbs ::ᵥ List.Vector.nil)) hk)

end ZolanaVE.P256.Completeness
