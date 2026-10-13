import VerifiableEncryption.Curve.CompletenessAdd
import VerifiableEncryption.Curve.CompletenessCombTailArithmetic

/-! Construct the actual nested fixed-base tail from its canonical x/y
witnesses and checked complete addition. Noninverse geometry stays local and
is discharged by the supported scalar-domain assembly. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem combTail_complete (hr : RangeComplete) (X L WX WY TX TY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h7e1bb4d8) (hL : L.bnd = balC)
    (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    (hTX : TX.bnd = reducedC) (hTY : TY.bnd = reducedC)
    (hcTX : limbNat TX.limbs < p)
    (hA : OnCurve (X.value : Fp) ((L.value * (WX.value - X.value) - WY.value : ℤ) : Fp))
    (hT : OnCurve (TX.value : Fp) (TY.value : Fp))
    (hne : mkPoint hA ≠ -mkPoint hT) :
    ∃ RX RY : ElemVal 8, RX.bnd = reducedC ∧ RY.bnd = reducedC ∧
      limbNat RX.limbs < p ∧ limbNat RY.limbs < p ∧
      (∃ hR : OnCurve (RX.value : Fp) (RY.value : Fp),
        mkPoint hA + mkPoint hT = mkPoint hR) ∧
      ∀ k : List.Vector (List.Vector F 8) 2 → Prop,
        k (RX.limbs ::ᵥ RY.limbs ::ᵥ List.Vector.nil) →
        CheckPolynomial_8_h78194ae0 X.limbs (fun ex =>
          CheckPolynomial_24_h0845ed76 (combTailVector L.limbs WX.limbs ex WY.limbs) (fun ey =>
            CompleteAdd_8_8_8_8_h3f5cf0cd ex ey TX.limbs TY.limbs k)) := by
  let EX := canonicalFpElem (X.value : Fp)
  let EY := canonicalFpElem ((L.value * (WX.value - X.value) - WY.value : ℤ) : Fp)
  have vEX : (EX.value : Fp) = (X.value : Fp) := canonicalFpElem_cast _
  have vEY : (EY.value : Fp) = ((L.value * (WX.value - X.value) - WY.value : ℤ) : Fp) :=
    canonicalFpElem_cast _
  have hE : OnCurve (EX.value : Fp) (EY.value : Fp) := by rw [vEX, vEY]; exact hA
  have pE : mkPoint hE = mkPoint hA := mkPoint_inj.mpr ⟨vEX, vEY⟩
  have hnE : mkPoint hE ≠ -mkPoint hT := by rw [pE]; exact hne
  have hcEX : limbNat EX.limbs < p := by
    change limbNat (canonicalFpElem (X.value : Fp)).limbs < p
    unfold canonicalFpElem
    rw [canonicalNatElem_limbNat]
    exact ZMod.val_lt _
  obtain ⟨RX, RY, hRX, hRY, hcRX, hcRY, hR, hadd⟩ :=
    completeAdd_with_point_complete hr EX EY TX TY rfl rfl hTX hTY hcEX hcTX hE hT hnE
  refine ⟨RX, RY, hRX, hRY, hcRX, hcRY, ?_, ?_⟩
  · simpa only [pE] using hR
  · intro k hk
    apply combTailReduce_complete hr X hX
    apply combTailRecover_complete hr L WX EX WY X hL hWX rfl hWY vEX
    exact hadd k hk

end ZolanaVE.P256.Completeness
