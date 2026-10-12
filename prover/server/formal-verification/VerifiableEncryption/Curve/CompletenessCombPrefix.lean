import VerifiableEncryption.Curve.CompletenessCombSelection
import VerifiableEncryption.Curve.CompletenessCombSecond

/-! Connect selected recoding windows to the first two actual chain steps.
Local exceptional-point obligations are derived from the comb digits here,
not retained as hypotheses on a secret or satisfying-operation assumption.
This is a prefix construction, not full ScalarMulBase completeness. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks ZolanaVE.CombLimbs
open scoped BigOperators

def combFirstTwoNative (s : ℕ) (k : List.Vector (List.Vector F 8) 2 → Prop) : Prop :=
  CombSelect_8_32_3_32_5_h25d1d12b (txAt 0) (tyAt 0) (combWindowBits s 0) (fun w0 =>
    CombSelect_8_32_3_32_5_h25d1d12b (txAt 1) (tyAt 1) (combWindowBits s 1) (fun w1 =>
      CombSelect_8_32_3_32_5_h25d1d12b (txAt 2) (tyAt 2) (combWindowBits s 2) (fun w2 =>
        CombChainStep_8_8_8_8_8_8_8_h9024d0c7 (w0.get 0)
          (List.Vector.replicate 8 0) (List.Vector.replicate 8 0) (List.Vector.replicate 8 0)
          (w1.get 0) (w1.get 1) (w0.get 1) (fun a1 =>
            CombChainStep_8_8_8_8_8_8_8_h88ed5eb6 (a1.get 0) (a1.get 1)
              (w1.get 0) (w1.get 1) (w2.get 0) (w2.get 1) (w0.get 1) k))))

theorem combFirstTwo_from_bits (hr : RangeComplete) (s : ℕ) :
    ∃ X L WX WY : ElemVal 8,
      X.bnd = lazyOut lazy_h33616364 ∧ L.bnd = balC ∧
      WX.bnd = reducedC ∧ WY.bnd = packC ∧
      (∃ hA : OnCurve (X.value : Fp) ((L.value * (WX.value - X.value) - WY.value : ℤ) : Fp),
        mkPoint hA = (∑ u ∈ Finset.range 3, digOf (combBits s) u * 2 ^ (5 * u)) • G) ∧
      ∀ k : List.Vector (List.Vector F 8) 2 → Prop,
        k (X.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) → combFirstTwoNative s k := by
  obtain ⟨W0X, W0Y, hW0X, hW0Y, ⟨hA1, pA1⟩, sel0⟩ := combWindow_bits_complete s 0
  obtain ⟨W1X, W1Y, hW1X, hW1Y, ⟨hW1, pW1⟩, sel1⟩ := combWindow_bits_complete s 1
  obtain ⟨W2X, W2Y, hW2X, hW2Y, ⟨hW2, pW2⟩, sel2⟩ := combWindow_bits_complete s 2
  have pA1' : mkPoint hA1 =
      (∑ u ∈ Finset.range 1, digOf (combBits s) u * 2 ^ (5 * u)) • G := by
    simpa using pA1
  obtain ⟨hne1, hs1⟩ := comb_acc_step (combBits_all s) (le_refl 257)
    (t := 1) (by norm_num) pA1' pW1
  obtain ⟨X1, L1, hX1, hL1, rel1, ⟨hA2, pA2⟩, chain1⟩ :=
    combFirst_complete hr W0X W1X W1Y W0Y hW0X hW1X hW1Y hW0Y hA1 hW1 hne1
  have pA2' : mkPoint hA2 =
      (∑ u ∈ Finset.range 2, digOf (combBits s) u * 2 ^ (5 * u)) • G := by
    rw [pA2]
    exact hs1
  obtain ⟨hne2, hs2⟩ := comb_acc_step (combBits_all s) (le_refl 257)
    (t := 2) (by norm_num) pA2' pW2
  obtain ⟨X2, L2, hX2, hL2, rel2, ⟨hA3, pA3⟩, chain2⟩ :=
    combSecond_complete hr X1 L1 W1X W1Y W2X W2Y hX1 hL1 hW1X hW1Y hW2X hW2Y hA2 hW2 hne2
  refine ⟨X2, L2, W2X, W2Y, hX2, hL2, hW2X, hW2Y, ⟨hA3, ?_⟩, ?_⟩
  · rw [pA3]
    exact hs2
  · intro k hk
    unfold combFirstTwoNative
    apply sel0
    apply sel1
    apply sel2
    apply chain1
    exact chain2 W0Y.limbs k hk

end ZolanaVE.P256.Completeness
