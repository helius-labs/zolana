import VerifiableEncryption.Curve.CompletenessCombWindows
import VerifiableEncryption.Curve.CompletenessBits

/-! Selected-coordinate witnesses tied to the actual recoded bit vector and
its signed comb digits. These facts feed the full native chain assembly. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks ZolanaVE.CombLimbs

def combBoolBits (s : ℕ) : List.Vector Bool 257 :=
  (combParity s) ::ᵥ Fin.toBitsLE ⟨combRecoded s, combRecoded_lt s⟩

theorem combBoolBits_native (s : ℕ) (i : Fin 257) :
    boolNative ((combBoolBits s).get i) = (combBits s).get i := by
  change boolNative ((combBoolBits s).get i) =
    ((combBoolBits s).map (Bool.toZMod (N := Order))).get i
  rw [List.Vector.get_map]
  cases (combBoolBits s).get i <;> rfl

def combWindowBits (s : ℕ) (t : Fin 51) : List.Vector F 5 :=
  vec![(combBits s).get ⟨1 + 5 * t.val, by omega⟩,
    (combBits s).get ⟨2 + 5 * t.val, by omega⟩,
    (combBits s).get ⟨3 + 5 * t.val, by omega⟩,
    (combBits s).get ⟨4 + 5 * t.val, by omega⟩,
    (combBits s).get ⟨5 + 5 * t.val, by omega⟩]

theorem combWindow_bits_complete (s : ℕ) (t : Fin 51) :
    ∃ WX WY : ElemVal 8, WX.bnd = reducedC ∧ WY.bnd = packC ∧
      (∃ hW : OnCurve (WX.value : Fp) (WY.value : Fp),
        mkPoint hW = (digOf (combBits s) t.val * 2 ^ (5 * t.val)) • G) ∧
      ∀ k : List.Vector (List.Vector F 8) 2 → Prop,
        k (WX.limbs ::ᵥ WY.limbs ::ᵥ List.Vector.nil) →
        CombSelect_8_32_3_32_5_h25d1d12b (txAt t.val) (tyAt t.val) (combWindowBits s t) k := by
  obtain ⟨i, WX, WY, hi, hx, hy, hW, hactual⟩ := combWindow_complete t.isLt
    ((combBoolBits s).get ⟨1 + 5 * t.val, by omega⟩)
    ((combBoolBits s).get ⟨2 + 5 * t.val, by omega⟩)
    ((combBoolBits s).get ⟨3 + 5 * t.val, by omega⟩)
    ((combBoolBits s).get ⟨4 + 5 * t.val, by omega⟩)
    ((combBoolBits s).get ⟨5 + 5 * t.val, by omega⟩)
  simp only [combBoolBits_native] at hi
  have hchunk : (i : ℤ) = chunk (combBits s) (1 + 5 * t.val) 5 := by
    apply sel5_chunk (combBits_all s) (by omega) i.isLt
    simpa only [vget_getD,
      show 1 + 5 * t.val + 1 = 2 + 5 * t.val by omega,
      show 1 + 5 * t.val + 2 = 3 + 5 * t.val by omega,
      show 1 + 5 * t.val + 3 = 4 + 5 * t.val by omega,
      show 1 + 5 * t.val + 4 = 5 + 5 * t.val by omega] using hi
  refine ⟨WX, WY, hx, hy, ?_, ?_⟩
  · obtain ⟨hw, hp⟩ := hW
    refine ⟨hw, ?_⟩
    rw [hp, digOf, if_pos t.isLt, hchunk]
    congr 1
    ring
  · intro k hk
    simpa only [combBoolBits_native, combWindowBits] using hactual k hk

theorem combTop_bits_complete (s : ℕ) :
    ∃ TX TY : ElemVal 8, TX.bnd = reducedC ∧ TY.bnd = reducedC ∧
      limbNat TX.limbs < p ∧ limbNat TY.limbs < p ∧
      (∃ hT : OnCurve (TX.value : Fp) (TY.value : Fp),
        mkPoint hT = ((2 * bitI (combBits s) 256 - 1) * 2 ^ 255 -
          (1 - bitI (combBits s) 0)) • G) ∧
      ∀ k : List.Vector (List.Vector F 8) 2 → Prop,
        k (TX.limbs ::ᵥ TY.limbs ::ᵥ List.Vector.nil) →
        CombSelect_8_4_8_4_2_h27b40688 topX topY
          vec![(combBits s).get 256, (combBits s).get 0] k := by
  obtain ⟨i, TX, TY, hi, hx, hy, hcX, hcY, hT, hactual⟩ := combTop_complete
    ((combBoolBits s).get 256) ((combBoolBits s).get 0)
  simp only [combBoolBits_native] at hi
  have hscalar := top_val (combBits_all s) (le_refl 257) i.isLt
    (by simpa only [vget_getD] using hi)
  refine ⟨TX, TY, hx, hy, hcX, hcY, ?_, ?_⟩
  · obtain ⟨ht, hp⟩ := hT
    exact ⟨ht, by rw [hp, hscalar]⟩
  · intro k hk
    simpa only [combBoolBits_native] using hactual k hk

theorem combWindows_complete (s : ℕ) :
    ∃ WX WY : Fin 51 → ElemVal 8, ∀ t : Fin 51,
      (WX t).bnd = reducedC ∧ (WY t).bnd = packC ∧
      (∃ hW : OnCurve ((WX t).value : Fp) ((WY t).value : Fp),
        mkPoint hW = (digOf (combBits s) t.val * 2 ^ (5 * t.val)) • G) ∧
      ∀ k : List.Vector (List.Vector F 8) 2 → Prop,
        k ((WX t).limbs ::ᵥ (WY t).limbs ::ᵥ List.Vector.nil) →
        CombSelect_8_32_3_32_5_h25d1d12b (txAt t.val) (tyAt t.val) (combWindowBits s t) k := by
  classical
  choose WX WY hx hy hp hk using (fun t : Fin 51 => combWindow_bits_complete s t)
  exact ⟨WX, WY, fun t => ⟨hx t, hy t, hp t, hk t⟩⟩

end ZolanaVE.P256.Completeness
