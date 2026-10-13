import VerifiableEncryption.Curve.CompletenessComb

/-! Actual native window selectors are constructed before their table-point
facts are attached. Selector soundness here is ordinary polynomial algebra:
no opaque row-lookup soundness or successful-selection premise is required.
Source candidates remain unelaborated. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks ZolanaVE.CombLimbs ZolanaVE.P256.Comb

theorem boolNative_boolean (b : Bool) : GatesDef.is_bool (boolNative b) := by
  cases b <;> simp [boolNative, GatesDef.is_bool]

/-- Closed literal table property, independent of selector or hint success. -/
theorem combTop_canonical : ∀ i : Fin 4,
    limbNat (topX.get i) < p ∧ limbNat (topY.get i) < p := by decide +kernel

theorem combWindow_complete {t : ℕ} (ht : t < 51) (b0 b1 b2 b3 b4 : Bool) :
    ∃ (i : Fin 32) (WX WY : ElemVal 8),
      boolNative b0 + boolNative b1 * 2 + boolNative b2 * 4 +
        boolNative b3 * 8 + boolNative b4 * 16 = ((i : ℕ) : F) ∧
      WX.bnd = reducedC ∧ WY.bnd = packC ∧
      (∃ hW : OnCurve (WX.value : Fp) (WY.value : Fp),
        mkPoint hW = ((2 * (i : ℤ) + 1 - 32) * 2 ^ (5 * t)) • G) ∧
      ∀ k : List.Vector (List.Vector F 8) 2 → Prop,
        k (WX.limbs ::ᵥ WY.limbs ::ᵥ List.Vector.nil) →
        CombSelect_8_32_3_32_5_h2261d38e (txAt t) (tyAt t)
          vec![boolNative b0, boolNative b1, boolNative b2, boolNative b3, boolNative b4] k := by
  let result := selected32 (txAt t) (tyAt t) (index32 b0 b1 b2 b3 b4)
  have hactual := combSelect32_complete (txAt t) (tyAt t) b0 b1 b2 b3 b4
    (fun o => o = result) rfl
  obtain ⟨i, hi, WX, WY, hx, hy, hv, hW⟩ := window_select ht
    (boolNative_boolean b0) (boolNative_boolean b1) (boolNative_boolean b2)
    (boolNative_boolean b3) (boolNative_boolean b4) hactual
  refine ⟨i, WX, WY, hi, hx, hy, hW, ?_⟩
  intro k hk
  apply combSelect32_complete
  change k result
  rw [← hv]
  exact hk

theorem combTop_complete (b0 b1 : Bool) :
    ∃ (i : Fin 4) (TX TY : ElemVal 8),
      boolNative b0 + boolNative b1 * 2 = ((i : ℕ) : F) ∧
      TX.bnd = reducedC ∧ TY.bnd = reducedC ∧
      limbNat TX.limbs < p ∧ limbNat TY.limbs < p ∧
      (∃ hT : OnCurve (TX.value : Fp) (TY.value : Fp), mkPoint hT = topScalar i • G) ∧
      ∀ k : List.Vector (List.Vector F 8) 2 → Prop,
        k (TX.limbs ::ᵥ TY.limbs ::ᵥ List.Vector.nil) →
        CombSelect_8_4_8_4_2_h80fdf981 topX topY
          vec![boolNative b0, boolNative b1] k := by
  let result := (topX.get (index4 b0 b1)) ::ᵥ
    (topY.get (index4 b0 b1)) ::ᵥ List.Vector.nil
  have hactual := combSelect4_complete topX topY b0 b1 (fun o => o = result) rfl
  obtain ⟨i, hi, TX, TY, hx, hy, hv, hT⟩ := top_select
    (boolNative_boolean b0) (boolNative_boolean b1) hactual
  have hxNative : TX.limbs = topX.get (index4 b0 b1) :=
    congrArg (fun o => o.get 0) hv
  have hyNative : TY.limbs = topY.get (index4 b0 b1) :=
    congrArg (fun o => o.get 1) hv
  refine ⟨i, TX, TY, hi, hx, hy, ?_, ?_, hT, ?_⟩
  · rw [hxNative]
    exact (combTop_canonical _).1
  · rw [hyNative]
    exact (combTop_canonical _).2
  · intro k hk
    apply combSelect4_complete
    change k result
    rw [← hv]
    exact hk

end ZolanaVE.P256.Completeness
