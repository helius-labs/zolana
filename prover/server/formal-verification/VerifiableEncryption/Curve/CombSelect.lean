import VerifiableEncryption.Curve.Select

/-!
`combSelect`: the one-hot selection of a constant comb table entry.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem combSelect4_sound {TX TY : List.Vector (List.Vector F 8) 4} {bits : List.Vector F 2}
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (hb : ∀ j : Fin 2, GatesDef.is_bool (bits.get j)) (h : CombSelect_8_4_8_4_2_h27b40688 TX TY bits k) :
    ∃ i : Fin 4, bits.get 0 + bits.get 1 * 2 = ((i : ℕ) : F) ∧
      k vec![vec![(TX.get i).get 0, (TX.get i).get 1, (TX.get i).get 2, (TX.get i).get 3,
          (TX.get i).get 4, (TX.get i).get 5, (TX.get i).get 6, (TX.get i).get 7],
        vec![(TY.get i).get 0, (TY.get i).get 1, (TY.get i).get 2, (TY.get i).get 3,
          (TY.get i).get 4, (TY.get i).get 5, (TY.get i).get 6, (TY.get i).get 7]] := by
  unfold CombSelect_8_4_8_4_2_h27b40688 at h
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, GatesDef.sub,
    exists_eq_left] at h
  obtain ⟨b0, hb0⟩ := bool_of_is_bool (hb 0)
  obtain ⟨b1, hb1⟩ := bool_of_is_bool (hb 1)
  rw [hb0, hb1] at h ⊢
  cases b0 <;> cases b1 <;>
    simp only [Bool.false_eq_true, ↓reduceIte, mul_one, mul_zero, one_mul, zero_mul, sub_zero, sub_self,
      add_zero, zero_add] at h ⊢ <;>
    exact ⟨_, by norm_num <;> rfl, h⟩

theorem combSelect32_sound {TX : List.Vector (List.Vector F 8) 32} {TY : List.Vector (List.Vector F 3) 32}
    {bits : List.Vector F 5} {k : List.Vector (List.Vector F 8) 2 → Prop}
    (hb : ∀ j : Fin 5, GatesDef.is_bool (bits.get j)) (h : CombSelect_8_32_3_32_5_h25d1d12b TX TY bits k) :
    ∃ i : Fin 32, bits.get 0 + bits.get 1 * 2 + bits.get 2 * 4 + bits.get 3 * 8 + bits.get 4 * 16 = ((i : ℕ) : F) ∧
      k vec![vec![(TX.get i).get 0, (TX.get i).get 1, (TX.get i).get 2, (TX.get i).get 3,
          (TX.get i).get 4, (TX.get i).get 5, (TX.get i).get 6, (TX.get i).get 7],
        vec![(TY.get i).get 0, (0 : F), (0 : F), (TY.get i).get 1, (0 : F), (0 : F), (TY.get i).get 2, (0 : F)]] := by
  unfold CombSelect_8_32_3_32_5_h25d1d12b CombSelect_8_32_3_32_5_h25d1d12b_p1 CombSelect_8_32_3_32_5_h25d1d12b_p2
    CombSelect_8_32_3_32_5_h25d1d12b_p3 at h
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, GatesDef.sub,
    exists_eq_left] at h
  obtain ⟨b0, hb0⟩ := bool_of_is_bool (hb 0)
  obtain ⟨b1, hb1⟩ := bool_of_is_bool (hb 1)
  obtain ⟨b2, hb2⟩ := bool_of_is_bool (hb 2)
  obtain ⟨b3, hb3⟩ := bool_of_is_bool (hb 3)
  obtain ⟨b4, hb4⟩ := bool_of_is_bool (hb 4)
  rw [hb0, hb1, hb2, hb3, hb4] at h ⊢
  cases b0 <;> cases b1 <;> cases b2 <;> cases b3 <;> cases b4 <;>
    simp only [Bool.false_eq_true, ↓reduceIte, mul_one, mul_zero, one_mul, zero_mul, sub_zero, sub_self,
      add_zero, zero_add] at h ⊢ <;>
    exact ⟨_, by norm_num <;> rfl, h⟩

end ZolanaVE.P256
