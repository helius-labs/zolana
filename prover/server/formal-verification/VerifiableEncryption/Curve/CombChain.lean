import VerifiableEncryption.Curve.CombWindows
import VerifiableEncryption.Curve.CompleteAdd
import VerifiableEncryption.Curve.LadderTable
import VerifiableEncryption.Curve.Slots

/-!
The comb addition chain at the group level, and the window selections as
table points.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks ZolanaVE.CombLimbs ZolanaVE.P256.Comb

/-- One chain addition: the accumulator `(x, l0·(pwx - x) - pwy)` plus the
window point, given that neither equals the other nor its negation. -/
theorem chain_group {x l0 pwx pwy wx wy l nx : ℤ}
    (hA : OnCurve (x : Fp) ((l0 * (pwx - x) - pwy : ℤ) : Fp)) (hW : OnCurve (wx : Fp) (wy : Fp))
    (hne : mkPoint hA ≠ mkPoint hW ∧ mkPoint hA ≠ -mkPoint hW)
    (hrel : ChainRel x l0 pwx pwy wx wy l nx) :
    ∃ hN : OnCurve (nx : Fp) ((l * (wx - nx) - wy : ℤ) : Fp), mkPoint hN = mkPoint hA + mkPoint hW := by
  have hx : (x : Fp) ≠ (wx : Fp) := (x_ne_iff hA hW).mpr hne
  have h1 := hrel.1
  rw [modEq_p_iff] at h1
  push_cast at h1
  obtain ⟨hS, pS⟩ := slope_add_int (l := l) (xs := nx) (ys := l * (x - nx) - (l0 * (pwx - x) - pwy)) hA hW hx
    (by rw [modEq_p_iff]; push_cast; linear_combination h1) (by rw [sq]; exact hrel.2) (Int.ModEq.refl _)
  have e : ((l * (x - nx) - (l0 * (pwx - x) - pwy) : ℤ) : Fp) = ((l * (wx - nx) - wy : ℤ) : Fp) := by
    push_cast
    linear_combination -h1
  have hN : OnCurve (nx : Fp) ((l * (wx - nx) - wy : ℤ) : Fp) := by rw [← e]; exact hS
  exact ⟨hN, by rw [pS]; exact mkPoint_inj.mpr ⟨rfl, e.symm⟩⟩

theorem chain_first_group {x fy wx wy l nx : ℤ}
    (hA : OnCurve (x : Fp) (fy : Fp)) (hW : OnCurve (wx : Fp) (wy : Fp))
    (hne : mkPoint hA ≠ mkPoint hW ∧ mkPoint hA ≠ -mkPoint hW)
    (hrel : FirstRel x wx wy fy l nx) :
    ∃ hN : OnCurve (nx : Fp) ((l * (wx - nx) - wy : ℤ) : Fp), mkPoint hN = mkPoint hA + mkPoint hW := by
  have hx : (x : Fp) ≠ (wx : Fp) := (x_ne_iff hA hW).mpr hne
  have h1 := hrel.1
  rw [modEq_p_iff] at h1
  push_cast at h1
  obtain ⟨hS, pS⟩ := slope_add_int (l := l) (xs := nx) (ys := l * (x - nx) - fy) hA hW hx
    (by rw [modEq_p_iff]; push_cast; linear_combination h1) (by rw [sq]; exact hrel.2) (Int.ModEq.refl _)
  have e : ((l * (x - nx) - fy : ℤ) : Fp) = ((l * (wx - nx) - wy : ℤ) : Fp) := by
    push_cast
    linear_combination -h1
  have hN : OnCurve (nx : Fp) ((l * (wx - nx) - wy : ℤ) : Fp) := by rw [← e]; exact hS
  exact ⟨hN, by rw [pS]; exact mkPoint_inj.mpr ⟨rfl, e.symm⟩⟩

/-- Five hinted bits read little-endian name the selected table row. -/
theorem sel5_chunk {n : ℕ} {g : List.Vector F n} (hb : AllBits g) {a : ℕ} (ha : a + 5 ≤ n) {i : ℕ}
    (hi : i < 32)
    (h : g.toList.getD a 0 + g.toList.getD (a + 1) 0 * 2 + g.toList.getD (a + 2) 0 * 4 +
      g.toList.getD (a + 3) 0 * 8 + g.toList.getD (a + 4) 0 * 16 = ((i : ℕ) : F)) :
    (i : ℤ) = chunk g a 5 := by
  obtain ⟨v0, h0, b0, g0⟩ := bit01 hb (a := a) (by omega)
  obtain ⟨v1, h1, b1, g1⟩ := bit01 hb (a := a + 1) (by omega)
  obtain ⟨v2, h2, b2, g2⟩ := bit01 hb (a := a + 2) (by omega)
  obtain ⟨v3, h3, b3, g3⟩ := bit01 hb (a := a + 3) (by omega)
  obtain ⟨v4, h4, b4, g4⟩ := bit01 hb (a := a + 4) (by omega)
  rw [← vget_getD' g a (by omega), ← vget_getD' g (a + 1) (by omega), ← vget_getD' g (a + 2) (by omega),
    ← vget_getD' g (a + 3) (by omega), ← vget_getD' g (a + 4) (by omega), g0, g1, g2, g3, g4] at h
  have h' : ((v0 + v1 * 2 + v2 * 4 + v3 * 8 + v4 * 16 : ℕ) : F) = ((i : ℕ) : F) := by push_cast; exact h
  have hv := natCast_inj (lt_order_of_le (by omega)) (lt_order_of_le (by omega)) h'
  simp only [chunk, Finset.sum_range_succ, Finset.sum_range_zero, Nat.add_zero, add_zero, zero_add, b0, b1, b2, b3,
    b4]
  rw [← hv]
  push_cast
  ring

/-- A window select of the comb: the selected entry as reduced coordinates,
the point `(2i + 1 - 32)·2^(5t)·G`. -/
theorem window_select {t : ℕ} (ht : t < 51) {b0 b1 b2 b3 b4 : F} (hb0 : GatesDef.is_bool b0)
    (hb1 : GatesDef.is_bool b1) (hb2 : GatesDef.is_bool b2) (hb3 : GatesDef.is_bool b3)
    (hb4 : GatesDef.is_bool b4) {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombSelect_8_32_3_32_5_h25d1d12b (txAt t) (tyAt t) (b0 ::ᵥ b1 ::ᵥ b2 ::ᵥ b3 ::ᵥ b4 ::ᵥ List.Vector.nil) k) :
    ∃ i : Fin 32, b0 + b1 * 2 + b2 * 4 + b3 * 8 + b4 * 16 = ((i : ℕ) : F) ∧
      ∃ WX WY : ElemVal 8, WX.bnd = reducedC ∧ WY.bnd = packC ∧ k (WX.limbs ::ᵥ WY.limbs ::ᵥ List.Vector.nil) ∧
        ∃ hW : OnCurve (WX.value : Fp) (WY.value : Fp),
          mkPoint hW = ((2 * (i : ℤ) + 1 - 32) * 2 ^ (5 * t)) • G := by
  obtain ⟨i, hi, hk⟩ := combSelect32_sound (fun j => by fin_cases j <;> assumption) h
  have hon := entry_on (t := t) (j := i) (by omega) (by rw [width_lt ht]; exact i.2)
  have hlt := onCurveB_lt hon
  have h1 : (entry t i).1 < 2 ^ 256 := lt_trans hlt.1 p_lt_two_pow
  have h2 : (entry t i).2 < 2 ^ 256 := lt_trans hlt.2 p_lt_two_pow
  refine ⟨i, hi, winX _ h1, winY _ h2, rfl, rfl, ?_, ?_⟩
  · have tx := tx_ok ⟨t, ht⟩ i
    have ty := ty_ok ⟨t, ht⟩ i
    simp only at tx ty
    rw [tx 0, tx 1, tx 2, tx 3, tx 4, tx 5, tx 6, tx 7, ty 0, ty 1, ty 2] at hk
    convert hk using 3
    apply List.Vector.toList_injective
    simp only [winX, winY, mkElem_limbs]
    simp only [xInts, yInts, Fin.isValue, Fin.coe_ofNat_eq_mod, Nat.reduceMod, Fin.val_zero, List.getD_cons_succ,
      List.getD_cons_zero, Int.cast_natCast, Int.cast_zero, Nat.reduceMul, List.Vector.toList_cons,
      List.Vector.toList_nil, pow_zero, Nat.div_one]
  · have e1 : ((winX _ h1).value : Fp) = ((entry t i).1 : Fp) := by
      simp only [winX, mkElem_value]; rw [rec8_xInts h1]; push_cast; rfl
    have e2 : ((winY _ h2).value : Fp) = ((entry t i).2 : Fp) := by
      simp only [winY, mkElem_value]; rw [rec8_yInts h2]; push_cast; rfl
    have hW : OnCurve ((winX _ h1).value : Fp) ((winY _ h2).value : Fp) := by
      rw [e1, e2]; exact onCurveB_sound hon
    refine ⟨hW, ?_⟩
    have hwp := window_point t i (by omega) (by rw [width_lt ht]; exact i.2)
    have hw : ((width t : ℕ) : ℤ) = 32 := by rw [width_lt ht]; rfl
    rw [hw] at hwp
    rw [← hwp]
    exact mkPoint_inj.mpr ⟨e1, e2⟩

/-- The top window: `topEven` (parity bit clear) or `windows[51]`. -/
def topScalar (i : ℕ) : ℤ := if i < 2 then (2 * i - 1) * 2 ^ 255 - 1 else (2 * ((i : ℤ) - 2) - 1) * 2 ^ 255

theorem top_select {b0 b1 : F} (hb0 : GatesDef.is_bool b0) (hb1 : GatesDef.is_bool b1)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombSelect_8_4_8_4_2_h27b40688 topX topY (b0 ::ᵥ b1 ::ᵥ List.Vector.nil) k) :
    ∃ i : Fin 4, b0 + b1 * 2 = ((i : ℕ) : F) ∧
      ∃ WX WY : ElemVal 8, WX.bnd = reducedC ∧ WY.bnd = reducedC ∧ k (WX.limbs ::ᵥ WY.limbs ::ᵥ List.Vector.nil) ∧
        ∃ hW : OnCurve (WX.value : Fp) (WY.value : Fp), mkPoint hW = topScalar i • G := by
  obtain ⟨i, hi, hk⟩ := combSelect4_sound (fun j => by fin_cases j <;> assumption) h
  have hon : onCurveB (topEntry i) = true := by
    unfold topEntry
    split_ifs with hlt
    · exact top_on hlt
    · exact entry_on (by norm_num) (by rw [width_top]; omega)
  have hlt := onCurveB_lt hon
  have h1 : (topEntry i).1 < 2 ^ 256 := lt_trans hlt.1 p_lt_two_pow
  have h2 : (topEntry i).2 < 2 ^ 256 := lt_trans hlt.2 p_lt_two_pow
  refine ⟨i, hi, winX _ h1, winX _ h2, rfl, rfl, ?_, ?_⟩
  · have tx := topX_ok i
    have ty := topY_ok i
    rw [tx 0, tx 1, tx 2, tx 3, tx 4, tx 5, tx 6, tx 7, ty 0, ty 1, ty 2, ty 3, ty 4, ty 5, ty 6, ty 7] at hk
    convert hk using 3
  · have e1 : ((winX _ h1).value : Fp) = ((topEntry i).1 : Fp) := by
      simp only [winX, mkElem_value]; rw [rec8_xInts h1]; push_cast; rfl
    have e2 : ((winX _ h2).value : Fp) = ((topEntry i).2 : Fp) := by
      simp only [winX, mkElem_value]; rw [rec8_xInts h2]; push_cast; rfl
    have hW : OnCurve ((winX _ h1).value : Fp) ((winX _ h2).value : Fp) := by
      rw [e1, e2]; exact onCurveB_sound hon
    refine ⟨hW, ?_⟩
    have hpt : mkPoint hW = toPt (topEntry i) hon := mkPoint_inj.mpr ⟨e1, e2⟩
    rw [hpt]
    have hi4 := i.2
    unfold topScalar
    by_cases hlt : (i : ℕ) < 2
    · rw [if_pos hlt, toPt_congr (show topEntry i = topAt i by simp [topEntry, hlt]) hon (top_on hlt),
        topEven_point _ hlt]
    · rw [if_neg hlt]
      have hj : (i : ℕ) - 2 < width 51 := by rw [width_top]; omega
      rw [toPt_congr (show topEntry i = entry 51 (i - 2) by simp [topEntry, hlt]) hon (entry_on (by norm_num) hj),
        window_point 51 _ (by norm_num) hj, width_top]
      congr 1
      push_cast [Nat.cast_sub (show 2 ≤ (i : ℕ) by omega)]
      ring

end ZolanaVE.P256
