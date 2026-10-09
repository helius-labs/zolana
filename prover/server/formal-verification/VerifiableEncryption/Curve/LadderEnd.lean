import VerifiableEncryption.Curve.LadderTable
import VerifiableEncryption.Curve.Slots

/-!
The ladder's last step: the looked-up row plus `3R`, then the doubling-aware
quadruple-and-add.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem ladder_last (hl : LookupSound RangeCheck 11) (hr : RowLookupSound)
    {rows : List.Vector (List.Vector F 12) 16} {Q R : P} (ht : TableOK rows Q R)
    (AX AY : ElemVal 8) (hAX : AX.bnd = lazyOut lazy_h9c68f146) (hAY : AY.bnd = lazyOut lazy_hee995b41)
    (hA : OnCurve (AX.value : Fp) (AY.value : Fp))
    (TX TY : ElemVal 8) (hTX : TX.bnd = reducedC) (hTY : TY.bnd = reducedC)
    (hT : OnCurve (TX.value : Fp) (TY.value : Fp)) {idx : F}
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : RowLookup_12_16 rows idx fun r =>
      AssertDistinctX_8_8_h83dcf683
        (r.get 0 ::ᵥ r.get 1 ::ᵥ r.get 2 ::ᵥ r.get 3 ::ᵥ r.get 4 ::ᵥ r.get 5 ::ᵥ r.get 6 ::ᵥ r.get 7 ::ᵥ
          List.Vector.nil) TX.limbs ∧
      Add_8_8_8_8_h8ef7b27b
        (r.get 0 ::ᵥ r.get 1 ::ᵥ r.get 2 ::ᵥ r.get 3 ::ᵥ r.get 4 ::ᵥ r.get 5 ::ᵥ r.get 6 ::ᵥ r.get 7 ::ᵥ
          List.Vector.nil)
        (r.get 8 ::ᵥ (0 : F) ::ᵥ (0 : F) ::ᵥ r.get 9 ::ᵥ (0 : F) ::ᵥ (0 : F) ::ᵥ r.get 10 ::ᵥ (0 : F) ::ᵥ
          List.Vector.nil) TX.limbs TY.limbs
        fun s => QuadrupleAndAddLazy_8_8_8_8_h4e58d4bc AX.limbs AY.limbs (s.get 0) (s.get 1) 0 k) :
    ∃ i : Fin 16, idx = ((i : ℕ) : F) ∧ ∃ OX OY : ElemVal 8,
      OX.bnd = lazyOut lazy_h9c68f146 ∧ OY.bnd = lazyOut lazy_hc2c2cd77 ∧
      k (OX.limbs ::ᵥ OY.limbs ::ᵥ List.Vector.nil) ∧
      ∃ hO : OnCurve (OX.value : Fp) (OY.value : Fp),
        mkPoint hO = 4 • mkPoint hA + (Ladder.rowPoint i Q R + mkPoint hT) := by
  obtain ⟨i, hi, hk⟩ := hr _ _ _ h
  obtain ⟨X, Y, hXY, hs, hq, hXb, hYb, hxl, hyl, hhs, hlt, hqs, hquart, hpt⟩ := ht i
  rw [hxl, hyl] at hk
  obtain ⟨hg, hadd⟩ := hk
  have dg := distinctX_elem hXb hTX hg
  obtain ⟨SX, SY, hSX, hSY, hk2, cr⟩ := add_h8ef7b27b_sound hl X Y TX TY hXb hYb hTX hTY hadd
  obtain ⟨hS, hSeq⟩ := chord_point hXY hT dg.2.2.2.2 cr.1 cr.2
  simp only [get2_0, get2_1] at hk2
  obtain ⟨OX, OY, hOX, hOY, hk3, L, hLb, dX, dY, μ, ν, iX, c, hlast⟩ :=
    quadAdd_h4e58d4bc_sound hl AX AY SX SY hAX hAY hSX hSY hk2
  obtain ⟨hO, hOeq⟩ := quad_add_correct hA hS c (Or.inr hlast)
  exact ⟨i, hi, OX, OY, hOX, hOY, hk3, hO, by rw [hOeq, hSeq, hpt]⟩

theorem bitI_eq_of_sel {n : ℕ} {g : List.Vector F n} (hb : AllBits g) {a : ℕ} (ha : a < n) {b : Bool}
    (h : g.toList.getD a 0 = if b then 1 else 0) : bitI g a = if b then 1 else 0 := by
  obtain ⟨v, hv, hbv, hgv⟩ := bit01 hb ha
  rw [vget_getD'] at hgv
  rw [hgv] at h
  rw [hbv]
  cases b
  · simp only [Bool.false_eq_true, if_false] at h ⊢
    have := natCast_inj (a := v) (b := 0) (lt_order_of_le (by omega)) (lt_order_of_le (by norm_num)) (by simpa using h)
    simp [this]
  · simp only [if_true] at h ⊢
    have := natCast_inj (a := v) (b := 1) (lt_order_of_le (by omega)) (lt_order_of_le (by norm_num)) (by simpa using h)
    simp [this]

/-- The ladder's closing corrections: the last row plus `3R`, then `-Q` unless
the numerator's low bit is set and `-R` unless the denominator's is, must land
on `3R`. -/
theorem ladder_close {Q R T A0 A E NQ NR C1 C2 : P} {a c dq dr : ℤ} {i : Fin 16} (b1 b2 : Bool)
    (hinv : A0 = a • Q + c • R) (hA : A = 4 • A0 + (Ladder.rowPoint i Q R + T))
    (hd : Ladder.digQ i = dq ∧ Ladder.digR i = dr) (hT : 3 • R = T) (hE : E = A)
    (hNQ : NQ = -Q) (hNR : NR = -R)
    (hC1 : C1 = if b1 then E else NQ + E) (hC2 : C2 = if b2 then C1 else NR + C1) (hfin : C2 = T) :
    (4 * a + dq + (if b1 then 1 else 0) - 1) • Q + (4 * c + dr + (if b2 then 1 else 0) - 1) • R = 0 := by
  rw [Ladder.row_point Q R i i.2, hd.1, hd.2] at hA
  subst hinv hE hNQ hNR hC1 hC2 hT hA
  cases b1 <;> cases b2 <;> simp only [Bool.false_eq_true, ↓reduceIte] at hfin ⊢ <;>
    (rw [← sub_eq_zero] at hfin; rw [← hfin]; module)

/-- The scalar binding: the recoded decomposition `s'·(ε·den) + num ≡ 0` and
the ladder relation give `Prod = s'·Q'`, and undoing the exceptional-residue
selection gives `s·Q`. -/
theorem scalar_close {Q Q' R Prod : P} {s s0 hH num den ε : ℤ} (e : Bool) (hε : ε = 1 ∨ ε = -1)
    (hden : 1 ≤ den ∧ den < n) (hdec : (if e then hH else s0) * (ε * den) + num ≡ 0 [ZMOD n])
    (hrel : num • Q' + den • R = 0) (hR : R = ε • Prod) (hQ' : Q' = if e then (2 : ℤ) • Q else Q)
    (hh : hH * 2 ≡ s0 [ZMOD n]) (hs : s0 ≡ s [ZMOD n]) : Prod = s • Q := by
  subst hR
  have h1 := Ladder.ladder_chain hε hden hdec hrel
  rw [Ladder.select_sound (Out := Prod) e hh (by rw [h1, hQ'])]
  exact zsmul_congr hs Q

end ZolanaVE.P256
