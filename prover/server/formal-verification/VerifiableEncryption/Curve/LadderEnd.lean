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

/-- `curve.add` of the closing correction: the addend's y is a selection
between the signed `R.y` and a reduced coordinate. -/
theorem add_h47aeac58_sound (hl : LookupSound RangeCheck 11) (PX PY QX QY : ElemVal 8)
    (hPX : PX.bnd = reducedC) (hPY : PY.bnd = selBnd selC reducedC) (hQX : QX.bnd = reducedC)
    (hQY : QY.bnd = reducedC) {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : Add_8_8_8_8_h47aeac58 PX.limbs PY.limbs QX.limbs QY.limbs k) :
    ∃ SX SY : ElemVal 8, SX.bnd = reducedC ∧ SY.bnd = reducedC ∧
      k (SX.limbs ::ᵥ SY.limbs ::ᵥ List.Vector.nil) ∧
      ChordRel PX.value PY.value QX.value QY.value SX.value SY.value := by
  unfold Add_8_8_8_8_h47aeac58 Add_8_8_8_8_h47aeac58_p1 at h
  elim_gates h
  obtain ⟨g, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, r24, r25, r26, r27, r28, r29, r30, r31, r32, r33, r34, r35, r36, r37,
    r38, r39, r40, r41, r42, r43, r44, r45, r46, r47, h⟩ := h
  have hpx : ∀ i : Fin 8, PieceRC g (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  have hpy : ∀ i : Fin 8, PieceRC g (24 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r24, rc_getD r25, rc_getD r26⟩, ⟨rc_getD r27, rc_getD r28, rc_getD r29⟩,
      ⟨rc_getD r30, rc_getD r31, rc_getD r32⟩, ⟨rc_getD r33, rc_getD r34, rc_getD r35⟩,
      ⟨rc_getD r36, rc_getD r37, rc_getD r38⟩, ⟨rc_getD r39, rc_getD r40, rc_getD r41⟩,
      ⟨rc_getD r42, rc_getD r43, rc_getD r44⟩, ⟨rc_getD r45, rc_getD r46, rc_getD r47⟩]
  have edx : lazy_h12f7d03a.elems = [subRedC] := rfl
  set DX := mkElem _ _ (sub_red_fits hQX hPX) with hDX
  obtain ⟨D2, hD2lo, hD2hi, hD2vlo, hD2vhi, hk1, hD2v⟩ :=
    Lazy_8_h12f7d03a_sound [⟨8, DX⟩] (elemsMatch_of (by rw [edx]; rfl)) _ (by exact sub_hxs QX PX _) h
  clear h
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23 r24 r25
    r26 r27 r28 r29 r30 r31 r32 r33 r34 r35 r36 r37 r38 r39 r40 r41 r42 r43 r44 r45 r46 r47
  set SX := mkElem _ _ (pieces_fits hl hpx) with hSX
  set SY := mkElem _ _ (pieces_fits hl hpy) with hSY
  have hSXb : SX.bnd = reducedC := rfl
  have hSYb : SY.bnd = reducedC := rfl
  elim_gates hk1
  obtain ⟨hc24, hc32, hk⟩ := hk1
  have hD2b := lazy_bnd hD2lo hD2hi hD2vlo hD2vhi
  set XS := mkElem _ _ (add3_red_fits hSXb hPX hQX) with hXS
  set DY := linElem [(1, QY), (-1, PY)] with hDY
  have c24 := CheckPolynomial_24_h85e25851_sound hl [⟨8, XS⟩, ⟨8, D2⟩, ⟨8, DY⟩]
    (elemsMatch_of (by
      show [XS.bnd, D2.bnd, DY.bnd] = _
      rw [hD2b, hDY, linElem_bnd]; simp only [List.map]; rw [hQY, hPY]; rfl))
    _ (by limbs_tac [hXS, hDY, hSX]) hc24
  set SXP := mkElem _ _ (sub_red_fits hSXb hPX) with hSXP
  set SYP := linElem [(1, SY), (1, PY)] with hSYP
  have c32 := CheckPolynomial_32_h03b2b1ec_sound hl [⟨8, DY⟩, ⟨8, SXP⟩, ⟨8, SYP⟩, ⟨8, DX⟩]
    (elemsMatch_of (by
      show [DY.bnd, SXP.bnd, SYP.bnd, DX.bnd] = _
      rw [hDY, hSYP, linElem_bnd, linElem_bnd]; simp only [List.map]; rw [hQY, hPY]; rfl))
    _ (by limbs_tac [hDY, hSXP, hSYP, hDX, hSX, hSY]) hc32
  refine ⟨SX, SY, rfl, rfl, ?_, ?_⟩
  · convert hk using 3
    · apply List.Vector.toList_injective
      limbs_tac [hSX]
    · apply List.Vector.toList_injective
      limbs_tac [hSY]
  · have m24 : (cert_h85e25851.m : ℤ) = p := rfl
    have m32 : (cert_h03b2b1ec.m : ℤ) = p := rfl
    have ml : (lazy_h12f7d03a.m : ℤ) = p := rfl
    rw [m24] at c24
    rw [m32] at c32
    rw [ml] at hD2v
    have x24 : cert_h85e25851.exprValue (values [⟨8, XS⟩, ⟨8, D2⟩, ⟨8, DY⟩]) =
        XS.value * D2.value - DY.value * DY.value := by
      simp [PolyShape.exprValue, values, cert_h85e25851]; ring
    have x32 : cert_h03b2b1ec.exprValue (values [⟨8, DY⟩, ⟨8, SXP⟩, ⟨8, SYP⟩, ⟨8, DX⟩]) =
        DY.value * SXP.value + SYP.value * DX.value := by
      simp [PolyShape.exprValue, values, cert_h03b2b1ec]
    have xl : lazy_h12f7d03a.exprValue (values [⟨8, DX⟩]) = DX.value * DX.value := by
      simp [PolyShape.exprValue, values, lazy_h12f7d03a]
    rw [x24] at c24
    rw [x32] at c32
    rw [xl] at hD2v
    have vXS : XS.value = SX.value + PX.value + QX.value := by
      rw [hXS, mkElem_value, rec8_add, rec8_add, ← SX.value_eq, ← PX.value_eq, ← QX.value_eq]
    have vDY : DY.value = QY.value - PY.value := by rw [hDY, linElem_value]; simp; try ring
    have vDX : DX.value = QX.value - PX.value := by
      rw [hDX, mkElem_value, rec8_sub, ← QX.value_eq, ← PX.value_eq]
    have vSXP : SXP.value = SX.value - PX.value := by
      rw [hSXP, mkElem_value, rec8_sub, ← SX.value_eq, ← PX.value_eq]
    have vSYP : SYP.value = SY.value + PY.value := by rw [hSYP, linElem_value]; simp; try ring
    rw [modEq_p_iff] at c24 c32 hD2v
    push_cast [vXS, vDY, vDX, vSXP, vSYP] at c24 c32 hD2v
    constructor
    · rw [modEq_p_iff]
      push_cast
      linear_combination c24 - (SX.value + PX.value + QX.value : Fp) * hD2v
    · rw [modEq_p_iff]
      push_cast
      linear_combination c32

theorem sel_limb_of {b : Bool} {c a e w : F} {A B : ElemVal 8} {i : Fin 8} (hc : c = if b then 1 else 0)
    (hw : w = e - c * (e - a)) (ha : a = A.limbs.get i) (he : e = B.limbs.get i) :
    w = (selElem b A B).limbs.get i := by
  rw [hw, selElem_limb, ← hc, ha, he]

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

/-- The ladder's closing relation: the last row plus `3R` must equal the target
`3R + (1 - d)R + (1 - n)Q`, assembled from `F = 3R + R`, the `d`-selected
`T1`, the `n`-selected addend `D` and `G = D + T1`. -/
theorem ladder_close {Q R T A0 A E F T1 D G : P} {a c dq dr : ℤ} {i : Fin 16} (b1 b2 : Bool)
    (hinv : A0 = a • Q + c • R) (hA : A = 4 • A0 + (Ladder.rowPoint i Q R + T))
    (hd : Ladder.digQ i = dq ∧ Ladder.digR i = dr) (hT : 3 • R = T) (hE : E = A)
    (hF : F = T + R) (hT1 : T1 = if b2 then T else F) (hD : D = if b1 then R else Q)
    (hG : G = D + T1) (hfin : E = if b1 then T1 else G) :
    (4 * a + dq + (if b1 then 1 else 0) - 1) • Q + (4 * c + dr + (if b2 then 1 else 0) - 1) • R = 0 := by
  rw [Ladder.row_point Q R i i.2, hd.1, hd.2] at hA
  subst hinv hE hF hT1 hD hG hT hA
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

/-- Transport a continuation along limb lists, without unfolding either side. -/
theorem k_of_limbs {k : List.Vector (List.Vector F 8) 2 → Prop} {A B A' B' : List.Vector F 8}
    (h : k (A ::ᵥ B ::ᵥ List.Vector.nil)) (hA : A'.toList = A.toList) (hB : B'.toList = B.toList) :
    k (A' ::ᵥ B' ::ᵥ List.Vector.nil) := by
  rw [List.Vector.toList_injective hA, List.Vector.toList_injective hB]
  exact h

end ZolanaVE.P256
