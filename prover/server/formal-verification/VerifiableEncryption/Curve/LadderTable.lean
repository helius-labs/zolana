import VerifiableEncryption.Curve.LadderAux

/-!
The packed ladder table and one quadruple-and-add step through a lookup.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

/-- Idealised soundness of the packed ladder table lookup: the returned row is
the row at the index. -/
def RowLookupSound : Prop :=
  ∀ (rows : List.Vector (List.Vector F 12) 16) (idx : F) (k : List.Vector F 12 → Prop),
    RowLookup_12_16 rows idx k → ∃ i : Fin 16, idx = ((i : ℕ) : F) ∧ k (rows.get i)

/-- A table row encodes the point `T`: x limbs, the three packed y groups,
and a native half slope `hs`; `hq` is a half slope of `T` itself, `±hs`. -/
def RowOK (r : List.Vector F 12) (T : P) : Prop :=
  ∃ (X Y : ElemVal 8) (hXY : OnCurve (X.value : Fp) (Y.value : Fp)) (hs hq : ℤ),
    X.bnd = reducedC ∧ Y.bnd = unpackC ∧
    (r.get 0 ::ᵥ r.get 1 ::ᵥ r.get 2 ::ᵥ r.get 3 ::ᵥ r.get 4 ::ᵥ r.get 5 ::ᵥ r.get 6 ::ᵥ r.get 7 ::ᵥ
      List.Vector.nil) = X.limbs ∧
    (r.get 8 ::ᵥ (0 : F) ::ᵥ (0 : F) ::ᵥ r.get 9 ::ᵥ (0 : F) ::ᵥ (0 : F) ::ᵥ r.get 10 ::ᵥ (0 : F) ::ᵥ
      List.Vector.nil) = Y.limbs ∧
    r.get 11 = ((hs : ℤ) : F) ∧ |hs| < p ∧ (hq = hs ∨ hq = -hs) ∧
    halfQuartic (X.value : Fp) (Y.value : Fp) (hq : Fp) = 0 ∧ mkPoint hXY = T

def TableOK (rows : List.Vector (List.Vector F 12) 16) (Q R : P) : Prop :=
  ∀ i : Fin 16, RowOK (rows.get i) (Ladder.rowPoint i Q R)

theorem ladder_step_h320f0a4e (hl : LookupSound RangeCheck 11) (hr : RowLookupSound)
    {rows : List.Vector (List.Vector F 12) 16} {Q R : P} (ht : TableOK rows Q R)
    (AX AY : ElemVal 8) (hAX : AX.bnd = lazyOut lazy_h9c68f146) (hAY : AY.bnd = lazyOut lazy_hee995b41)
    (hA : OnCurve (AX.value : Fp) (AY.value : Fp)) {idx : F}
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : RowLookup_12_16 rows idx fun r =>
      QuadrupleAndAddLazy_8_8_8_8_h320f0a4e AX.limbs AY.limbs
        (r.get 0 ::ᵥ r.get 1 ::ᵥ r.get 2 ::ᵥ r.get 3 ::ᵥ r.get 4 ::ᵥ r.get 5 ::ᵥ r.get 6 ::ᵥ r.get 7 ::ᵥ
          List.Vector.nil)
        (r.get 8 ::ᵥ (0 : F) ::ᵥ (0 : F) ::ᵥ r.get 9 ::ᵥ (0 : F) ::ᵥ (0 : F) ::ᵥ r.get 10 ::ᵥ (0 : F) ::ᵥ
          List.Vector.nil) (r.get 11) k) :
    ∃ i : Fin 16, idx = ((i : ℕ) : F) ∧ ∃ OX OY : ElemVal 8,
      OX.bnd = lazyOut lazy_h9c68f146 ∧ OY.bnd = lazyOut lazy_hee995b41 ∧
      k (OX.limbs ::ᵥ OY.limbs ::ᵥ List.Vector.nil) ∧
      ∃ hO : OnCurve (OX.value : Fp) (OY.value : Fp),
        mkPoint hO = 4 • mkPoint hA + Ladder.rowPoint i Q R := by
  obtain ⟨i, hi, hk⟩ := hr _ _ _ h
  obtain ⟨X, Y, hXY, hs, hq, hXb, hYb, hxl, hyl, hhs, hlt, hqs, hquart, hpt⟩ := ht i
  rw [hxl, hyl, hhs] at hk
  obtain ⟨OX, OY, hOX, hOY, hk', L, hLb, gs, dX, dY, μ, ν, iX, c⟩ :=
    quadAdd_h320f0a4e_sound hl AX AY X Y hAX hAY hXb hYb hk
  have hne := distinctSlope_guard (q := Order) (bal_value_lt hLb) hlt gs
  have hne' : (L.value : Fp) ≠ (hq : Fp) ∧ (L.value : Fp) ≠ -(hq : Fp) := by
    rcases hqs with rfl | rfl
    · exact hne
    · push_cast; exact ⟨hne.2, by rw [neg_neg]; exact hne.1⟩
  obtain ⟨hD, hDeq⟩ := tangent_double hA c.tangent c.dx c.dy
  have hx := step_guard hA (by linear_combination c.tangent) hXY hquart hne' hD hDeq
  obtain ⟨hO, hOeq⟩ := quad_add_correct hA hXY c (Or.inl hx)
  exact ⟨i, hi, OX, OY, hOX, hOY, hk', hO, by rw [hOeq, hpt]⟩

theorem ladder_step_he10e6061 (hl : LookupSound RangeCheck 11) (hr : RowLookupSound)
    {rows : List.Vector (List.Vector F 12) 16} {Q R : P} (ht : TableOK rows Q R)
    (AX AY : ElemVal 8) (hAX : AX.bnd = reducedC) (hAY : AY.bnd = reducedC)
    (hA : OnCurve (AX.value : Fp) (AY.value : Fp)) {idx : F}
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : RowLookup_12_16 rows idx fun r =>
      QuadrupleAndAddLazy_8_8_8_8_he10e6061 AX.limbs AY.limbs
        (r.get 0 ::ᵥ r.get 1 ::ᵥ r.get 2 ::ᵥ r.get 3 ::ᵥ r.get 4 ::ᵥ r.get 5 ::ᵥ r.get 6 ::ᵥ r.get 7 ::ᵥ
          List.Vector.nil)
        (r.get 8 ::ᵥ (0 : F) ::ᵥ (0 : F) ::ᵥ r.get 9 ::ᵥ (0 : F) ::ᵥ (0 : F) ::ᵥ r.get 10 ::ᵥ (0 : F) ::ᵥ
          List.Vector.nil) (r.get 11) k) :
    ∃ i : Fin 16, idx = ((i : ℕ) : F) ∧ ∃ OX OY : ElemVal 8,
      OX.bnd = lazyOut lazy_h9c68f146 ∧ OY.bnd = lazyOut lazy_h57fc266d ∧
      k (OX.limbs ::ᵥ OY.limbs ::ᵥ List.Vector.nil) ∧
      ∃ hO : OnCurve (OX.value : Fp) (OY.value : Fp),
        mkPoint hO = 4 • mkPoint hA + Ladder.rowPoint i Q R := by
  obtain ⟨i, hi, hk⟩ := hr _ _ _ h
  obtain ⟨X, Y, hXY, hs, hq, hXb, hYb, hxl, hyl, hhs, hlt, hqs, hquart, hpt⟩ := ht i
  rw [hxl, hyl, hhs] at hk
  obtain ⟨OX, OY, hOX, hOY, hk', L, hLb, gs, dX, dY, μ, ν, iX, c⟩ :=
    quadAdd_he10e6061_sound hl AX AY X Y hAX hAY hXb hYb hk
  have hne := distinctSlope_guard (q := Order) (bal_value_lt hLb) hlt gs
  have hne' : (L.value : Fp) ≠ (hq : Fp) ∧ (L.value : Fp) ≠ -(hq : Fp) := by
    rcases hqs with rfl | rfl
    · exact hne
    · push_cast; exact ⟨hne.2, by rw [neg_neg]; exact hne.1⟩
  obtain ⟨hD, hDeq⟩ := tangent_double hA c.tangent c.dx c.dy
  have hx := step_guard hA (by linear_combination c.tangent) hXY hquart hne' hD hDeq
  obtain ⟨hO, hOeq⟩ := quad_add_correct hA hXY c (Or.inl hx)
  exact ⟨i, hi, OX, OY, hOX, hOY, hk', hO, by rw [hOeq, hpt]⟩

theorem ladder_step_h8a920ea3 (hl : LookupSound RangeCheck 11) (hr : RowLookupSound)
    {rows : List.Vector (List.Vector F 12) 16} {Q R : P} (ht : TableOK rows Q R)
    (AX AY : ElemVal 8) (hAX : AX.bnd = lazyOut lazy_h9c68f146) (hAY : AY.bnd = lazyOut lazy_h57fc266d)
    (hA : OnCurve (AX.value : Fp) (AY.value : Fp)) {idx : F}
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : RowLookup_12_16 rows idx fun r =>
      QuadrupleAndAddLazy_8_8_8_8_h8a920ea3 AX.limbs AY.limbs
        (r.get 0 ::ᵥ r.get 1 ::ᵥ r.get 2 ::ᵥ r.get 3 ::ᵥ r.get 4 ::ᵥ r.get 5 ::ᵥ r.get 6 ::ᵥ r.get 7 ::ᵥ
          List.Vector.nil)
        (r.get 8 ::ᵥ (0 : F) ::ᵥ (0 : F) ::ᵥ r.get 9 ::ᵥ (0 : F) ::ᵥ (0 : F) ::ᵥ r.get 10 ::ᵥ (0 : F) ::ᵥ
          List.Vector.nil) (r.get 11) k) :
    ∃ i : Fin 16, idx = ((i : ℕ) : F) ∧ ∃ OX OY : ElemVal 8,
      OX.bnd = lazyOut lazy_h9c68f146 ∧ OY.bnd = lazyOut lazy_hee995b41 ∧
      k (OX.limbs ::ᵥ OY.limbs ::ᵥ List.Vector.nil) ∧
      ∃ hO : OnCurve (OX.value : Fp) (OY.value : Fp),
        mkPoint hO = 4 • mkPoint hA + Ladder.rowPoint i Q R := by
  obtain ⟨i, hi, hk⟩ := hr _ _ _ h
  obtain ⟨X, Y, hXY, hs, hq, hXb, hYb, hxl, hyl, hhs, hlt, hqs, hquart, hpt⟩ := ht i
  rw [hxl, hyl, hhs] at hk
  obtain ⟨OX, OY, hOX, hOY, hk', L, hLb, gs, dX, dY, μ, ν, iX, c⟩ :=
    quadAdd_h8a920ea3_sound hl AX AY X Y hAX hAY hXb hYb hk
  have hne := distinctSlope_guard (q := Order) (bal_value_lt hLb) hlt gs
  have hne' : (L.value : Fp) ≠ (hq : Fp) ∧ (L.value : Fp) ≠ -(hq : Fp) := by
    rcases hqs with rfl | rfl
    · exact hne
    · push_cast; exact ⟨hne.2, by rw [neg_neg]; exact hne.1⟩
  obtain ⟨hD, hDeq⟩ := tangent_double hA c.tangent c.dx c.dy
  have hx := step_guard hA (by linear_combination c.tangent) hXY hquart hne' hD hDeq
  obtain ⟨hO, hOeq⟩ := quad_add_correct hA hXY c (Or.inl hx)
  exact ⟨i, hi, OX, OY, hOX, hOY, hk', hO, by rw [hOeq, hpt]⟩

theorem unpackC_eq : unpackC = ⟨[-(2 ^ 96 - 1), 0, 0, -(2 ^ 96 - 1), 0, 0, -(2 ^ 64 - 1), 0],
    [2 ^ 96 - 1, 0, 0, 2 ^ 96 - 1, 0, 0, 2 ^ 64 - 1, 0], -(2 ^ 256 - 1), 2 ^ 256 - 1⟩ := rfl

/-- `curve.packedY` of `s·y` for a reduced `y`, spread back to eight limbs. -/
def packInts (s : ℤ) (Y : ElemVal 8) (j : Fin 8) : ℤ :=
  s * [Y.ints.get 0 + 2 ^ 32 * Y.ints.get 1 + 2 ^ 64 * Y.ints.get 2, 0, 0,
    Y.ints.get 3 + 2 ^ 32 * Y.ints.get 4 + 2 ^ 64 * Y.ints.get 5, 0, 0, Y.ints.get 6 + 2 ^ 32 * Y.ints.get 7, 0].getD j 0

theorem rec8_packInts (s : ℤ) (Y : ElemVal 8) : rec8 (packInts s Y) = s * Y.value := by
  rw [Y.value_eq]
  simp only [rec8, packInts, Fin.coe_ofNat_eq_mod, Nat.reduceMod, Fin.val_zero, List.getD_cons_succ,
    List.getD_cons_zero]
  ring

theorem unpack_fits {Y : ElemVal 8} (hY : Y.bnd = reducedC) {s : ℤ} (hs : s = 1 ∨ s = -1) :
    Fits (packInts s Y) unpackC := by
  have l0 := uni_limb hY 0; have l1 := uni_limb hY 1; have l2 := uni_limb hY 2; have l3 := uni_limb hY 3
  have l4 := uni_limb hY 4; have l5 := uni_limb hY 5; have l6 := uni_limb hY 6; have l7 := uni_limb hY 7
  have hv := uni_value hY
  rw [unpackC_eq]
  refine ⟨rfl, rfl, fun j => ?_, ?_, ?_⟩
  · fin_cases j <;>
      simp only [packInts, Fin.coe_ofNat_eq_mod, Nat.reduceMod, Fin.val_zero, List.getD_cons_succ,
        List.getD_cons_zero, Fin.mk_zero, Fin.zero_eta, Fin.isValue, Fin.mk_one] <;>
      norm_num at * <;>
      rcases hs with rfl | rfl <;> constructor <;> nlinarith
  · rw [rec8_packInts]; rcases hs with rfl | rfl <;> norm_num at hv ⊢ <;> linarith
  · rw [rec8_packInts]; rcases hs with rfl | rfl <;> norm_num at hv ⊢ <;> linarith

theorem halfQuartic_neg (X Y h : Fp) : halfQuartic X (-Y) (-h) = halfQuartic X Y h := by
  unfold halfQuartic; ring

/-- A row built from a slot point, its half slope, and the row sign `s`. -/
theorem rowOK_of {X Y H : ElemVal 8} (hX : X.bnd = reducedC) (hY : Y.bnd = reducedC) (hH : H.bnd = balC)
    (hon : OnCurve (X.value : Fp) (Y.value : Fp)) (hq : halfQuartic (X.value : Fp) (Y.value : Fp) (H.value : Fp) = 0)
    {s : ℤ} (hs : s = 1 ∨ s = -1) {r : List.Vector F 12}
    (hr0 : (r.get 0 ::ᵥ r.get 1 ::ᵥ r.get 2 ::ᵥ r.get 3 ::ᵥ r.get 4 ::ᵥ r.get 5 ::ᵥ r.get 6 ::ᵥ r.get 7 ::ᵥ
      List.Vector.nil) = X.limbs)
    (hr8 : r.get 8 = ((packInts s Y 0 : ℤ) : F)) (hr9 : r.get 9 = ((packInts s Y 3 : ℤ) : F))
    (hr10 : r.get 10 = ((packInts s Y 6 : ℤ) : F)) (hr11 : r.get 11 = ((H.value : ℤ) : F)) {T : P}
    (hT : s = 1 → mkPoint hon = T) (hT' : s = -1 → -mkPoint hon = T) : RowOK r T := by
  set U := mkElem _ _ (unpack_fits hY hs) with hU
  have hUv : U.value = s * Y.value := by rw [hU, mkElem_value, rec8_packInts]
  have hUon : OnCurve (X.value : Fp) (U.value : Fp) := by
    unfold OnCurve at hon ⊢
    rw [hUv]; push_cast
    rcases hs with rfl | rfl
    · push_cast; linear_combination hon
    · push_cast; linear_combination hon
  refine ⟨X, U, hUon, H.value, s * H.value, hX, rfl, hr0, ?_, hr11, bal_value_lt hH, ?_, ?_, ?_⟩
  · apply List.Vector.toList_injective
    rw [vec8_toList U.limbs]
    simp only [List.Vector.toList_cons, List.Vector.toList_nil, hU, mkElem_limb, hr8, hr9, hr10, packInts,
      Fin.coe_ofNat_eq_mod, Nat.reduceMod, Fin.val_zero, List.getD_cons_succ, List.getD_cons_zero, mul_zero,
      Int.cast_zero]
  · rcases hs with rfl | rfl
    · left; ring
    · right; ring
  · rw [hUv]
    rcases hs with rfl | rfl
    · push_cast; simpa using hq
    · push_cast
      rw [show -(1 : Fp) * (Y.value : Fp) = -(Y.value : Fp) by ring,
        show -(1 : Fp) * (H.value : Fp) = -(H.value : Fp) by ring, halfQuartic_neg]
      exact hq
  · rcases hs with rfl | rfl
    · rw [← hT rfl]; exact mkPoint_inj.mpr ⟨rfl, by rw [hUv]; push_cast; ring⟩
    · rw [← hT' rfl]
      obtain ⟨hn, hne⟩ := neg_mkPoint hon
      rw [hne]; exact mkPoint_inj.mpr ⟨rfl, by rw [hUv]; push_cast; ring⟩

theorem rowOK_of2 {X Y H : ElemVal 8} (hX : X.bnd = reducedC) (hY : Y.bnd = reducedC) (hH : H.bnd = balC)
    (hon : OnCurve (X.value : Fp) (Y.value : Fp)) (hq : halfQuartic (X.value : Fp) (Y.value : Fp) (H.value : Fp) = 0)
    {s : ℤ} (hs : s = 1 ∨ s = -1) {x0 x1 x2 x3 x4 x5 x6 x7 y0 y1 y2 hh : F}
    (hx : (x0 ::ᵥ x1 ::ᵥ x2 ::ᵥ x3 ::ᵥ x4 ::ᵥ x5 ::ᵥ x6 ::ᵥ x7 ::ᵥ List.Vector.nil) = X.limbs)
    (h0 : y0 = ((packInts s Y 0 : ℤ) : F)) (h1 : y1 = ((packInts s Y 3 : ℤ) : F))
    (h2 : y2 = ((packInts s Y 6 : ℤ) : F)) (h3 : hh = ((H.value : ℤ) : F)) {T : P}
    (hT : s = 1 → mkPoint hon = T) (hT' : s = -1 → -mkPoint hon = T) :
    RowOK (x0 ::ᵥ x1 ::ᵥ x2 ::ᵥ x3 ::ᵥ x4 ::ᵥ x5 ::ᵥ x6 ::ᵥ x7 ::ᵥ y0 ::ᵥ y1 ::ᵥ y2 ::ᵥ hh ::ᵥ
      List.Vector.nil) T :=
  rowOK_of (r := x0 ::ᵥ x1 ::ᵥ x2 ::ᵥ x3 ::ᵥ x4 ::ᵥ x5 ::ᵥ x6 ::ᵥ x7 ::ᵥ y0 ::ᵥ y1 ::ᵥ y2 ::ᵥ hh ::ᵥ
    List.Vector.nil) hX hY hH hon hq hs hx h0 h1 h2 h3 hT hT'

/-- `0 + y·(-1)`, the extracted form of `Neg` on one limb. -/
theorem packed_limbs_neg (Y : ElemVal 8) :
    ((packInts (-1) Y 0 : ℤ) : F) = -(Y.limbs.get 0) - Y.limbs.get 1 * 4294967296 - Y.limbs.get 2 * K_390 ∧
    ((packInts (-1) Y 3 : ℤ) : F) = -(Y.limbs.get 3) - Y.limbs.get 4 * 4294967296 - Y.limbs.get 5 * K_390 ∧
    ((packInts (-1) Y 6 : ℤ) : F) = -(Y.limbs.get 6) - Y.limbs.get 7 * 4294967296 := by
  simp only [packInts, ElemVal.limb_eq, K_390, Fin.coe_ofNat_eq_mod, Nat.reduceMod, Fin.val_zero,
    List.getD_cons_succ, List.getD_cons_zero]
  push_cast
  refine ⟨by ring, by ring, by ring⟩

theorem packed_limbs_pos (Y : ElemVal 8) :
    ((packInts 1 Y 0 : ℤ) : F) = Y.limbs.get 0 + Y.limbs.get 1 * 4294967296 + Y.limbs.get 2 * K_390 ∧
    ((packInts 1 Y 3 : ℤ) : F) = Y.limbs.get 3 + Y.limbs.get 4 * 4294967296 + Y.limbs.get 5 * K_390 ∧
    ((packInts 1 Y 6 : ℤ) : F) = Y.limbs.get 6 + Y.limbs.get 7 * 4294967296 := by
  simp only [packInts, ElemVal.limb_eq, K_390, Fin.coe_ofNat_eq_mod, Nat.reduceMod, Fin.val_zero,
    List.getD_cons_succ, List.getD_cons_zero]
  push_cast
  refine ⟨by ring, by ring, by ring⟩

end ZolanaVE.P256
