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

end ZolanaVE.P256
