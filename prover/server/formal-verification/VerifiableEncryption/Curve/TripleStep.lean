import VerifiableEncryption.Curve.QuadStep

/-!
The extracted `curve.triple` gadgets: a tangent, then the return slope
`r - l` with `r·(x - xd) = 2y`, evaluated to reduced coordinates.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

/-- The constraints of `curve.triple` over `Fp`, as `triple` consumes them. -/
structure TripleCons (x y x3 y3 l xd r : Fp) : Prop where
  tangent : 2 * l * y = 3 * x ^ 2 - 3
  dx : xd = l ^ 2 - 2 * x
  ratio : r * (x - xd) = 2 * y
  ex3 : x3 = (r - l) ^ 2 - x - xd
  ey3 : y3 = (r - l) * (x - x3) - y

theorem triple_h2c0228bb_sound (hl : LookupSound RangeCheck 11) (X Y : ElemVal 8)
    (hX : X.bnd = reducedC) (hY : Y.bnd = reducedC) {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : Triple_8_8_h2c0228bb X.limbs Y.limbs k) :
    ∃ X3 Y3 : ElemVal 8, X3.bnd = reducedC ∧ Y3.bnd = reducedC ∧
      k (X3.limbs ::ᵥ Y3.limbs ::ᵥ List.Vector.nil) ∧
      ∃ l xd r : Fp, TripleCons (X.value : Fp) (Y.value : Fp) (X3.value : Fp) (Y3.value : Fp) l xd r := by
  unfold Triple_8_8_h2c0228bb Triple_8_8_h2c0228bb_p1 at h
  elim_gates h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc1, h⟩ := h
  have hp1 : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp1) with hL
  have c1 := CheckPolynomial_32_h35a4bc86_sound hl [⟨8, L⟩, ⟨8, Y⟩, ⟨8, X⟩, ⟨8, aElem⟩]
    (elemsMatch_of (by show [L.bnd, Y.bnd, X.bnd, aElem.bnd] = _; rw [hY, hX]; rfl)) _
    (by limbs_tac [hL, aElem, aLimbs]) hc1
  obtain ⟨D, hDlo, hDhi, hDvlo, hDvhi, h, vD⟩ :=
    Lazy_16_h30893ad5_sound [⟨8, L⟩, ⟨8, X⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd] = _; rw [hX]; rfl)) _ (by limbs_tac [hL]) h
  have hDb := lazy_bnd hDlo hDhi hDvlo hDvhi
  clear hDlo hDhi hDvlo hDvhi
  elim_gates h
  obtain ⟨g132, g133, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17,
    r18, r19, r20, r21, r22, r23, hc2, h⟩ := h
  have hp2 : ∀ i : Fin 8, PieceRC g133 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set R := mkElem _ _ (bal_fits hl hp2) with hR
  set XmD := linElem [(1, X), (-1, D)] with hXmD
  set Y2 := linElem [(2, Y)] with hY2
  have c2 := CheckPolynomial_24_h6ce7114d_sound hl [⟨8, R⟩, ⟨8, XmD⟩, ⟨8, Y2⟩]
    (elemsMatch_of (by
      show [R.bnd, XmD.bnd, Y2.bnd] = _
      rw [hXmD, hY2, linElem_bnd, linElem_bnd]; simp only [List.map]; rw [hX, hDb, hY]; rfl))
    _ (by limbs_tac [hR, hXmD, hY2]) hc2
  set RS := linElem [(1, R), (-1, L)] with hRS
  obtain ⟨X3, hX3lo, hX3hi, hX3vlo, hX3vhi, h, vX3⟩ :=
    CheckPolynomial_24_h38fe3d8b_sound hl [⟨8, RS⟩, ⟨8, X⟩, ⟨8, D⟩]
      (elemsMatch_of (by
        show [RS.bnd, X.bnd, D.bnd] = _
        rw [hRS, linElem_bnd]; simp only [List.map]; rw [hX, hDb]; rfl))
      _ (by limbs_tac [hRS, hR, hL]) h
  have hX3b := eval_bnd hX3lo hX3hi hX3vlo hX3vhi rfl
  clear hX3lo hX3hi hX3vlo hX3vhi
  elim_gates h
  set XmX3 := linElem [(1, X), (-1, X3)] with hXmX3
  obtain ⟨Y3, hY3lo, hY3hi, hY3vlo, hY3vhi, h, vY3⟩ :=
    CheckPolynomial_24_ha082c489_sound hl [⟨8, RS⟩, ⟨8, XmX3⟩, ⟨8, Y⟩]
      (elemsMatch_of (by
        show [RS.bnd, XmX3.bnd, Y.bnd] = _
        rw [hRS, hXmX3, linElem_bnd, linElem_bnd]; simp only [List.map]; rw [hX, hX3b, hY]; rfl))
      _ (by limbs_tac [hRS, hR, hL, hXmX3]) h
  have hY3b := eval_bnd hY3lo hY3hi hY3vlo hY3vhi rfl
  clear hY3lo hY3hi hY3vlo hY3vhi
  refine ⟨X3, Y3, hX3b, hY3b, by convert h using 2, L.value, D.value, R.value, ?_⟩
  have e1 : cert_h35a4bc86.exprValue (values [⟨8, L⟩, ⟨8, Y⟩, ⟨8, X⟩, ⟨8, aElem⟩]) =
      2 * (L.value * Y.value) - 3 * (X.value * X.value) - aElem.value := by
    simp [PolyShape.exprValue, values, cert_h35a4bc86]; ring
  have e2 : lazy_h30893ad5.exprValue (values [⟨8, L⟩, ⟨8, X⟩]) = L.value * L.value - 2 * X.value := by
    simp [PolyShape.exprValue, values, lazy_h30893ad5]; ring
  have e3 : cert_h6ce7114d.exprValue (values [⟨8, R⟩, ⟨8, XmD⟩, ⟨8, Y2⟩]) = R.value * XmD.value - Y2.value := by
    simp [PolyShape.exprValue, values, cert_h6ce7114d]; ring
  have e4 : cert_h38fe3d8b.exprValue (values [⟨8, RS⟩, ⟨8, X⟩, ⟨8, D⟩]) =
      RS.value * RS.value - X.value - D.value := by
    simp [PolyShape.exprValue, values, cert_h38fe3d8b]; ring
  have e5 : cert_ha082c489.exprValue (values [⟨8, RS⟩, ⟨8, XmX3⟩, ⟨8, Y⟩]) =
      RS.value * XmX3.value - Y.value := by
    simp [PolyShape.exprValue, values, cert_ha082c489]; ring
  have m1 : (cert_h35a4bc86.m : ℤ) = p := rfl
  have m2 : (lazy_h30893ad5.m : ℤ) = p := rfl
  have m3 : (cert_h6ce7114d.m : ℤ) = p := rfl
  have m4 : (cert_h38fe3d8b.m : ℤ) = p := rfl
  have m5 : (cert_ha082c489.m : ℤ) = p := rfl
  rw [e1, m1, modEq_p_iff] at c1
  rw [e2, m2, modEq_p_iff] at vD
  rw [e3, m3, modEq_p_iff] at c2
  rw [e4, m4, modEq_p_iff] at vX3
  rw [e5, m5, modEq_p_iff] at vY3
  have va : ((aElem.value : ℤ) : Fp) = -3 := by
    rw [aElem_value]; push_cast; rw [ZMod.natCast_self]; ring
  have vXmD : XmD.value = X.value - D.value := by rw [hXmD, linElem_value]; simp; try ring
  have vY2 : Y2.value = 2 * Y.value := by rw [hY2, linElem_value]; simp
  have vRS : RS.value = R.value - L.value := by rw [hRS, linElem_value]; simp; try ring
  have vXmX3 : XmX3.value = X.value - X3.value := by rw [hXmX3, linElem_value]; simp; try ring
  rw [vXmD, vY2] at c2
  rw [vRS] at vX3 vY3
  rw [vXmX3] at vY3
  push_cast at c1 vD c2 vX3 vY3
  rw [va] at c1
  exact ⟨by linear_combination c1, by linear_combination vD, by linear_combination c2,
    by linear_combination vX3, by linear_combination vY3⟩

theorem triple_hffcb8921_sound (hl : LookupSound RangeCheck 11) (X Y : ElemVal 8)
    (hX : X.bnd = reducedC) (hY : Y.bnd = selC) {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : Triple_8_8_hffcb8921 X.limbs Y.limbs k) :
    ∃ X3 Y3 : ElemVal 8, X3.bnd = reducedC ∧ Y3.bnd = reducedC ∧
      k (X3.limbs ::ᵥ Y3.limbs ::ᵥ List.Vector.nil) ∧
      ∃ l xd r : Fp, TripleCons (X.value : Fp) (Y.value : Fp) (X3.value : Fp) (Y3.value : Fp) l xd r := by
  unfold Triple_8_8_hffcb8921 Triple_8_8_hffcb8921_p1 at h
  elim_gates h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc1, h⟩ := h
  have hp1 : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp1) with hL
  have c1 := CheckPolynomial_32_h8cfcaa46_sound hl [⟨8, L⟩, ⟨8, Y⟩, ⟨8, X⟩, ⟨8, aElem⟩]
    (elemsMatch_of (by show [L.bnd, Y.bnd, X.bnd, aElem.bnd] = _; rw [hY, hX]; rfl)) _
    (by limbs_tac [hL, aElem, aLimbs]) hc1
  obtain ⟨D, hDlo, hDhi, hDvlo, hDvhi, h, vD⟩ :=
    Lazy_16_h30893ad5_sound [⟨8, L⟩, ⟨8, X⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd] = _; rw [hX]; rfl)) _ (by limbs_tac [hL]) h
  have hDb := lazy_bnd hDlo hDhi hDvlo hDvhi
  clear hDlo hDhi hDvlo hDvhi
  elim_gates h
  obtain ⟨g132, g133, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17,
    r18, r19, r20, r21, r22, r23, hc2, h⟩ := h
  have hp2 : ∀ i : Fin 8, PieceRC g133 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set R := mkElem _ _ (bal_fits hl hp2) with hR
  set XmD := linElem [(1, X), (-1, D)] with hXmD
  set Y2 := linElem [(2, Y)] with hY2
  have c2 := CheckPolynomial_24_h6a3ed603_sound hl [⟨8, R⟩, ⟨8, XmD⟩, ⟨8, Y2⟩]
    (elemsMatch_of (by
      show [R.bnd, XmD.bnd, Y2.bnd] = _
      rw [hXmD, hY2, linElem_bnd, linElem_bnd]; simp only [List.map]; rw [hX, hDb, hY]; rfl))
    _ (by limbs_tac [hR, hXmD, hY2]) hc2
  set RS := linElem [(1, R), (-1, L)] with hRS
  obtain ⟨X3, hX3lo, hX3hi, hX3vlo, hX3vhi, h, vX3⟩ :=
    CheckPolynomial_24_h38fe3d8b_sound hl [⟨8, RS⟩, ⟨8, X⟩, ⟨8, D⟩]
      (elemsMatch_of (by
        show [RS.bnd, X.bnd, D.bnd] = _
        rw [hRS, linElem_bnd]; simp only [List.map]; rw [hX, hDb]; rfl))
      _ (by limbs_tac [hRS, hR, hL]) h
  have hX3b := eval_bnd hX3lo hX3hi hX3vlo hX3vhi rfl
  clear hX3lo hX3hi hX3vlo hX3vhi
  elim_gates h
  set XmX3 := linElem [(1, X), (-1, X3)] with hXmX3
  obtain ⟨Y3, hY3lo, hY3hi, hY3vlo, hY3vhi, h, vY3⟩ :=
    CheckPolynomial_24_h70dd0288_sound hl [⟨8, RS⟩, ⟨8, XmX3⟩, ⟨8, Y⟩]
      (elemsMatch_of (by
        show [RS.bnd, XmX3.bnd, Y.bnd] = _
        rw [hRS, hXmX3, linElem_bnd, linElem_bnd]; simp only [List.map]; rw [hX, hX3b, hY]; rfl))
      _ (by limbs_tac [hRS, hR, hL, hXmX3]) h
  have hY3b := eval_bnd hY3lo hY3hi hY3vlo hY3vhi rfl
  clear hY3lo hY3hi hY3vlo hY3vhi
  refine ⟨X3, Y3, hX3b, hY3b, by convert h using 2, L.value, D.value, R.value, ?_⟩
  have e1 : cert_h8cfcaa46.exprValue (values [⟨8, L⟩, ⟨8, Y⟩, ⟨8, X⟩, ⟨8, aElem⟩]) =
      2 * (L.value * Y.value) - 3 * (X.value * X.value) - aElem.value := by
    simp [PolyShape.exprValue, values, cert_h8cfcaa46]; ring
  have e2 : lazy_h30893ad5.exprValue (values [⟨8, L⟩, ⟨8, X⟩]) = L.value * L.value - 2 * X.value := by
    simp [PolyShape.exprValue, values, lazy_h30893ad5]; ring
  have e3 : cert_h6a3ed603.exprValue (values [⟨8, R⟩, ⟨8, XmD⟩, ⟨8, Y2⟩]) = R.value * XmD.value - Y2.value := by
    simp [PolyShape.exprValue, values, cert_h6a3ed603]; ring
  have e4 : cert_h38fe3d8b.exprValue (values [⟨8, RS⟩, ⟨8, X⟩, ⟨8, D⟩]) =
      RS.value * RS.value - X.value - D.value := by
    simp [PolyShape.exprValue, values, cert_h38fe3d8b]; ring
  have e5 : cert_h70dd0288.exprValue (values [⟨8, RS⟩, ⟨8, XmX3⟩, ⟨8, Y⟩]) =
      RS.value * XmX3.value - Y.value := by
    simp [PolyShape.exprValue, values, cert_h70dd0288]; ring
  have m1 : (cert_h8cfcaa46.m : ℤ) = p := rfl
  have m2 : (lazy_h30893ad5.m : ℤ) = p := rfl
  have m3 : (cert_h6a3ed603.m : ℤ) = p := rfl
  have m4 : (cert_h38fe3d8b.m : ℤ) = p := rfl
  have m5 : (cert_h70dd0288.m : ℤ) = p := rfl
  rw [e1, m1, modEq_p_iff] at c1
  rw [e2, m2, modEq_p_iff] at vD
  rw [e3, m3, modEq_p_iff] at c2
  rw [e4, m4, modEq_p_iff] at vX3
  rw [e5, m5, modEq_p_iff] at vY3
  have va : ((aElem.value : ℤ) : Fp) = -3 := by
    rw [aElem_value]; push_cast; rw [ZMod.natCast_self]; ring
  have vXmD : XmD.value = X.value - D.value := by rw [hXmD, linElem_value]; simp; try ring
  have vY2 : Y2.value = 2 * Y.value := by rw [hY2, linElem_value]; simp
  have vRS : RS.value = R.value - L.value := by rw [hRS, linElem_value]; simp; try ring
  have vXmX3 : XmX3.value = X.value - X3.value := by rw [hXmX3, linElem_value]; simp; try ring
  rw [vXmD, vY2] at c2
  rw [vRS] at vX3 vY3
  rw [vXmX3] at vY3
  push_cast at c1 vD c2 vX3 vY3
  rw [va] at c1
  exact ⟨by linear_combination c1, by linear_combination vD, by linear_combination c2,
    by linear_combination vX3, by linear_combination vY3⟩

theorem halfTangentSlope_sound (hl : LookupSound RangeCheck 11) (X Y : ElemVal 8)
    (hX : X.bnd = reducedC) (hY : Y.bnd = reducedC) {k : List.Vector F 8 → Prop}
    (h : HalfTangentSlope_8_8_h2c0228bb X.limbs Y.limbs k) :
    ∃ L : ElemVal 8, L.bnd = balC ∧ k L.limbs ∧
      halfQuartic (X.value : Fp) (Y.value : Fp) (L.value : Fp) = 0 := by
  unfold HalfTangentSlope_8_8_h2c0228bb at h
  elim_gates h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, h⟩ := h
  have hp1 : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp1) with hL
  obtain ⟨S, hSlo, hShi, hSvlo, hSvhi, h, vS⟩ :=
    Lazy_8_h158c056f_sound [⟨8, L⟩] (elemsMatch_of rfl) _ (by limbs_tac [hL]) h
  have hSb := lazy_bnd hSlo hShi hSvlo hSvhi
  clear hSlo hShi hSvlo hSvhi
  elim_gates h
  obtain ⟨hc, hk⟩ := h
  have c := CheckPolynomial_40_h0930c075_sound hl [⟨8, S⟩, ⟨8, X⟩, ⟨8, L⟩, ⟨8, Y⟩, ⟨8, aElem⟩]
    (elemsMatch_of (by show [S.bnd, X.bnd, L.bnd, Y.bnd, aElem.bnd] = _; rw [hSb, hX, hY]; rfl))
    _ (by limbs_tac [hL, aElem, aLimbs]) hc
  refine ⟨L, rfl, by convert hk using 1; apply List.Vector.toList_injective; limbs_tac [hL], ?_⟩
  have e1 : lazy_h158c056f.exprValue (values [⟨8, L⟩]) = L.value * L.value := by
    simp [PolyShape.exprValue, values, lazy_h158c056f]
  have e2 : cert_h0930c075.exprValue (values [⟨8, S⟩, ⟨8, X⟩, ⟨8, L⟩, ⟨8, Y⟩, ⟨8, aElem⟩]) =
      S.value * S.value - 6 * (S.value * X.value) - 8 * (L.value * Y.value) - 3 * (X.value * X.value) -
        4 * aElem.value := by
    simp [PolyShape.exprValue, values, cert_h0930c075]; ring
  have m1 : (lazy_h158c056f.m : ℤ) = p := rfl
  have m2 : (cert_h0930c075.m : ℤ) = p := rfl
  rw [e1, m1, modEq_p_iff] at vS
  rw [e2, m2, modEq_p_iff] at c
  have va : ((aElem.value : ℤ) : Fp) = -3 := by
    rw [aElem_value]; push_cast; rw [ZMod.natCast_self]; ring
  push_cast at vS c
  rw [va] at c
  unfold halfQuartic
  rw [vS] at c
  linear_combination c

end ZolanaVE.P256
