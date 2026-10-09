import VerifiableEncryption.Curve.QuadStep

/-!
`combChainStep`: one addition of the fixed-base comb chain, with the
accumulator's y-coordinate implicit in the previous slope.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

/-- Bounds of a selected comb window's packed y-coordinate. -/
def packC : ElemC := cert_hd6f972c2.elems.getD 4 default

/-- The chain relations of one comb step: the slope through the accumulator
and the window point, and the next accumulator x. -/
def ChainRel (x l0 pwx pwy wx wy l nx : ℤ) : Prop :=
  l * (wx - x) + l0 * (pwx - x) - wy - pwy ≡ 0 [ZMOD p] ∧ nx ≡ l * l - x - wx [ZMOD p]

def FirstRel (x wx wy fy l nx : ℤ) : Prop :=
  l * (wx - x) - wy + fy ≡ 0 [ZMOD p] ∧ nx ≡ l * l - x - wx [ZMOD p]

theorem chain_first_sound (hl : LookupSound RangeCheck 11) (X WX WY FY : ElemVal 8) (L0 PWX PWY : List.Vector F 8)
    (hX : X.bnd = reducedC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC) (hFY : FY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h9024d0c7 X.limbs L0 PWX PWY WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h4ef94fb8 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      FirstRel X.value WX.value WY.value FY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h9024d0c7 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  have c := CheckPolynomial_32_hb838cae4_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, WY⟩, ⟨8, FY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, WY.bnd, FY.bnd] = _
      rw [hXD, linElem_bnd]; simp only [List.map]; rw [hWX, hX, hWY, hFY]; rfl))
    _ (by limbs_tac [hL, hXD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h4ef94fb8_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hb838cae4.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, WY⟩, ⟨8, FY⟩]) =
        L.value * XD.value - WY.value + FY.value := by
      simp [PolyShape.exprValue, values, cert_hb838cae4]; try ring
    have m : (cert_hb838cae4.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    rw [e, m, vXD] at c
    exact c
  · have e : lazy_h4ef94fb8.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h4ef94fb8]; try ring
    have m : (lazy_h4ef94fb8.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h88ed5eb6_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h4ef94fb8) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h88ed5eb6 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h33616364 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h88ed5eb6 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hd6f972c2_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h33616364_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hd6f972c2.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hd6f972c2]; try ring
    have m : (cert_hd6f972c2.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h33616364.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h33616364]; try ring
    have m : (lazy_h33616364.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_he7f12bd4_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h33616364) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_he7f12bd4 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h5d959345 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_he7f12bd4 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hc3b7913d_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h5d959345_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hc3b7913d.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hc3b7913d]; try ring
    have m : (cert_hc3b7913d.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h5d959345.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h5d959345]; try ring
    have m : (lazy_h5d959345.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_hbc88b2dd_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h5d959345) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_hbc88b2dd X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h8bca4322 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_hbc88b2dd at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h7eb5af1f_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h8bca4322_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h7eb5af1f.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h7eb5af1f]; try ring
    have m : (cert_h7eb5af1f.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h8bca4322.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h8bca4322]; try ring
    have m : (lazy_h8bca4322.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_haea263e9_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h8bca4322) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_haea263e9 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_hda13b782 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_haea263e9 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hf93ee67b_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_hda13b782_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hf93ee67b.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hf93ee67b]; try ring
    have m : (cert_hf93ee67b.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_hda13b782.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_hda13b782]; try ring
    have m : (lazy_hda13b782.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h0ecbf3f5_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_hda13b782) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h0ecbf3f5 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h4c46916d ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h0ecbf3f5 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h2d2e868f_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h4c46916d_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h2d2e868f.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h2d2e868f]; try ring
    have m : (cert_h2d2e868f.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h4c46916d.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h4c46916d]; try ring
    have m : (lazy_h4c46916d.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h16349f87_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h4c46916d) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h16349f87 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h70433ddf ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h16349f87 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h4d342646_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h70433ddf_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h4d342646.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h4d342646]; try ring
    have m : (cert_h4d342646.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h70433ddf.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h70433ddf]; try ring
    have m : (lazy_h70433ddf.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h0148019b_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h70433ddf) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h0148019b X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h8fbed755 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h0148019b at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_haca3f4dc_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h8fbed755_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_haca3f4dc.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_haca3f4dc]; try ring
    have m : (cert_haca3f4dc.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h8fbed755.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h8fbed755]; try ring
    have m : (lazy_h8fbed755.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_hd915f581_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h8fbed755) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_hd915f581 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_heb19166d ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_hd915f581 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hd333f47e_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_heb19166d_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hd333f47e.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hd333f47e]; try ring
    have m : (cert_hd333f47e.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_heb19166d.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_heb19166d]; try ring
    have m : (lazy_heb19166d.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_ha5ae99c0_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_heb19166d) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_ha5ae99c0 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_hd5ac7c2a ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_ha5ae99c0 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hd7b2dad1_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_hd5ac7c2a_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hd7b2dad1.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hd7b2dad1]; try ring
    have m : (cert_hd7b2dad1.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_hd5ac7c2a.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_hd5ac7c2a]; try ring
    have m : (lazy_hd5ac7c2a.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h27ce7ca2_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_hd5ac7c2a) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h27ce7ca2 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_hdc687f01 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h27ce7ca2 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h7383b54d_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_hdc687f01_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h7383b54d.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h7383b54d]; try ring
    have m : (cert_h7383b54d.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_hdc687f01.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_hdc687f01]; try ring
    have m : (lazy_hdc687f01.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h0c822e8d_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_hdc687f01) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h0c822e8d X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h183e6a3f ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h0c822e8d at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h5c23f74c_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h183e6a3f_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h5c23f74c.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h5c23f74c]; try ring
    have m : (cert_h5c23f74c.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h183e6a3f.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h183e6a3f]; try ring
    have m : (lazy_h183e6a3f.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h92d08b28_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h183e6a3f) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h92d08b28 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_hde720dec ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h92d08b28 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h8a16b201_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_hde720dec_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h8a16b201.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h8a16b201]; try ring
    have m : (cert_h8a16b201.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_hde720dec.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_hde720dec]; try ring
    have m : (lazy_hde720dec.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h8d70b631_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_hde720dec) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h8d70b631 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_hca4d82bd ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h8d70b631 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h568cde94_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_hca4d82bd_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h568cde94.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h568cde94]; try ring
    have m : (cert_h568cde94.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_hca4d82bd.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_hca4d82bd]; try ring
    have m : (lazy_hca4d82bd.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h313874e4_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_hca4d82bd) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h313874e4 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_hb31eb938 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h313874e4 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h21655805_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_hb31eb938_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h21655805.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h21655805]; try ring
    have m : (cert_h21655805.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_hb31eb938.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_hb31eb938]; try ring
    have m : (lazy_hb31eb938.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h013650f7_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_hb31eb938) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h013650f7 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h0b39a3e2 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h013650f7 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hc39fa5c0_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h0b39a3e2_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hc39fa5c0.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hc39fa5c0]; try ring
    have m : (cert_hc39fa5c0.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h0b39a3e2.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h0b39a3e2]; try ring
    have m : (lazy_h0b39a3e2.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h7edcb8cc_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h0b39a3e2) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h7edcb8cc X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h81cfec0e ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h7edcb8cc at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hb7d22aff_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h81cfec0e_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hb7d22aff.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hb7d22aff]; try ring
    have m : (cert_hb7d22aff.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h81cfec0e.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h81cfec0e]; try ring
    have m : (lazy_h81cfec0e.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h1eb7ded7_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h81cfec0e) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h1eb7ded7 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h77f7514c ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h1eb7ded7 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h4114346a_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h77f7514c_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h4114346a.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h4114346a]; try ring
    have m : (cert_h4114346a.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h77f7514c.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h77f7514c]; try ring
    have m : (lazy_h77f7514c.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h3c1f10d2_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h77f7514c) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h3c1f10d2 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_hd23c1321 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h3c1f10d2 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hf3b38897_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_hd23c1321_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hf3b38897.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hf3b38897]; try ring
    have m : (cert_hf3b38897.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_hd23c1321.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_hd23c1321]; try ring
    have m : (lazy_hd23c1321.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_hff713c2b_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_hd23c1321) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_hff713c2b X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h289d8769 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_hff713c2b at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h47951bd5_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h289d8769_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h47951bd5.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h47951bd5]; try ring
    have m : (cert_h47951bd5.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h289d8769.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h289d8769]; try ring
    have m : (lazy_h289d8769.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_ha86afca6_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h289d8769) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_ha86afca6 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_hfd15ca5e ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_ha86afca6 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h43a27c1d_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_hfd15ca5e_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h43a27c1d.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h43a27c1d]; try ring
    have m : (cert_h43a27c1d.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_hfd15ca5e.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_hfd15ca5e]; try ring
    have m : (lazy_hfd15ca5e.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_hbc800f66_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_hfd15ca5e) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_hbc800f66 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h6bcb0ecf ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_hbc800f66 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h2f338a84_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h6bcb0ecf_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h2f338a84.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h2f338a84]; try ring
    have m : (cert_h2f338a84.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h6bcb0ecf.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h6bcb0ecf]; try ring
    have m : (lazy_h6bcb0ecf.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_hc9743c4e_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h6bcb0ecf) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_hc9743c4e X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h70762eb9 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_hc9743c4e at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hb3072cc6_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h70762eb9_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hb3072cc6.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hb3072cc6]; try ring
    have m : (cert_hb3072cc6.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h70762eb9.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h70762eb9]; try ring
    have m : (lazy_h70762eb9.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h5ffe8758_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h70762eb9) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h5ffe8758 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h38e8ac31 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h5ffe8758 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h7395df96_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h38e8ac31_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h7395df96.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h7395df96]; try ring
    have m : (cert_h7395df96.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h38e8ac31.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h38e8ac31]; try ring
    have m : (lazy_h38e8ac31.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h48fdfa88_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h38e8ac31) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h48fdfa88 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_hb9b2a022 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h48fdfa88 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_he6e7e1f6_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_hb9b2a022_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_he6e7e1f6.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_he6e7e1f6]; try ring
    have m : (cert_he6e7e1f6.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_hb9b2a022.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_hb9b2a022]; try ring
    have m : (lazy_hb9b2a022.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h17b219f3_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_hb9b2a022) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h17b219f3 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h40955e83 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h17b219f3 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h211271d3_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h40955e83_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h211271d3.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h211271d3]; try ring
    have m : (cert_h211271d3.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h40955e83.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h40955e83]; try ring
    have m : (lazy_h40955e83.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_hfce0bd8a_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h40955e83) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_hfce0bd8a X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_hf09a21c7 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_hfce0bd8a at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h15ae7c48_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_hf09a21c7_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h15ae7c48.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h15ae7c48]; try ring
    have m : (cert_h15ae7c48.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_hf09a21c7.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_hf09a21c7]; try ring
    have m : (lazy_hf09a21c7.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h73c155f4_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_hf09a21c7) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h73c155f4 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h4972f626 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h73c155f4 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h1fb47175_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h4972f626_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h1fb47175.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h1fb47175]; try ring
    have m : (cert_h1fb47175.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h4972f626.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h4972f626]; try ring
    have m : (lazy_h4972f626.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h5a641a57_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h4972f626) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h5a641a57 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h677e8427 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h5a641a57 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hab90690b_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h677e8427_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hab90690b.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hab90690b]; try ring
    have m : (cert_hab90690b.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h677e8427.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h677e8427]; try ring
    have m : (lazy_h677e8427.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_hccc2fbcb_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h677e8427) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_hccc2fbcb X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_hae8dc535 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_hccc2fbcb at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h49261fcf_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_hae8dc535_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h49261fcf.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h49261fcf]; try ring
    have m : (cert_h49261fcf.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_hae8dc535.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_hae8dc535]; try ring
    have m : (lazy_hae8dc535.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h73c2114e_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_hae8dc535) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h73c2114e X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h0f279e18 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h73c2114e at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h1ce5f55d_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h0f279e18_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h1ce5f55d.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h1ce5f55d]; try ring
    have m : (cert_h1ce5f55d.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h0f279e18.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h0f279e18]; try ring
    have m : (lazy_h0f279e18.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_hf3f31729_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h0f279e18) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_hf3f31729 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h19f9c19c ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_hf3f31729 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h0de4edae_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h19f9c19c_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h0de4edae.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h0de4edae]; try ring
    have m : (cert_h0de4edae.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h19f9c19c.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h19f9c19c]; try ring
    have m : (lazy_h19f9c19c.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h3847f643_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h19f9c19c) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h3847f643 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h311d38f1 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h3847f643 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hf7042422_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h311d38f1_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hf7042422.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hf7042422]; try ring
    have m : (cert_hf7042422.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h311d38f1.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h311d38f1]; try ring
    have m : (lazy_h311d38f1.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_ha3f0c00a_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h311d38f1) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_ha3f0c00a X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_hc65e35fe ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_ha3f0c00a at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h583726ef_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_hc65e35fe_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h583726ef.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h583726ef]; try ring
    have m : (cert_h583726ef.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_hc65e35fe.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_hc65e35fe]; try ring
    have m : (lazy_hc65e35fe.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h9ebf1727_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_hc65e35fe) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h9ebf1727 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h6ef8b49c ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h9ebf1727 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hc20aa839_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h6ef8b49c_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hc20aa839.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hc20aa839]; try ring
    have m : (cert_hc20aa839.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h6ef8b49c.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h6ef8b49c]; try ring
    have m : (lazy_h6ef8b49c.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h5ea40572_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h6ef8b49c) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h5ea40572 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_hc3ec5671 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h5ea40572 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h1512d68a_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_hc3ec5671_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h1512d68a.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h1512d68a]; try ring
    have m : (cert_h1512d68a.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_hc3ec5671.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_hc3ec5671]; try ring
    have m : (lazy_hc3ec5671.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h0a06c13d_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_hc3ec5671) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h0a06c13d X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_hfc273997 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h0a06c13d at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hf0f7cd8d_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_hfc273997_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hf0f7cd8d.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hf0f7cd8d]; try ring
    have m : (cert_hf0f7cd8d.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_hfc273997.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_hfc273997]; try ring
    have m : (lazy_hfc273997.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h6c7272ff_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_hfc273997) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h6c7272ff X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h96360ee1 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h6c7272ff at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_ha3cd1508_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h96360ee1_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_ha3cd1508.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_ha3cd1508]; try ring
    have m : (cert_ha3cd1508.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h96360ee1.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h96360ee1]; try ring
    have m : (lazy_h96360ee1.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h604b5f97_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h96360ee1) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h604b5f97 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h83a415b9 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h604b5f97 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h1a30b6ff_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h83a415b9_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h1a30b6ff.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h1a30b6ff]; try ring
    have m : (cert_h1a30b6ff.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h83a415b9.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h83a415b9]; try ring
    have m : (lazy_h83a415b9.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_hbb6cf05c_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h83a415b9) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_hbb6cf05c X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h3ed7df0f ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_hbb6cf05c at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hd007efc7_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h3ed7df0f_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hd007efc7.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hd007efc7]; try ring
    have m : (cert_hd007efc7.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h3ed7df0f.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h3ed7df0f]; try ring
    have m : (lazy_h3ed7df0f.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h57987298_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h3ed7df0f) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h57987298 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h26631a60 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h57987298 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hd88d777b_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h26631a60_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hd88d777b.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hd88d777b]; try ring
    have m : (cert_hd88d777b.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h26631a60.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h26631a60]; try ring
    have m : (lazy_h26631a60.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_hc3975dc5_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h26631a60) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_hc3975dc5 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h8e929349 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_hc3975dc5 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h033dac5a_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h8e929349_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h033dac5a.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h033dac5a]; try ring
    have m : (cert_h033dac5a.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h8e929349.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h8e929349]; try ring
    have m : (lazy_h8e929349.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_hc2b6f687_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h8e929349) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_hc2b6f687 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h2fd0ed5d ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_hc2b6f687 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h5c7e4971_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h2fd0ed5d_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h5c7e4971.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h5c7e4971]; try ring
    have m : (cert_h5c7e4971.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h2fd0ed5d.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h2fd0ed5d]; try ring
    have m : (lazy_h2fd0ed5d.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h4074c487_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h2fd0ed5d) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h4074c487 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h6f54b8b1 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h4074c487 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h5220a672_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h6f54b8b1_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h5220a672.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h5220a672]; try ring
    have m : (cert_h5220a672.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h6f54b8b1.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h6f54b8b1]; try ring
    have m : (lazy_h6f54b8b1.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h15643c52_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h6f54b8b1) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h15643c52 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_he088c588 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h15643c52 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_he98b9e85_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_he088c588_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_he98b9e85.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_he98b9e85]; try ring
    have m : (cert_he98b9e85.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_he088c588.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_he088c588]; try ring
    have m : (lazy_he088c588.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_hb370f239_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_he088c588) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_hb370f239 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_hcc322c7b ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_hb370f239 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h58fa9890_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_hcc322c7b_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h58fa9890.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h58fa9890]; try ring
    have m : (cert_h58fa9890.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_hcc322c7b.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_hcc322c7b]; try ring
    have m : (lazy_hcc322c7b.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_h65e467d3_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_hcc322c7b) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_h65e467d3 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h4e5489d2 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_h65e467d3 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hbfd40503_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h4e5489d2_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hbfd40503.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hbfd40503]; try ring
    have m : (cert_hbfd40503.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h4e5489d2.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h4e5489d2]; try ring
    have m : (lazy_h4e5489d2.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_hf49d9647_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h4e5489d2) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_hf49d9647 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_he1cc16ce ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_hf49d9647 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_hb81b755e_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_he1cc16ce_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_hb81b755e.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_hb81b755e]; try ring
    have m : (cert_hb81b755e.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_he1cc16ce.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_he1cc16ce]; try ring
    have m : (lazy_he1cc16ce.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_hf1b4e4e3_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_he1cc16ce) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_hf1b4e4e3 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h636a42b5 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_hf1b4e4e3 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h0d0f0b6d_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h636a42b5_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h0d0f0b6d.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h0d0f0b6d]; try ring
    have m : (cert_h0d0f0b6d.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h636a42b5.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h636a42b5]; try ring
    have m : (lazy_h636a42b5.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

theorem chain_hb2920079_sound (hl : LookupSound RangeCheck 11) (X L0 PWX PWY WX WY FY : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h636a42b5) (hL0 : L0.bnd = balC) (hPWX : PWX.bnd = reducedC)
    (hPWY : PWY.bnd = packC) (hWX : WX.bnd = reducedC) (hWY : WY.bnd = packC)
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CombChainStep_8_8_8_8_8_8_8_hb2920079 X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs FY.limbs k) :
    ∃ NX L : ElemVal 8, NX.bnd = lazyOut lazy_h7e1bb4d8 ∧ L.bnd = balC ∧
      k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) ∧
      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value := by
  unfold CombChainStep_8_8_8_8_8_8_8_hb2920079 at h
  elim_gates_shallow h
  obtain ⟨g0, g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, h⟩ := h
  have hp : ∀ i : Fin 8, PieceRC g1 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, WX), (-1, X)] with hXD
  set PD := linElem [(1, PWX), (-1, X)] with hPD
  have c := CheckPolynomial_48_h1f40fdb3_sound hl [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, L0.bnd, PD.bnd, WY.bnd, PWY.bnd] = _
      rw [hXD, hPD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hWX, hX, hL0, hPWX, hWY, hPWY]; rfl))
    _ (by limbs_tac [hL, hXD, hPD]) hc
  obtain ⟨NX, hlo, hhi, hvlo, hvhi, hk, vNX⟩ :=
    Lazy_24_h7e1bb4d8_sound [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
      (elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hX, hWX]; rfl))
      _ (by limbs_tac [hL]) h
  refine ⟨NX, L, lazy_bnd hlo hhi hvlo hvhi, rfl, ?_, ?_, ?_⟩
  · convert hk using 3
    apply List.Vector.toList_injective
    limbs_tac [hL]
  · have e : cert_h1f40fdb3.exprValue (values [⟨8, L⟩, ⟨8, XD⟩, ⟨8, L0⟩, ⟨8, PD⟩, ⟨8, WY⟩, ⟨8, PWY⟩]) =
        L.value * XD.value + L0.value * PD.value - WY.value - PWY.value := by
      simp [PolyShape.exprValue, values, cert_h1f40fdb3]; try ring
    have m : (cert_h1f40fdb3.m : ℤ) = p := rfl
    have vXD : XD.value = WX.value - X.value := by rw [hXD, linElem_value]; simp; try ring
    have vPD : PD.value = PWX.value - X.value := by rw [hPD, linElem_value]; simp; try ring
    rw [e, m, vXD, vPD] at c
    exact c
  · have e : lazy_h7e1bb4d8.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
        L.value * L.value - X.value - WX.value := by
      simp [PolyShape.exprValue, values, lazy_h7e1bb4d8]; try ring
    have m : (lazy_h7e1bb4d8.m : ℤ) = p := rfl
    rw [e, m] at vNX
    exact vNX

end ZolanaVE.P256
