import VerifiableEncryption.Curve.LadderTable
import VerifiableEncryption.Curve.Ladder

/-!
Soundness of the extracted variable-base scalar multiplication
`ScalarMulChecked` (`ladder.go`).
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem modEq_n_iff {a b : ℤ} : a ≡ b [ZMOD n] ↔ ((a : ℤ) : ZMod n) = ((b : ℤ) : ZMod n) :=
  (ZMod.intCast_eq_intCast_iff a b n).symm

/-- Limbs of `(n + 1)/2`, the inverse of two modulo `n`. -/
def inv2Limbs (i : Fin 8) : ℤ :=
  [2117178025, 2044519777, 3549155138, 3732110678, 4294967295, 2147483647, 2147483648, 2147483647].getD i 0

theorem inv2_spec : rec8 inv2Limbs * 2 ≡ 1 [ZMOD n] := by
  have : rec8 inv2Limbs * 2 = 1 + n := by rfl
  rw [this]
  exact (Int.modEq_iff_dvd.mpr (by simp)).symm

theorem scalarMulChecked_sound (hl : LookupSound RangeCheck 11) (hr : RowLookupSound)
    (PX PY S : ElemVal 8) (hPX : PX.bnd = reducedC) (hPY : PY.bnd = reducedC) (hS : S.bnd = reducedC)
    (hQ : OnCurve (PX.value : Fp) (PY.value : Fp)) {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : ScalarMulChecked_8_8_8_h903d3456 PX.limbs PY.limbs S.limbs k) :
    ∃ RX RY : ElemVal 8, RX.bnd = reducedC ∧ RY.bnd = reducedC ∧
      k (RX.limbs ::ᵥ RY.limbs ::ᵥ List.Vector.nil) ∧
      ∃ hR : OnCurve (RX.value : Fp) (RY.value : Fp), mkPoint hR = S.value • mkPoint hQ := by
  unfold ScalarMulChecked_8_8_8_h903d3456 at h
  obtain ⟨S0, hS0lo, hS0hi, hS0vlo, hS0vhi, h, vS0⟩ :=
    CheckPolynomial_8_h57d6a69c_sound hl [⟨8, S⟩] (elemsMatch_of (by show [S.bnd] = _; rw [hS]; rfl))
      _ (by limbs_tac []) h
  have hS0b := eval_bnd hS0lo hS0hi hS0vlo hS0vhi rfl
  clear hS0lo hS0hi hS0vlo hS0vhi
  elim_gates_shallow h
  obtain ⟨g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
    r19, r20, r21, r22, r23, hc, hlo, hhi, h⟩ := h
  have hcan : AssertCanonical_8_1_hc36017e9 S0.limbs := by
    unfold AssertCanonical_8_1_hc36017e9
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, GatesDef.sub,
      GatesDef.eq, exists_eq_left]
    exact ⟨g1, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18,
      r19, r20, r21, r22, r23, hc, hlo, hhi, trivial⟩
  have hS0can := canonical_gap_n_sound hl S0 (reduced_lohi hS0b) hcan
  clear hcan r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23 hc hlo hhi
  obtain ⟨z1, hz1, z2, hz2, z3, hz3, h⟩ := h
  unfold ScalarMulChecked_8_8_8_h903d3456_p1 at h
  elim_gates_shallow h
  obtain ⟨z4, hz4, z5, hz5, z6, hz6, h⟩ := h
  clear hz1 hz2 hz3 hz4 hz5 hz6
  obtain ⟨H, hHlo, hHhi, hHvlo, hHvhi, h, vH⟩ :=
    CheckPolynomial_16_h93312e5c_sound hl [⟨8, S0⟩, ⟨8, constElem inv2Limbs⟩]
      (elemsMatch_of (by show [S0.bnd, (constElem inv2Limbs).bnd] = _; rw [hS0b]; rfl))
      _ (by limbs_tac [constElem, inv2Limbs]) h
  have hHb := eval_bnd hHlo hHhi hHvlo hHvhi rfl
  clear hHlo hHhi hHvlo hHvhi
  elim_gates_shallow h
  obtain ⟨g261, g262, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17,
    r18, r19, r20, r21, r22, r23, hcT, h⟩ := h
  have hpL : ∀ i : Fin 8, PieceRC g262 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set L := mkElem _ _ (bal_fits hl hpL) with hL
  have cT := CheckPolynomial_32_h35a4bc86_sound hl [⟨8, L⟩, ⟨8, PY⟩, ⟨8, PX⟩, ⟨8, aElem⟩]
    (elemsMatch_of (by show [L.bnd, PY.bnd, PX.bnd, aElem.bnd] = _; rw [hPY, hPX]; rfl)) _
    (by limbs_tac [hL, aElem, aLimbs]) hcT
  obtain ⟨DX, hDXlo, hDXhi, hDXvlo, hDXvhi, h, vDX⟩ :=
    CheckPolynomial_16_h0c8d6bae_sound hl [⟨8, L⟩, ⟨8, PX⟩]
      (elemsMatch_of (by show [L.bnd, PX.bnd] = _; rw [hPX]; rfl)) _ (by limbs_tac [hL]) h
  have hDXb := eval_bnd hDXlo hDXhi hDXvlo hDXvhi rfl
  clear hDXlo hDXhi hDXvlo hDXvhi
  elim_gates_shallow h
  set XmD := linElem [(1, PX), (-1, DX)] with hXmD
  obtain ⟨DY, hDYlo, hDYhi, hDYvlo, hDYvhi, h, vDY⟩ :=
    CheckPolynomial_24_h2629e496_sound hl [⟨8, L⟩, ⟨8, XmD⟩, ⟨8, PY⟩]
      (elemsMatch_of (by
        show [L.bnd, XmD.bnd, PY.bnd] = _
        rw [hXmD, linElem_bnd]; simp only [List.map]; rw [hPX, hDXb, hPY]; rfl))
      _ (by limbs_tac [hL, hXmD]) h
  have hDYb := eval_bnd hDYlo hDYhi hDYvlo hDYvhi rfl
  clear hDYlo hDYhi hDYvlo hDYvhi
  elim_gates_shallow h
  obtain ⟨o0, s0, o1, s1, o2, s2, o3, s3, o4, s4, o5, s5, o6, s6, o7, s7, o8, s8, o9, s9, o10, s10, o11, s11, o12, s12, o13, s13, o14, s14, o15, s15, o16, s16, o17, s17, o18, s18, o19, s19, o20, s20, o21, s21, h⟩ := h
  unfold ScalarMulChecked_8_8_8_h903d3456_p2 at h
  elim_gates_shallow h
  obtain ⟨o22, s22, o23, s23, g402, h⟩ := h
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.select] at s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s21 s22 s23
  obtain ⟨b, hb⟩ := bool_of_is_bool s0.1
  set QX := selElem b DX PX with hQX
  set QY := selElem b DY PY with hQY
  set S1 := selElem b H S0 with hS1
  have e0 : o0 = QX.limbs.get 0 := by rw [s0.2, hQX, selElem_limb, ← hb]
  have e1 : o1 = QX.limbs.get 1 := by rw [s1.2, hQX, selElem_limb, ← hb]
  have e2 : o2 = QX.limbs.get 2 := by rw [s2.2, hQX, selElem_limb, ← hb]
  have e3 : o3 = QX.limbs.get 3 := by rw [s3.2, hQX, selElem_limb, ← hb]
  have e4 : o4 = QX.limbs.get 4 := by rw [s4.2, hQX, selElem_limb, ← hb]
  have e5 : o5 = QX.limbs.get 5 := by rw [s5.2, hQX, selElem_limb, ← hb]
  have e6 : o6 = QX.limbs.get 6 := by rw [s6.2, hQX, selElem_limb, ← hb]
  have e7 : o7 = QX.limbs.get 7 := by rw [s7.2, hQX, selElem_limb, ← hb]
  have e8 : o8 = QY.limbs.get 0 := by rw [s8.2, hQY, selElem_limb, ← hb]
  have e9 : o9 = QY.limbs.get 1 := by rw [s9.2, hQY, selElem_limb, ← hb]
  have e10 : o10 = QY.limbs.get 2 := by rw [s10.2, hQY, selElem_limb, ← hb]
  have e11 : o11 = QY.limbs.get 3 := by rw [s11.2, hQY, selElem_limb, ← hb]
  have e12 : o12 = QY.limbs.get 4 := by rw [s12.2, hQY, selElem_limb, ← hb]
  have e13 : o13 = QY.limbs.get 5 := by rw [s13.2, hQY, selElem_limb, ← hb]
  have e14 : o14 = QY.limbs.get 6 := by rw [s14.2, hQY, selElem_limb, ← hb]
  have e15 : o15 = QY.limbs.get 7 := by rw [s15.2, hQY, selElem_limb, ← hb]
  have e16 : o16 = S1.limbs.get 0 := by rw [s16.2, hS1, selElem_limb, ← hb]
  have e17 : o17 = S1.limbs.get 1 := by rw [s17.2, hS1, selElem_limb, ← hb]
  have e18 : o18 = S1.limbs.get 2 := by rw [s18.2, hS1, selElem_limb, ← hb]
  have e19 : o19 = S1.limbs.get 3 := by rw [s19.2, hS1, selElem_limb, ← hb]
  have e20 : o20 = S1.limbs.get 4 := by rw [s20.2, hS1, selElem_limb, ← hb]
  have e21 : o21 = S1.limbs.get 5 := by rw [s21.2, hS1, selElem_limb, ← hb]
  have e22 : o22 = S1.limbs.get 6 := by rw [s22.2, hS1, selElem_limb, ← hb]
  have e23 : o23 = S1.limbs.get 7 := by rw [s23.2, hS1, selElem_limb, ← hb]
  clear s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s21 s22 s23
  subst e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 e10 e11 e12 e13 e14 e15 e16 e17 e18 e19 e20 e21 e22 e23
  obtain ⟨hbA, h⟩ := boolRun_split (j := 0) (m := 197) (g := g402) h
  obtain ⟨hbB, h⟩ := boolRun_split (j := 197) (m := 62) (g := g402) h
  elim_gates_shallow h
  have hbits : AllBits g402 := by
    intro j hj
    by_cases hj' : j < 197
    · exact hbA j (by omega) (by omega)
    · exact hbB j (by omega) (by omega)
  clear hbA hbB
  obtain ⟨n0, f0, n1, f1, n2, f2, n3, f3, n4, f4, n5, f5, n6, f6, n7, f7, n8, f8, n9, f9, h⟩ := h
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8] at f0 f1 f2 f3 f4 f5 f6 f7 f8 f9
  have fe0 := fromBinary_chunk hbits (a := 1) (w := 32) (by norm_num) rfl f0
  have fe1 := fromBinary_chunk hbits (a := 33) (w := 32) (by norm_num) rfl f1
  have fe2 := fromBinary_chunk hbits (a := 65) (w := 32) (by norm_num) rfl f2
  have fe3 := fromBinary_chunk hbits (a := 97) (w := 32) (by norm_num) rfl f3
  have fe4 := fromBinary_chunk hbits (a := 129) (w := 1) (by norm_num) rfl f4
  have fe5 := fromBinary_chunk hbits (a := 130) (w := 32) (by norm_num) rfl f5
  have fe6 := fromBinary_chunk hbits (a := 162) (w := 32) (by norm_num) rfl f6
  have fe7 := fromBinary_chunk hbits (a := 194) (w := 32) (by norm_num) rfl f7
  have fe8 := fromBinary_chunk hbits (a := 226) (w := 32) (by norm_num) rfl f8
  have fe9 := fromBinary_chunk hbits (a := 258) (w := 1) (by norm_num) rfl f9
  clear f0 f1 f2 f3 f4 f5 f6 f7 f8 f9
  subst fe0 fe1 fe2 fe3 fe4 fe5 fe6 fe7 fe8 fe9
  obtain ⟨q0, t0, q1, t1, q2, t2, q3, t3, q4, t4, hc18, h⟩ := h
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.select, GatesDef.add, GatesDef.mul] at t0 t1 t2 t3 t4
  obtain ⟨hσb, hσ⟩ := bitI_of_bool (hbits 0 (by norm_num))
  rw [← vget_getD' g402 0 (by norm_num)] at hσ
  have te0 := signed_limb hσ t0.2
  have te1 := signed_limb hσ t1.2
  have te2 := signed_limb hσ t2.2
  have te3 := signed_limb hσ t3.2
  have te4 := signed_limb hσ t4.2
  clear t0 t1 t2 t3 t4
  subst te0 te1 te2 te3 te4
  have hs1 : (1 - 2 * bitI g402 0) = 1 ∨ (1 - 2 * bitI g402 0) = -1 := by rcases hσb with h0 | h0 <;> rw [h0] <;> norm_num
  set SD := mkElem5 _ _ (signed_fits hbits (a := 130) (by norm_num) hs1) with hSD
  set NUM := mkElem5 _ _ (limbs129_fits hbits (g := g402) (a := 1) (by norm_num)) with hNUM
  have c18 := CheckPolynomial_18_hb0ad1306_sound hl [⟨8, S1⟩, ⟨5, SD⟩, ⟨5, NUM⟩]
    (elemsMatch_of (by show [S1.bnd, SD.bnd, NUM.bnd] = _; rw [hS1, selElem_bnd, hHb, hS0b]; rfl))
    _ (by limbs_tac [hSD, hNUM, limbs129]) hc18
  obtain ⟨hne, g690, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r26, r27, r28, r29, r30, r31, r32, r33, r34, r35, r36, h⟩ := h
  unfold ScalarMulChecked_8_8_8_h903d3456_p4 at h
  elim_gates_shallow h
  obtain ⟨r37, r38, r39, r40, r41, r42, r43, r44, r45, r46, r47, h⟩ := h
  have hden : 1 ≤ chunk g402 130 129 := den_pos hbits (a := 130) (w := 129) (by norm_num) (by
    intro h0
    apply hne
    rw [← h0]
    simp only [Finset.sum_range_succ, Finset.sum_range_zero, zero_add, Nat.reduceAdd, Gates, GatesGnark12,
      GatesGnark9, GatesGnark8, GatesDef.add, vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod])
  clear hne
  have hpPX : ∀ i : Fin 8, PieceRC g690 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩, ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩, ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩, ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  have hpPY : ∀ i : Fin 8, PieceRC g690 (24 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r24, rc_getD r25, rc_getD r26⟩, ⟨rc_getD r27, rc_getD r28, rc_getD r29⟩, ⟨rc_getD r30, rc_getD r31, rc_getD r32⟩, ⟨rc_getD r33, rc_getD r34, rc_getD r35⟩, ⟨rc_getD r36, rc_getD r37, rc_getD r38⟩, ⟨rc_getD r39, rc_getD r40, rc_getD r41⟩, ⟨rc_getD r42, rc_getD r43, rc_getD r44⟩, ⟨rc_getD r45, rc_getD r46, rc_getD r47⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23 r24 r25 r26 r27 r28 r29 r30 r31 r32 r33 r34 r35 r36 r37 r38 r39 r40 r41 r42 r43 r44 r45 r46 r47
  set PRX := mkElem _ _ (pieces_fits hl hpPX) with hPRX
  set PRY := mkElem _ _ (pieces_fits hl hpPY) with hPRY
  have hPRXb : PRX.bnd = reducedC := rfl
  have hPRYb : PRY.bnd = reducedC := rfl
  obtain ⟨X2, hX2lo, hX2hi, hX2vlo, hX2vhi, h, vX2⟩ :=
    Lazy_8_h2d947ec4_sound [⟨8, PRX⟩] (elemsMatch_of (by show [PRX.bnd] = _; rw [hPRXb]; rfl))
      _ (by limbs_tac [hPRX]) h
  have hX2b := lazy_bnd hX2lo hX2hi hX2vlo hX2vhi
  clear hX2lo hX2hi hX2vlo hX2vhi
  elim_gates_shallow h
  obtain ⟨hoc, h⟩ := h
  have coc := CheckPolynomial_40_h29707435_sound hl
    [⟨8, X2⟩, ⟨8, PRX⟩, ⟨8, aElem⟩, ⟨8, constElem bLimbs⟩, ⟨8, PRY⟩]
    (elemsMatch_of (by
      show [X2.bnd, PRX.bnd, aElem.bnd, (constElem bLimbs).bnd, PRY.bnd] = _
      rw [hX2b, hPRXb, hPRYb]; rfl))
    _ (by limbs_tac [hPRX, hPRY, aElem, aLimbs, constElem, bLimbs]) hoc
  clear hoc
  have hQXb : QX.bnd = reducedC := by rw [hQX, selElem_bnd, hDXb, hPX]; rfl
  have hQYb : QY.bnd = reducedC := by rw [hQY, selElem_bnd, hDYb, hPY]; rfl
  obtain ⟨T1X, T1Y, hT1X, hT1Y, h, l1, xd1, r1, tc1⟩ :=
    triple_habd58e5e_sound hl QX QY hQXb hQYb (by convert h using 2 <;> exact (vec8_eta _).symm)
  beta_reduce at h
  try simp only [get2_0, get2_1] at h
  elim_gates_shallow h
  obtain ⟨y0, u0, y1, u1, y2, u2, y3, u3, y4, u4, y5, u5, y6, u6, y7, u7, h⟩ := h
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.select, GatesDef.add, GatesDef.mul] at u0 u1 u2 u3 u4 u5 u6 u7
  have ue0 := signed_limb hσ u0.2
  have ue1 := signed_limb hσ u1.2
  have ue2 := signed_limb hσ u2.2
  have ue3 := signed_limb hσ u3.2
  have ue4 := signed_limb hσ u4.2
  have ue5 := signed_limb hσ u5.2
  have ue6 := signed_limb hσ u6.2
  have ue7 := signed_limb hσ u7.2
  clear u0 u1 u2 u3 u4 u5 u6 u7
  set SPY := mkElem _ _ (signed_red_fits hPRYb hs1) with hSPY
  have hSPYb : SPY.bnd = selC := rfl
  have ve0 : y0 = SPY.limbs.get 0 := by
    rw [ue0, hSPY, mkElem_limb]
    simp only [hPRY, mkElem_int]
    simp only [List.Vector.get_eq_get_toList, Fin.coe_ofNat_eq_mod,
      Nat.reduceMod, Nat.reduceMul, Nat.reduceAdd, List.get_eq_getElem, getElem_eq_getD0, Fin.coe_cast,
      Int.cast_mul, Int.cast_sub, pieceInt_cast]
    try ring
  have ve1 : y1 = SPY.limbs.get 1 := by
    rw [ue1, hSPY, mkElem_limb]
    simp only [hPRY, mkElem_int]
    simp only [List.Vector.get_eq_get_toList, Fin.coe_ofNat_eq_mod,
      Nat.reduceMod, Nat.reduceMul, Nat.reduceAdd, List.get_eq_getElem, getElem_eq_getD0, Fin.coe_cast,
      Int.cast_mul, Int.cast_sub, pieceInt_cast]
    try ring
  have ve2 : y2 = SPY.limbs.get 2 := by
    rw [ue2, hSPY, mkElem_limb]
    simp only [hPRY, mkElem_int]
    simp only [List.Vector.get_eq_get_toList, Fin.coe_ofNat_eq_mod,
      Nat.reduceMod, Nat.reduceMul, Nat.reduceAdd, List.get_eq_getElem, getElem_eq_getD0, Fin.coe_cast,
      Int.cast_mul, Int.cast_sub, pieceInt_cast]
    try ring
  have ve3 : y3 = SPY.limbs.get 3 := by
    rw [ue3, hSPY, mkElem_limb]
    simp only [hPRY, mkElem_int]
    simp only [List.Vector.get_eq_get_toList, Fin.coe_ofNat_eq_mod,
      Nat.reduceMod, Nat.reduceMul, Nat.reduceAdd, List.get_eq_getElem, getElem_eq_getD0, Fin.coe_cast,
      Int.cast_mul, Int.cast_sub, pieceInt_cast]
    try ring
  have ve4 : y4 = SPY.limbs.get 4 := by
    rw [ue4, hSPY, mkElem_limb]
    simp only [hPRY, mkElem_int]
    simp only [List.Vector.get_eq_get_toList, Fin.coe_ofNat_eq_mod,
      Nat.reduceMod, Nat.reduceMul, Nat.reduceAdd, List.get_eq_getElem, getElem_eq_getD0, Fin.coe_cast,
      Int.cast_mul, Int.cast_sub, pieceInt_cast]
    try ring
  have ve5 : y5 = SPY.limbs.get 5 := by
    rw [ue5, hSPY, mkElem_limb]
    simp only [hPRY, mkElem_int]
    simp only [List.Vector.get_eq_get_toList, Fin.coe_ofNat_eq_mod,
      Nat.reduceMod, Nat.reduceMul, Nat.reduceAdd, List.get_eq_getElem, getElem_eq_getD0, Fin.coe_cast,
      Int.cast_mul, Int.cast_sub, pieceInt_cast]
    try ring
  have ve6 : y6 = SPY.limbs.get 6 := by
    rw [ue6, hSPY, mkElem_limb]
    simp only [hPRY, mkElem_int]
    simp only [List.Vector.get_eq_get_toList, Fin.coe_ofNat_eq_mod,
      Nat.reduceMod, Nat.reduceMul, Nat.reduceAdd, List.get_eq_getElem, getElem_eq_getD0, Fin.coe_cast,
      Int.cast_mul, Int.cast_sub, pieceInt_cast]
    try ring
  have ve7 : y7 = SPY.limbs.get 7 := by
    rw [ue7, hSPY, mkElem_limb]
    simp only [hPRY, mkElem_int]
    simp only [List.Vector.get_eq_get_toList, Fin.coe_ofNat_eq_mod,
      Nat.reduceMod, Nat.reduceMul, Nat.reduceAdd, List.get_eq_getElem, getElem_eq_getD0, Fin.coe_cast,
      Int.cast_mul, Int.cast_sub, pieceInt_cast]
    try ring
  clear ue0 ue1 ue2 ue3 ue4 ue5 ue6 ue7
  subst ve0 ve1 ve2 ve3 ve4 ve5 ve6 ve7
  obtain ⟨T2X, T2Y, hT2X, hT2Y, h, l2, xd2, r2, tc2⟩ :=
    triple_he2f2b0f5_sound hl PRX SPY hPRXb hSPYb (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac [hPRX]))
  beta_reduce at h
  try simp only [get2_0, get2_1] at h
  elim_gates_shallow h
  obtain ⟨g1d, g2d, g3d, h⟩ := h
  have dg1 := distinctX_elem hPRXb hQXb (by
    convert g1d using 2 <;> (apply List.Vector.toList_injective; limbs_tac [hPRX]))
  have dg2 := distinctX_elem hPRXb hT1X (by
    convert g2d using 2; apply List.Vector.toList_injective; limbs_tac [hPRX])
  have dg3 := distinctX_elem hT2X hQXb (by convert g3d using 2; exact (vec8_eta _).symm)
  clear g1d g2d g3d
  set NSPY := linElem [(-1, SPY)] with hNSPY
  have hNSPYb : NSPY.bnd = selC := by rw [hNSPY, linElem_bnd]; simp only [List.map]; rw [hSPYb]; rfl
  set NT2Y := linElem [(-1, T2Y)] with hNT2Y
  have hNT2Yb : NT2Y.bnd = negRedC := by rw [hNT2Y, linElem_bnd]; simp only [List.map]; rw [hT2Y]; rfl
  obtain ⟨A0X, A0Y, hA0X, hA0Y, h, crA0⟩ :=
    add_he7b90398_sound hl QX QY PRX SPY hQXb hQYb hPRXb hSPYb (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac [hPRX]))
  beta_reduce at h
  try simp only [get2_0, get2_1] at h
  elim_gates_shallow h
  obtain ⟨A1X, A1Y, hA1X, hA1Y, h, crA1⟩ :=
    add_hd2848b17_sound hl T1X T1Y T2X T2Y hT1X hT1Y hT2X hT2Y (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac [hPRX]))
  beta_reduce at h
  try simp only [get2_0, get2_1] at h
  elim_gates_shallow h
  obtain ⟨A2X, A2Y, hA2X, hA2Y, h, crA2⟩ :=
    add_he7b90398_sound hl T1X T1Y PRX SPY hT1X hT1Y hPRXb hSPYb (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac [hPRX]))
  beta_reduce at h
  try simp only [get2_0, get2_1] at h
  elim_gates_shallow h
  obtain ⟨A3X, A3Y, hA3X, hA3Y, h, crA3⟩ :=
    add_hd2848b17_sound hl QX QY T2X T2Y hQXb hQYb hT2X hT2Y (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac [hPRX]))
  beta_reduce at h
  try simp only [get2_0, get2_1] at h
  elim_gates_shallow h
  obtain ⟨A4X, A4Y, hA4X, hA4Y, h, crA4⟩ :=
    add_hc7058f2f_sound hl PRX NSPY QX QY hPRXb hNSPYb hQXb hQYb (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac [hPRX, hNSPY]))
  beta_reduce at h
  try simp only [get2_0, get2_1] at h
  elim_gates_shallow h
  obtain ⟨A5X, A5Y, hA5X, hA5Y, h, crA5⟩ :=
    add_h15bb4ad7_sound hl QX QY T2X NT2Y hQXb hQYb hT2X hNT2Yb (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac [hNT2Y]))
  beta_reduce at h
  try simp only [get2_0, get2_1] at h
  elim_gates_shallow h
  obtain ⟨A6X, A6Y, hA6X, hA6Y, h, crA6⟩ :=
    add_h17455767_sound hl T1X T1Y PRX NSPY hT1X hT1Y hPRXb hNSPYb (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac [hPRX, hNSPY]))
  beta_reduce at h
  try simp only [get2_0, get2_1] at h
  elim_gates_shallow h
  obtain ⟨A7X, A7Y, hA7X, hA7Y, h, crA7⟩ :=
    add_h15bb4ad7_sound hl T1X T1Y T2X NT2Y hT1X hT1Y hT2X hNT2Yb (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac [hNT2Y]))
  beta_reduce at h
  try simp only [get2_0, get2_1] at h
  elim_gates_shallow h
  obtain ⟨HA1, hHA1, h, qHA1⟩ :=
    halfTangentSlope_sound hl A1X A1Y hA1X hA1Y (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac []))
  beta_reduce at h
  elim_gates_shallow h
  obtain ⟨HA5, hHA5, h, qHA5⟩ :=
    halfTangentSlope_sound hl A5X A5Y hA5X hA5Y (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac []))
  beta_reduce at h
  elim_gates_shallow h
  obtain ⟨HA6, hHA6, h, qHA6⟩ :=
    halfTangentSlope_sound hl A6X A6Y hA6X hA6Y (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac []))
  beta_reduce at h
  elim_gates_shallow h
  obtain ⟨HA0, hHA0, h, qHA0⟩ :=
    halfTangentSlope_sound hl A0X A0Y hA0X hA0Y (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac []))
  beta_reduce at h
  elim_gates_shallow h
  obtain ⟨HA3, hHA3, h, qHA3⟩ :=
    halfTangentSlope_sound hl A3X A3Y hA3X hA3Y (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac []))
  beta_reduce at h
  elim_gates_shallow h
  unfold ScalarMulChecked_8_8_8_h903d3456_p5 at h
  elim_gates_shallow h
  obtain ⟨HA7, hHA7, h, qHA7⟩ :=
    halfTangentSlope_sound hl A7X A7Y hA7X hA7Y (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac []))
  beta_reduce at h
  elim_gates_shallow h
  obtain ⟨HA4, hHA4, h, qHA4⟩ :=
    halfTangentSlope_sound hl A4X A4Y hA4X hA4Y (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac []))
  beta_reduce at h
  elim_gates_shallow h
  obtain ⟨HA2, hHA2, h, qHA2⟩ :=
    halfTangentSlope_sound hl A2X A2Y hA2X hA2Y (by
      convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac []))
  beta_reduce at h
  elim_gates_shallow h
  sorry

end ZolanaVE.P256
