import VerifiableEncryption.Curve.LadderTable
import VerifiableEncryption.Curve.Slots
import VerifiableEncryption.Curve.LadderEnd
import VerifiableEncryption.Curve.LadderRun
import VerifiableEncryption.Curve.AuxLemma
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
  obtain ⟨g1, r0, r1, r2, r3, r4, r5, r6, h⟩ := h
  obtain ⟨r7, r8, r9, r10, r11, r12, r13, r14, h⟩ := h
  obtain ⟨r15, r16, r17, r18, r19, r20, r21, r22, h⟩ := h
  obtain ⟨r23, hc, hlo, hhi, h⟩ := h
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
  obtain ⟨g261, g262, r0, r1, r2, r3, r4, r5, h⟩ := h
  obtain ⟨r6, r7, r8, r9, r10, r11, r12, r13, h⟩ := h
  obtain ⟨r14, r15, r16, r17, r18, r19, r20, r21, h⟩ := h
  obtain ⟨r22, r23, hcT, h⟩ := h
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
  obtain ⟨o0, s0, o1, s1, o2, s2, o3, s3, h⟩ := h
  obtain ⟨o4, s4, o5, s5, o6, s6, o7, s7, h⟩ := h
  obtain ⟨o8, s8, o9, s9, o10, s10, o11, s11, h⟩ := h
  obtain ⟨o12, s12, o13, s13, o14, s14, o15, s15, h⟩ := h
  obtain ⟨o16, s16, o17, s17, o18, s18, o19, s19, h⟩ := h
  obtain ⟨o20, s20, o21, s21, h⟩ := h
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
  obtain ⟨n0, f0, n1, f1, n2, f2, n3, f3, h⟩ := h
  obtain ⟨n4, f4, n5, f5, n6, f6, n7, f7, h⟩ := h
  obtain ⟨n8, f8, n9, f9, h⟩ := h
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
  obtain ⟨q0, t0, q1, t1, q2, t2, q3, t3, h⟩ := h
  obtain ⟨q4, t4, hc18, h⟩ := h
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
  obtain ⟨hne, g690, r0, r1, r2, r3, r4, r5, h⟩ := h
  obtain ⟨r6, r7, r8, r9, r10, r11, r12, r13, h⟩ := h
  obtain ⟨r14, r15, r16, r17, r18, r19, r20, r21, h⟩ := h
  obtain ⟨r22, r23, r24, r25, r26, r27, r28, r29, h⟩ := h
  obtain ⟨r30, r31, r32, r33, r34, r35, r36, h⟩ := h
  unfold ScalarMulChecked_8_8_8_h903d3456_p4 at h
  aux_lemma =>
    elim_gates_shallow h
    obtain ⟨r37, r38, r39, r40, r41, r42, r43, r44, h⟩ := h
    obtain ⟨r45, r46, r47, h⟩ := h
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
    try simp only [get2_0, get2_1] at h
    elim_gates_shallow h
    obtain ⟨y0, u0, y1, u1, y2, u2, y3, u3, h⟩ := h
    obtain ⟨y4, u4, y5, u5, y6, u6, y7, u7, h⟩ := h
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
        convert h using 2; apply List.Vector.toList_injective; limbs_tac [hPRX])
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
    try simp only [get2_0, get2_1] at h
    elim_gates_shallow h
    obtain ⟨A1X, A1Y, hA1X, hA1Y, h, crA1⟩ :=
      add_hd2848b17_sound hl T1X T1Y T2X T2Y hT1X hT1Y hT2X hT2Y (by
        convert h using 2)
    try simp only [get2_0, get2_1] at h
    elim_gates_shallow h
    obtain ⟨A2X, A2Y, hA2X, hA2Y, h, crA2⟩ :=
      add_he7b90398_sound hl T1X T1Y PRX SPY hT1X hT1Y hPRXb hSPYb (by
        convert h using 2; apply List.Vector.toList_injective; limbs_tac [hPRX])
    try simp only [get2_0, get2_1] at h
    elim_gates_shallow h
    obtain ⟨A3X, A3Y, hA3X, hA3Y, h, crA3⟩ :=
      add_hd2848b17_sound hl QX QY T2X T2Y hQXb hQYb hT2X hT2Y (by
        convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac [hPRX]))
    try simp only [get2_0, get2_1] at h
    elim_gates_shallow h
    obtain ⟨A4X, A4Y, hA4X, hA4Y, h, crA4⟩ :=
      add_hc7058f2f_sound hl PRX NSPY QX QY hPRXb hNSPYb hQXb hQYb (by
        convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac [hPRX, hNSPY]))
    try simp only [get2_0, get2_1] at h
    elim_gates_shallow h
    obtain ⟨A5X, A5Y, hA5X, hA5Y, h, crA5⟩ :=
      add_h15bb4ad7_sound hl QX QY T2X NT2Y hQXb hQYb hT2X hNT2Yb (by
        convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac [hNT2Y]))
    try simp only [get2_0, get2_1] at h
    elim_gates_shallow h
    obtain ⟨A6X, A6Y, hA6X, hA6Y, h, crA6⟩ :=
      add_h17455767_sound hl T1X T1Y PRX NSPY hT1X hT1Y hPRXb hNSPYb (by
        convert h using 2 <;> (apply List.Vector.toList_injective; limbs_tac [hPRX, hNSPY]))
    try simp only [get2_0, get2_1] at h
    elim_gates_shallow h
    obtain ⟨A7X, A7Y, hA7X, hA7Y, h, crA7⟩ :=
      add_h15bb4ad7_sound hl T1X T1Y T2X NT2Y hT1X hT1Y hT2X hNT2Yb (by
        convert h using 2; apply List.Vector.toList_injective; limbs_tac [hNT2Y])
    try simp only [get2_0, get2_1] at h
    elim_gates_shallow h
    obtain ⟨HA1, hHA1, h, qHA1⟩ :=
      halfTangentSlope_sound hl A1X A1Y hA1X hA1Y (by
        convert h using 2)
    elim_gates_shallow h
    obtain ⟨HA5, hHA5, h, qHA5⟩ :=
      halfTangentSlope_sound hl A5X A5Y hA5X hA5Y (by
        convert h using 2)
    elim_gates_shallow h
    obtain ⟨HA6, hHA6, h, qHA6⟩ :=
      halfTangentSlope_sound hl A6X A6Y hA6X hA6Y (by
        convert h using 2)
    elim_gates_shallow h
    obtain ⟨HA0, hHA0, h, qHA0⟩ :=
      halfTangentSlope_sound hl A0X A0Y hA0X hA0Y (by
        convert h using 2)
    elim_gates_shallow h
    obtain ⟨HA3, hHA3, h, qHA3⟩ :=
      halfTangentSlope_sound hl A3X A3Y hA3X hA3Y (by
        convert h using 2)
    elim_gates_shallow h
    unfold ScalarMulChecked_8_8_8_h903d3456_p5 at h
    aux_lemma =>
      elim_gates_shallow h
      obtain ⟨HA7, hHA7, h, qHA7⟩ :=
        halfTangentSlope_sound hl A7X A7Y hA7X hA7Y (by
          convert h using 2)
      elim_gates_shallow h
      obtain ⟨HA4, hHA4, h, qHA4⟩ :=
        halfTangentSlope_sound hl A4X A4Y hA4X hA4Y (by
          convert h using 2)
      elim_gates_shallow h
      obtain ⟨HA2, hHA2, h, qHA2⟩ :=
        halfTangentSlope_sound hl A2X A2Y hA2X hA2Y (by
          convert h using 2)
      elim_gates_shallow h
      have va : ((aElem.value : ℤ) : Fp) = -3 := by
        rw [aElem_value]; push_cast; rw [ZMod.natCast_self]; ring
      have vb : ((constElem bLimbs).value : Fp) = ((ZolanaVE.P256.b : ℕ) : Fp) := by rw [bConst_value]; push_cast; rfl
      have eT : cert_h35a4bc86.exprValue (values [⟨8, L⟩, ⟨8, PY⟩, ⟨8, PX⟩, ⟨8, aElem⟩]) =
          2 * (L.value * PY.value) - 3 * (PX.value * PX.value) - aElem.value := by
        simp [PolyShape.exprValue, values, cert_h35a4bc86]; ring
      have eDX : cert_h0c8d6bae.exprValue (values [⟨8, L⟩, ⟨8, PX⟩]) = L.value * L.value - 2 * PX.value := by
        simp [PolyShape.exprValue, values, cert_h0c8d6bae]; ring
      have eDY : cert_h2629e496.exprValue (values [⟨8, L⟩, ⟨8, XmD⟩, ⟨8, PY⟩]) = L.value * XmD.value - PY.value := by
        simp [PolyShape.exprValue, values, cert_h2629e496]; ring
      have eX2 : lazy_h2d947ec4.exprValue (values [⟨8, PRX⟩]) = PRX.value * PRX.value := by
        simp [PolyShape.exprValue, values, lazy_h2d947ec4]
      have eoc : cert_h29707435.exprValue
          (values [⟨8, X2⟩, ⟨8, PRX⟩, ⟨8, aElem⟩, ⟨8, constElem bLimbs⟩, ⟨8, PRY⟩]) =
          X2.value * PRX.value + aElem.value * PRX.value + (constElem bLimbs).value - PRY.value * PRY.value := by
        simp [PolyShape.exprValue, values, cert_h29707435]; ring
      have mT : (cert_h35a4bc86.m : ℤ) = p := rfl
      have mDX : (cert_h0c8d6bae.m : ℤ) = p := rfl
      have mDY : (cert_h2629e496.m : ℤ) = p := rfl
      have mX2 : (lazy_h2d947ec4.m : ℤ) = p := rfl
      have moc : (cert_h29707435.m : ℤ) = p := rfl
      rw [eT, mT, modEq_p_iff] at cT
      rw [eDX, mDX, modEq_p_iff] at vDX
      rw [eDY, mDY, modEq_p_iff] at vDY
      rw [eX2, mX2, modEq_p_iff] at vX2
      rw [eoc, moc, modEq_p_iff] at coc
      have vXmD : XmD.value = PX.value - DX.value := by rw [hXmD, linElem_value]; simp; try ring
      rw [vXmD] at vDY
      push_cast at cT vDX vDY vX2 coc
      rw [va] at cT coc
      rw [vb] at coc
      obtain ⟨hDon, hDeq⟩ := tangent_double (x := (PX.value : Fp)) (y := (PY.value : Fp)) (l := (L.value : Fp))
        (xd := (DX.value : Fp)) (yd := (DY.value : Fp)) hQ (by linear_combination cT)
        (by linear_combination vDX) (by linear_combination vDY)
      have hQXv : QX.value = if b then DX.value else PX.value := by rw [hQX, selElem_value]
      have hQYv : QY.value = if b then DY.value else PY.value := by rw [hQY, selElem_value]
      have hQ' : OnCurve (QX.value : Fp) (QY.value : Fp) := by
        rw [hQXv, hQYv]; cases b
        · exact hQ
        · exact hDon
      have hQ'pt : mkPoint hQ' = if b then (2 : ℤ) • mkPoint hQ else mkPoint hQ := by
        cases b
        · simp only [Bool.false_eq_true, if_false]; exact mkPoint_inj.mpr ⟨by rw [hQXv]; rfl, by rw [hQYv]; rfl⟩
        · simp only [if_true]
          rw [two_zsmul, ← two_nsmul, hDeq]
          exact mkPoint_inj.mpr ⟨by rw [hQXv]; rfl, by rw [hQYv]; rfl⟩
      have hPRon : OnCurve (PRX.value : Fp) (PRY.value : Fp) := by
        unfold OnCurve; rw [vX2] at coc; linear_combination -coc
      have vSPY : SPY.value = (1 - 2 * bitI g402 0) * PRY.value := by
        rw [hSPY, mkElem_value, rec8_smul, PRY.value_eq]
      have hRon : OnCurve (PRX.value : Fp) (SPY.value : Fp) := by
        have hsq : ((1 - 2 * bitI g402 0 : ℤ) : Fp) ^ 2 = 1 := by
          rcases hs1 with h1 | h1 <;> rw [h1] <;> norm_num
        unfold OnCurve at hPRon ⊢
        rw [vSPY]; push_cast
        push_cast at hsq
        linear_combination (PRY.value : Fp) ^ 2 * hsq + hPRon
      obtain ⟨hT1on, hT1eq⟩ := triple hQ' tc1.tangent tc1.dx tc1.ratio tc1.ex3 tc1.ey3
      obtain ⟨hT2on, hT2eq⟩ := triple hRon tc2.tangent tc2.dx tc2.ratio tc2.ex3 tc2.ey3
      have g1 := (x_ne_iff hRon hQ').mp dg1.2.2.2.2
      have g2 := (x_ne_iff hRon hT1on).mp dg2.2.2.2.2
      have g3 := (x_ne_iff hT2on hQ').mp dg3.2.2.2.2
      rw [← hT1eq] at g2
      rw [← hT2eq] at g3
      have xQR : (QX.value : Fp) ≠ (PRX.value : Fp) := fun he => dg1.2.2.2.2 he.symm
      have xT1R : (T1X.value : Fp) ≠ (PRX.value : Fp) := fun he => dg2.2.2.2.2 he.symm
      have xQT2 : (QX.value : Fp) ≠ (T2X.value : Fp) := fun he => dg3.2.2.2.2 he.symm
      have g1' : mkPoint hQ' ≠ mkPoint hRon ∧ mkPoint hQ' ≠ -mkPoint hRon :=
        ⟨fun he => g1.1 he.symm, fun he => g1.2 (by rw [he, neg_neg])⟩
      have xT1T2 : (T1X.value : Fp) ≠ (T2X.value : Fp) := by
        rw [x_ne_iff hT1on hT2on, ← hT1eq, ← hT2eq]
        exact three_ne g1'.1 g1'.2
      have vNSPY : NSPY.value = -SPY.value := by rw [hNSPY, linElem_value]; simp
      have vNT2Y : NT2Y.value = -T2Y.value := by rw [hNT2Y, linElem_value]; simp
      have hNRon : OnCurve (PRX.value : Fp) (NSPY.value : Fp) := by
        unfold OnCurve at hRon ⊢; rw [vNSPY]; push_cast; linear_combination hRon
      have hNT2on : OnCurve (T2X.value : Fp) (NT2Y.value : Fp) := by
        unfold OnCurve at hT2on ⊢; rw [vNT2Y]; push_cast; linear_combination hT2on
      have pNR : mkPoint hNRon = -mkPoint hRon := by
        obtain ⟨hn, hne⟩ := neg_mkPoint hRon
        rw [hne, mkPoint_inj]; exact ⟨rfl, by rw [vNSPY]; push_cast; rfl⟩
      have pNT2 : mkPoint hNT2on = -mkPoint hT2on := by
        obtain ⟨hn, hne⟩ := neg_mkPoint hT2on
        rw [hne, mkPoint_inj]; exact ⟨rfl, by rw [vNT2Y]; push_cast; rfl⟩
      obtain ⟨hA0, pA0⟩ := chord_point hQ' hRon xQR crA0.1 crA0.2
      obtain ⟨hA1, pA1⟩ := chord_point hT1on hT2on xT1T2 crA1.1 crA1.2
      obtain ⟨hA2, pA2⟩ := chord_point hT1on hRon xT1R crA2.1 crA2.2
      obtain ⟨hA3, pA3⟩ := chord_point hQ' hT2on xQT2 crA3.1 crA3.2
      obtain ⟨hA4, pA4⟩ := chord_point hNRon hQ' (fun he => xQR he.symm) crA4.1 crA4.2
      obtain ⟨hA5, pA5⟩ := chord_point hQ' hNT2on xQT2 crA5.1 crA5.2
      obtain ⟨hA6, pA6⟩ := chord_point hT1on hNRon xT1R crA6.1 crA6.2
      obtain ⟨hA7, pA7⟩ := chord_point hT1on hNT2on xT1T2 crA7.1 crA7.2
      rw [pNR] at pA4 pA6
      rw [pNT2] at pA5 pA7
      rw [← hT1eq] at pA1 pA2 pA6 pA7
      rw [← hT2eq] at pA1 pA3 pA5 pA7
      unfold ScalarMulChecked_8_8_8_h903d3456_p6 at h
      aux_lemma =>
        elim_gates_shallow h
        unfold ScalarMulChecked_8_8_8_h903d3456_p7 ScalarMulChecked_8_8_8_h903d3456_p8
          ScalarMulChecked_8_8_8_h903d3456_p9 at h
        elim_gates_shallow h
        try simp only [get2_0, get2_1] at h
        generalize_rows h as rows, hrows
        aux_lemma =>
          have htab : TableOK rows (mkPoint hQ') (mkPoint hRon) := by
            intro i
            fin_cases i
            · rw [← hrows]
              exact rowOK_of2 (s := (-1)) hA1X hA1Y hHA1 hA1 qHA1 (Or.inr rfl) (vec8_eta _)
                (by rw [(packed_limbs_neg _).1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_neg _).2.1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_neg _).2.2]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [value_cast]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (fun h1 => by norm_num at h1) (fun _ => by simp only [Ladder.rowPoint, Ladder.slotPoint]; norm_num; rw [pA1]; try abel)
            · rw [← hrows]
              exact rowOK_of2 (s := 1) hA5X hA5Y hHA5 hA5 qHA5 (Or.inl rfl) (vec8_eta _)
                (by rw [(packed_limbs_pos _).1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_pos _).2.1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_pos _).2.2]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [value_cast]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (fun _ => by simp only [Ladder.rowPoint, Ladder.slotPoint]; norm_num; rw [pA5]; try abel) (fun h1 => by norm_num at h1)
            · rw [← hrows]
              exact rowOK_of2 (s := (-1)) hA6X hA6Y hHA6 hA6 qHA6 (Or.inr rfl) (vec8_eta _)
                (by rw [(packed_limbs_neg _).1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_neg _).2.1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_neg _).2.2]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [value_cast]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (fun h1 => by norm_num at h1) (fun _ => by simp only [Ladder.rowPoint, Ladder.slotPoint]; norm_num; rw [pA6]; try abel)
            · rw [← hrows]
              exact rowOK_of2 (s := 1) hA0X hA0Y hHA0 hA0 qHA0 (Or.inl rfl) (vec8_eta _)
                (by rw [(packed_limbs_pos _).1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_pos _).2.1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_pos _).2.2]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [value_cast]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (fun _ => by simp only [Ladder.rowPoint, Ladder.slotPoint]; norm_num; rw [pA0]; try abel) (fun h1 => by norm_num at h1)
            · rw [← hrows]
              exact rowOK_of2 (s := (-1)) hA3X hA3Y hHA3 hA3 qHA3 (Or.inr rfl) (vec8_eta _)
                (by rw [(packed_limbs_neg _).1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_neg _).2.1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_neg _).2.2]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [value_cast]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (fun h1 => by norm_num at h1) (fun _ => by simp only [Ladder.rowPoint, Ladder.slotPoint]; norm_num; rw [pA3]; try abel)
            · rw [← hrows]
              exact rowOK_of2 (s := 1) hA7X hA7Y hHA7 hA7 qHA7 (Or.inl rfl) (vec8_eta _)
                (by rw [(packed_limbs_pos _).1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_pos _).2.1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_pos _).2.2]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [value_cast]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (fun _ => by simp only [Ladder.rowPoint, Ladder.slotPoint]; norm_num; rw [pA7]; try abel) (fun h1 => by norm_num at h1)
            · rw [← hrows]
              exact rowOK_of2 (s := (-1)) hA4X hA4Y hHA4 hA4 qHA4 (Or.inr rfl) (vec8_eta _)
                (by rw [(packed_limbs_neg _).1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_neg _).2.1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_neg _).2.2]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [value_cast]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (fun h1 => by norm_num at h1) (fun _ => by simp only [Ladder.rowPoint, Ladder.slotPoint]; norm_num; rw [pA4]; try abel)
            · rw [← hrows]
              exact rowOK_of2 (s := 1) hA2X hA2Y hHA2 hA2 qHA2 (Or.inl rfl) (vec8_eta _)
                (by rw [(packed_limbs_pos _).1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_pos _).2.1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_pos _).2.2]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [value_cast]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (fun _ => by simp only [Ladder.rowPoint, Ladder.slotPoint]; norm_num; rw [pA2]; try abel) (fun h1 => by norm_num at h1)
            · rw [← hrows]
              exact rowOK_of2 (s := (-1)) hA2X hA2Y hHA2 hA2 qHA2 (Or.inr rfl) (vec8_eta _)
                (by rw [(packed_limbs_neg _).1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_neg _).2.1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_neg _).2.2]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [value_cast]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (fun h1 => by norm_num at h1) (fun _ => by simp only [Ladder.rowPoint, Ladder.slotPoint]; norm_num; rw [pA2]; try abel)
            · rw [← hrows]
              exact rowOK_of2 (s := 1) hA4X hA4Y hHA4 hA4 qHA4 (Or.inl rfl) (vec8_eta _)
                (by rw [(packed_limbs_pos _).1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_pos _).2.1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_pos _).2.2]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [value_cast]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (fun _ => by simp only [Ladder.rowPoint, Ladder.slotPoint]; norm_num; rw [pA4]; try abel) (fun h1 => by norm_num at h1)
            · rw [← hrows]
              exact rowOK_of2 (s := (-1)) hA7X hA7Y hHA7 hA7 qHA7 (Or.inr rfl) (vec8_eta _)
                (by rw [(packed_limbs_neg _).1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_neg _).2.1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_neg _).2.2]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [value_cast]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (fun h1 => by norm_num at h1) (fun _ => by simp only [Ladder.rowPoint, Ladder.slotPoint]; norm_num; rw [pA7]; try abel)
            · rw [← hrows]
              exact rowOK_of2 (s := 1) hA3X hA3Y hHA3 hA3 qHA3 (Or.inl rfl) (vec8_eta _)
                (by rw [(packed_limbs_pos _).1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_pos _).2.1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_pos _).2.2]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [value_cast]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (fun _ => by simp only [Ladder.rowPoint, Ladder.slotPoint]; norm_num; rw [pA3]; try abel) (fun h1 => by norm_num at h1)
            · rw [← hrows]
              exact rowOK_of2 (s := (-1)) hA0X hA0Y hHA0 hA0 qHA0 (Or.inr rfl) (vec8_eta _)
                (by rw [(packed_limbs_neg _).1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_neg _).2.1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_neg _).2.2]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [value_cast]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (fun h1 => by norm_num at h1) (fun _ => by simp only [Ladder.rowPoint, Ladder.slotPoint]; norm_num; rw [pA0]; try abel)
            · rw [← hrows]
              exact rowOK_of2 (s := 1) hA6X hA6Y hHA6 hA6 qHA6 (Or.inl rfl) (vec8_eta _)
                (by rw [(packed_limbs_pos _).1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_pos _).2.1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_pos _).2.2]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [value_cast]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (fun _ => by simp only [Ladder.rowPoint, Ladder.slotPoint]; norm_num; rw [pA6]; try abel) (fun h1 => by norm_num at h1)
            · rw [← hrows]
              exact rowOK_of2 (s := (-1)) hA5X hA5Y hHA5 hA5 qHA5 (Or.inr rfl) (vec8_eta _)
                (by rw [(packed_limbs_neg _).1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_neg _).2.1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_neg _).2.2]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [value_cast]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (fun h1 => by norm_num at h1) (fun _ => by simp only [Ladder.rowPoint, Ladder.slotPoint]; norm_num; rw [pA5]; try abel)
            · rw [← hrows]
              exact rowOK_of2 (s := 1) hA1X hA1Y hHA1 hA1 qHA1 (Or.inl rfl) (vec8_eta _)
                (by rw [(packed_limbs_pos _).1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_pos _).2.1]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [(packed_limbs_pos _).2.2]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (by rw [value_cast]; simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, get2_0, get2_1]; ring)
                (fun _ => by simp only [Ladder.rowPoint, Ladder.slotPoint]; norm_num; rw [pA1]; try abel) (fun h1 => by norm_num at h1)
          have hinv : mkPoint hA0 = (1 : ℤ) • mkPoint hQ' + (1 : ℤ) • mkPoint hRon := by rw [pA0, one_zsmul, one_zsmul]
          aux_lemma =>
            obtain ⟨iR, hiR, AX, AY, hAX, hAY, h, hAon, hAeq⟩ := ladder_step_he10e6061 hl hr htab A0X A0Y hA0X hA0Y hA0 h
            have hinv := step_inv hinv hAeq (sel_digits hbits (a := 129) (c := 258) (d := 128) (e := 257)
              (by norm_num) (by norm_num) (by norm_num) (by norm_num) (by simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hiR; exact hiR))
            try simp only [get2_0, get2_1] at h
            elim_gates_shallow h
            obtain ⟨iR, hiR, AX, AY, hAX, hAY, h, hAon, hAeq⟩ := ladder_step_h8a920ea3 hl hr htab AX AY hAX hAY hAon h
            have hinv := step_inv hinv hAeq (sel_digits hbits (a := 127) (c := 256) (d := 126) (e := 255)
              (by norm_num) (by norm_num) (by norm_num) (by norm_num) (by simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hiR; exact hiR))
            obtain ⟨AX, AY, hAX, hAY, h, hAon, hinv⟩ := ladderRun_sound hl hr htab hbits
              [((125 : Fin 259), (254 : Fin 259), (124 : Fin 259), (253 : Fin 259)), ((123 : Fin 259), (252 : Fin 259), (122 : Fin 259), (251 : Fin 259)), ((121 : Fin 259), (250 : Fin 259), (120 : Fin 259), (249 : Fin 259)), ((119 : Fin 259), (248 : Fin 259), (118 : Fin 259), (247 : Fin 259)), ((117 : Fin 259), (246 : Fin 259), (116 : Fin 259), (245 : Fin 259)), ((115 : Fin 259), (244 : Fin 259), (114 : Fin 259), (243 : Fin 259)), ((113 : Fin 259), (242 : Fin 259), (112 : Fin 259), (241 : Fin 259)), ((111 : Fin 259), (240 : Fin 259), (110 : Fin 259), (239 : Fin 259)), ((109 : Fin 259), (238 : Fin 259), (108 : Fin 259), (237 : Fin 259)), ((107 : Fin 259), (236 : Fin 259), (106 : Fin 259), (235 : Fin 259)), ((105 : Fin 259), (234 : Fin 259), (104 : Fin 259), (233 : Fin 259)), ((103 : Fin 259), (232 : Fin 259), (102 : Fin 259), (231 : Fin 259)), ((101 : Fin 259), (230 : Fin 259), (100 : Fin 259), (229 : Fin 259)), ((99 : Fin 259), (228 : Fin 259), (98 : Fin 259), (227 : Fin 259)), ((97 : Fin 259), (226 : Fin 259), (96 : Fin 259), (225 : Fin 259)), ((95 : Fin 259), (224 : Fin 259), (94 : Fin 259), (223 : Fin 259))]
              AX AY hAX hAY hAon _ _ hinv h
            obtain ⟨AX, AY, hAX, hAY, h, hAon, hinv⟩ := ladderRun_sound hl hr htab hbits
              [((93 : Fin 259), (222 : Fin 259), (92 : Fin 259), (221 : Fin 259)), ((91 : Fin 259), (220 : Fin 259), (90 : Fin 259), (219 : Fin 259)), ((89 : Fin 259), (218 : Fin 259), (88 : Fin 259), (217 : Fin 259)), ((87 : Fin 259), (216 : Fin 259), (86 : Fin 259), (215 : Fin 259)), ((85 : Fin 259), (214 : Fin 259), (84 : Fin 259), (213 : Fin 259)), ((83 : Fin 259), (212 : Fin 259), (82 : Fin 259), (211 : Fin 259)), ((81 : Fin 259), (210 : Fin 259), (80 : Fin 259), (209 : Fin 259)), ((79 : Fin 259), (208 : Fin 259), (78 : Fin 259), (207 : Fin 259)), ((77 : Fin 259), (206 : Fin 259), (76 : Fin 259), (205 : Fin 259)), ((75 : Fin 259), (204 : Fin 259), (74 : Fin 259), (203 : Fin 259)), ((73 : Fin 259), (202 : Fin 259), (72 : Fin 259), (201 : Fin 259)), ((71 : Fin 259), (200 : Fin 259), (70 : Fin 259), (199 : Fin 259)), ((69 : Fin 259), (198 : Fin 259), (68 : Fin 259), (197 : Fin 259)), ((67 : Fin 259), (196 : Fin 259), (66 : Fin 259), (195 : Fin 259)), ((65 : Fin 259), (194 : Fin 259), (64 : Fin 259), (193 : Fin 259)), ((63 : Fin 259), (192 : Fin 259), (62 : Fin 259), (191 : Fin 259))]
              AX AY hAX hAY hAon _ _ hinv h
            obtain ⟨AX, AY, hAX, hAY, h, hAon, hinv⟩ := ladderRun_sound hl hr htab hbits
              [((61 : Fin 259), (190 : Fin 259), (60 : Fin 259), (189 : Fin 259)), ((59 : Fin 259), (188 : Fin 259), (58 : Fin 259), (187 : Fin 259)), ((57 : Fin 259), (186 : Fin 259), (56 : Fin 259), (185 : Fin 259)), ((55 : Fin 259), (184 : Fin 259), (54 : Fin 259), (183 : Fin 259)), ((53 : Fin 259), (182 : Fin 259), (52 : Fin 259), (181 : Fin 259)), ((51 : Fin 259), (180 : Fin 259), (50 : Fin 259), (179 : Fin 259)), ((49 : Fin 259), (178 : Fin 259), (48 : Fin 259), (177 : Fin 259)), ((47 : Fin 259), (176 : Fin 259), (46 : Fin 259), (175 : Fin 259)), ((45 : Fin 259), (174 : Fin 259), (44 : Fin 259), (173 : Fin 259)), ((43 : Fin 259), (172 : Fin 259), (42 : Fin 259), (171 : Fin 259)), ((41 : Fin 259), (170 : Fin 259), (40 : Fin 259), (169 : Fin 259)), ((39 : Fin 259), (168 : Fin 259), (38 : Fin 259), (167 : Fin 259)), ((37 : Fin 259), (166 : Fin 259), (36 : Fin 259), (165 : Fin 259)), ((35 : Fin 259), (164 : Fin 259), (34 : Fin 259), (163 : Fin 259)), ((33 : Fin 259), (162 : Fin 259), (32 : Fin 259), (161 : Fin 259)), ((31 : Fin 259), (160 : Fin 259), (30 : Fin 259), (159 : Fin 259))]
              AX AY hAX hAY hAon _ _ hinv h
            obtain ⟨AX, AY, hAX, hAY, h, hAon, hinv⟩ := ladderRun_sound hl hr htab hbits
              [((29 : Fin 259), (158 : Fin 259), (28 : Fin 259), (157 : Fin 259)), ((27 : Fin 259), (156 : Fin 259), (26 : Fin 259), (155 : Fin 259)), ((25 : Fin 259), (154 : Fin 259), (24 : Fin 259), (153 : Fin 259)), ((23 : Fin 259), (152 : Fin 259), (22 : Fin 259), (151 : Fin 259)), ((21 : Fin 259), (150 : Fin 259), (20 : Fin 259), (149 : Fin 259)), ((19 : Fin 259), (148 : Fin 259), (18 : Fin 259), (147 : Fin 259)), ((17 : Fin 259), (146 : Fin 259), (16 : Fin 259), (145 : Fin 259)), ((15 : Fin 259), (144 : Fin 259), (14 : Fin 259), (143 : Fin 259)), ((13 : Fin 259), (142 : Fin 259), (12 : Fin 259), (141 : Fin 259)), ((11 : Fin 259), (140 : Fin 259), (10 : Fin 259), (139 : Fin 259)), ((9 : Fin 259), (138 : Fin 259), (8 : Fin 259), (137 : Fin 259)), ((7 : Fin 259), (136 : Fin 259), (6 : Fin 259), (135 : Fin 259)), ((5 : Fin 259), (134 : Fin 259), (4 : Fin 259), (133 : Fin 259))]
              AX AY hAX hAY hAon _ _ hinv h
            try simp only [get2_0, get2_1] at h
            elim_gates_shallow h
            obtain ⟨iR, hiR, AX, AY, hAX, hAY, h, hAon, hAeq⟩ :=
              ladder_last hl hr htab AX AY hAX hAY hAon T2X T2Y hT2X hT2Y hT2on h
            have hdl := sel_digits hbits (a := 3) (c := 132) (d := 2) (e := 131)
              (by norm_num) (by norm_num) (by norm_num) (by norm_num) (by simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hiR; exact hiR)
            obtain ⟨EX, hEXlo, hEXhi, hEXvlo, hEXvhi, h, vEX⟩ :=
              CheckPolynomial_8_ha59f4c93_sound hl [⟨8, AX⟩] (elemsMatch_of (by show [AX.bnd] = _; rw [hAX]; rfl))
                _ (by limbs_tac [get2_0, get2_1]) h
            have hEXb := eval_bnd hEXlo hEXhi hEXvlo hEXvhi rfl
            clear hEXlo hEXhi hEXvlo hEXvhi
            elim_gates_shallow h
            obtain ⟨gF, h⟩ := h
            have dgF := distinctX_elem hT2X hPRXb (by
              convert gF using 2; apply List.Vector.toList_injective; limbs_tac [hPRX])
            clear gF
            obtain ⟨FX, FY, hFX, hFY, h, crF⟩ :=
              add_he7b90398_sound hl T2X T2Y PRX SPY hT2X hT2Y hPRXb hSPYb (by
                convert h using 2; apply List.Vector.toList_injective; limbs_tac [hPRX])
            try simp only [get2_0, get2_1] at h
            elim_gates_shallow h
            obtain ⟨u0, zu0, u1, zu1, u2, zu2, u3, zu3, u4, zu4, u5, zu5, u6, zu6, u7, zu7, h⟩ := h
            obtain ⟨u8, zu8, u9, zu9, u10, zu10, u11, zu11, u12, zu12, u13, zu13, u14, zu14, u15, zu15, h⟩ := h
            simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.select] at zu0 zu1 zu2 zu3 zu4 zu5 zu6 zu7 zu8 zu9 zu10 zu11 zu12 zu13 zu14 zu15
            obtain ⟨b2, hb2⟩ := bool_of_is_bool zu0.1
            set UX := selElem b2 T2X FX with hUX
            set UY := selElem b2 T2Y FY with hUY
            have ue0 : u0 = UX.limbs.get 0 := by rw [hUX]; exact sel_limb_of hb2 zu0.2 (by rfl) (by rfl)
            have ue1 : u1 = UX.limbs.get 1 := by rw [hUX]; exact sel_limb_of hb2 zu1.2 (by rfl) (by rfl)
            have ue2 : u2 = UX.limbs.get 2 := by rw [hUX]; exact sel_limb_of hb2 zu2.2 (by rfl) (by rfl)
            have ue3 : u3 = UX.limbs.get 3 := by rw [hUX]; exact sel_limb_of hb2 zu3.2 (by rfl) (by rfl)
            have ue4 : u4 = UX.limbs.get 4 := by rw [hUX]; exact sel_limb_of hb2 zu4.2 (by rfl) (by rfl)
            have ue5 : u5 = UX.limbs.get 5 := by rw [hUX]; exact sel_limb_of hb2 zu5.2 (by rfl) (by rfl)
            have ue6 : u6 = UX.limbs.get 6 := by rw [hUX]; exact sel_limb_of hb2 zu6.2 (by rfl) (by rfl)
            have ue7 : u7 = UX.limbs.get 7 := by rw [hUX]; exact sel_limb_of hb2 zu7.2 (by rfl) (by rfl)
            have ue8 : u8 = UY.limbs.get 0 := by rw [hUY]; exact sel_limb_of hb2 zu8.2 (by rfl) (by rfl)
            have ue9 : u9 = UY.limbs.get 1 := by rw [hUY]; exact sel_limb_of hb2 zu9.2 (by rfl) (by rfl)
            have ue10 : u10 = UY.limbs.get 2 := by rw [hUY]; exact sel_limb_of hb2 zu10.2 (by rfl) (by rfl)
            have ue11 : u11 = UY.limbs.get 3 := by rw [hUY]; exact sel_limb_of hb2 zu11.2 (by rfl) (by rfl)
            have ue12 : u12 = UY.limbs.get 4 := by rw [hUY]; exact sel_limb_of hb2 zu12.2 (by rfl) (by rfl)
            have ue13 : u13 = UY.limbs.get 5 := by rw [hUY]; exact sel_limb_of hb2 zu13.2 (by rfl) (by rfl)
            have ue14 : u14 = UY.limbs.get 6 := by rw [hUY]; exact sel_limb_of hb2 zu14.2 (by rfl) (by rfl)
            have ue15 : u15 = UY.limbs.get 7 := by rw [hUY]; exact sel_limb_of hb2 zu15.2 (by rfl) (by rfl)
            clear zu0 zu1 zu2 zu3 zu4 zu5 zu6 zu7 zu8 zu9 zu10 zu11 zu12 zu13 zu14 zu15
            subst ue0 ue1 ue2 ue3 ue4 ue5 ue6 ue7 ue8 ue9 ue10 ue11 ue12 ue13 ue14 ue15
            obtain ⟨v0, zv0, v1, zv1, v2, zv2, v3, zv3, v4, zv4, v5, zv5, v6, zv6, v7, zv7, h⟩ := h
            obtain ⟨v8, zv8, v9, zv9, v10, zv10, v11, zv11, v12, zv12, v13, zv13, v14, zv14, v15, zv15, h⟩ := h
            simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.select] at zv0 zv1 zv2 zv3 zv4 zv5 zv6 zv7 zv8 zv9 zv10 zv11 zv12 zv13 zv14 zv15
            obtain ⟨b1, hb1⟩ := bool_of_is_bool zv0.1
            set VX := selElem b1 PRX QX with hVX
            set VY := selElem b1 SPY QY with hVY
            have ve0 : v0 = VX.limbs.get 0 := by rw [hVX]; exact sel_limb_of hb1 zv0.2 (by limbs_tac [hPRX]) (by rfl)
            have ve1 : v1 = VX.limbs.get 1 := by rw [hVX]; exact sel_limb_of hb1 zv1.2 (by limbs_tac [hPRX]) (by rfl)
            have ve2 : v2 = VX.limbs.get 2 := by rw [hVX]; exact sel_limb_of hb1 zv2.2 (by limbs_tac [hPRX]) (by rfl)
            have ve3 : v3 = VX.limbs.get 3 := by rw [hVX]; exact sel_limb_of hb1 zv3.2 (by limbs_tac [hPRX]) (by rfl)
            have ve4 : v4 = VX.limbs.get 4 := by rw [hVX]; exact sel_limb_of hb1 zv4.2 (by limbs_tac [hPRX]) (by rfl)
            have ve5 : v5 = VX.limbs.get 5 := by rw [hVX]; exact sel_limb_of hb1 zv5.2 (by limbs_tac [hPRX]) (by rfl)
            have ve6 : v6 = VX.limbs.get 6 := by rw [hVX]; exact sel_limb_of hb1 zv6.2 (by limbs_tac [hPRX]) (by rfl)
            have ve7 : v7 = VX.limbs.get 7 := by rw [hVX]; exact sel_limb_of hb1 zv7.2 (by limbs_tac [hPRX]) (by rfl)
            have ve8 : v8 = VY.limbs.get 0 := by rw [hVY]; exact sel_limb_of hb1 zv8.2 (by limbs_tac [hPRX]) (by rfl)
            have ve9 : v9 = VY.limbs.get 1 := by rw [hVY]; exact sel_limb_of hb1 zv9.2 (by limbs_tac [hPRX]) (by rfl)
            have ve10 : v10 = VY.limbs.get 2 := by rw [hVY]; exact sel_limb_of hb1 zv10.2 (by limbs_tac [hPRX]) (by rfl)
            have ve11 : v11 = VY.limbs.get 3 := by rw [hVY]; exact sel_limb_of hb1 zv11.2 (by limbs_tac [hPRX]) (by rfl)
            have ve12 : v12 = VY.limbs.get 4 := by rw [hVY]; exact sel_limb_of hb1 zv12.2 (by limbs_tac [hPRX]) (by rfl)
            have ve13 : v13 = VY.limbs.get 5 := by rw [hVY]; exact sel_limb_of hb1 zv13.2 (by limbs_tac [hPRX]) (by rfl)
            have ve14 : v14 = VY.limbs.get 6 := by rw [hVY]; exact sel_limb_of hb1 zv14.2 (by limbs_tac [hPRX]) (by rfl)
            have ve15 : v15 = VY.limbs.get 7 := by rw [hVY]; exact sel_limb_of hb1 zv15.2 (by limbs_tac [hPRX]) (by rfl)
            clear zv0 zv1 zv2 zv3 zv4 zv5 zv6 zv7 zv8 zv9 zv10 zv11 zv12 zv13 zv14 zv15
            subst ve0 ve1 ve2 ve3 ve4 ve5 ve6 ve7 ve8 ve9 ve10 ve11 ve12 ve13 ve14 ve15
            have hUXb : UX.bnd = reducedC := by rw [hUX, selElem_bnd, hT2X, hFX]; rfl
            have hUYb : UY.bnd = reducedC := by rw [hUY, selElem_bnd, hT2Y, hFY]; rfl
            have hVXb : VX.bnd = reducedC := by rw [hVX, selElem_bnd, hPRXb, hQXb]; rfl
            have hVYb : VY.bnd = selBnd selC reducedC := by rw [hVY, selElem_bnd, hSPYb, hQYb]
            obtain ⟨gG, h⟩ := h
            have dgG := distinctX_elem hVXb hUXb (by convert gG using 2 <;> exact (vec8_eta _).symm)
            clear gG
            obtain ⟨GX, GY, hGX, hGY, h, crG⟩ :=
              add_h47aeac58_sound hl VX VY UX UY hVXb hVYb hUXb hUYb (by
                convert h using 2 <;> exact (vec8_eta _).symm)
            try simp only [get2_0, get2_1] at h
            elim_gates_shallow h
            obtain ⟨w0, zw0, w1, zw1, w2, zw2, w3, zw3, w4, zw4, w5, zw5, w6, zw6, w7, zw7, h⟩ := h
            obtain ⟨w8, zw8, w9, zw9, w10, zw10, w11, zw11, w12, zw12, w13, zw13, w14, zw14, w15, zw15, h⟩ := h
            simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.select] at zw0 zw1 zw2 zw3 zw4 zw5 zw6 zw7 zw8 zw9 zw10 zw11 zw12 zw13 zw14 zw15
            set WX := selElem b1 UX GX with hWX
            set WY := selElem b1 UY GY with hWY
            have we0 : w0 = WX.limbs.get 0 := by rw [hWX]; exact sel_limb_of hb1 zw0.2 (by rfl) (by rfl)
            have we1 : w1 = WX.limbs.get 1 := by rw [hWX]; exact sel_limb_of hb1 zw1.2 (by rfl) (by rfl)
            have we2 : w2 = WX.limbs.get 2 := by rw [hWX]; exact sel_limb_of hb1 zw2.2 (by rfl) (by rfl)
            have we3 : w3 = WX.limbs.get 3 := by rw [hWX]; exact sel_limb_of hb1 zw3.2 (by rfl) (by rfl)
            have we4 : w4 = WX.limbs.get 4 := by rw [hWX]; exact sel_limb_of hb1 zw4.2 (by rfl) (by rfl)
            have we5 : w5 = WX.limbs.get 5 := by rw [hWX]; exact sel_limb_of hb1 zw5.2 (by rfl) (by rfl)
            have we6 : w6 = WX.limbs.get 6 := by rw [hWX]; exact sel_limb_of hb1 zw6.2 (by rfl) (by rfl)
            have we7 : w7 = WX.limbs.get 7 := by rw [hWX]; exact sel_limb_of hb1 zw7.2 (by rfl) (by rfl)
            have we8 : w8 = WY.limbs.get 0 := by rw [hWY]; exact sel_limb_of hb1 zw8.2 (by rfl) (by rfl)
            have we9 : w9 = WY.limbs.get 1 := by rw [hWY]; exact sel_limb_of hb1 zw9.2 (by rfl) (by rfl)
            have we10 : w10 = WY.limbs.get 2 := by rw [hWY]; exact sel_limb_of hb1 zw10.2 (by rfl) (by rfl)
            have we11 : w11 = WY.limbs.get 3 := by rw [hWY]; exact sel_limb_of hb1 zw11.2 (by rfl) (by rfl)
            have we12 : w12 = WY.limbs.get 4 := by rw [hWY]; exact sel_limb_of hb1 zw12.2 (by rfl) (by rfl)
            have we13 : w13 = WY.limbs.get 5 := by rw [hWY]; exact sel_limb_of hb1 zw13.2 (by rfl) (by rfl)
            have we14 : w14 = WY.limbs.get 6 := by rw [hWY]; exact sel_limb_of hb1 zw14.2 (by rfl) (by rfl)
            have we15 : w15 = WY.limbs.get 7 := by rw [hWY]; exact sel_limb_of hb1 zw15.2 (by rfl) (by rfl)
            clear zw0 zw1 zw2 zw3 zw4 zw5 zw6 zw7 zw8 zw9 zw10 zw11 zw12 zw13 zw14 zw15
            subst we0 we1 we2 we3 we4 we5 we6 we7 we8 we9 we10 we11 we12 we13 we14 we15
            aux_lemma =>
              obtain ⟨hfx, hfy, hk⟩ := h
              have cfx := CheckPolynomial_16_h2335258c_sound hl [⟨8, EX⟩, ⟨8, WX⟩]
                (elemsMatch_of (by
                  show [EX.bnd, WX.bnd] = _
                  rw [hWX, selElem_bnd, hUXb, hGX, hEXb]; rfl))
                _ (by limbs_tac [get2_0, get2_1]) hfx
              have cfy := CheckPolynomial_16_h2b229ca1_sound hl [⟨8, AY⟩, ⟨8, WY⟩]
                (elemsMatch_of (by
                  show [AY.bnd, WY.bnd] = _
                  rw [hWY, selElem_bnd, hUYb, hGY, hAY]; rfl))
                _ (by limbs_tac [get2_0, get2_1]) hfy
              have m1 : (cert_ha59f4c93.m : ℤ) = p := rfl
              have m8 : (cert_h2335258c.m : ℤ) = p := rfl
              have m9 : (cert_h2b229ca1.m : ℤ) = p := rfl
              have e1 : cert_ha59f4c93.exprValue (values [⟨8, AX⟩]) = AX.value := by
                simp [PolyShape.exprValue, values, cert_ha59f4c93]
              have e8 : cert_h2335258c.exprValue (values [⟨8, EX⟩, ⟨8, WX⟩]) = EX.value - WX.value := by
                simp [PolyShape.exprValue, values, cert_h2335258c]; ring
              have e9 : cert_h2b229ca1.exprValue (values [⟨8, AY⟩, ⟨8, WY⟩]) = AY.value - WY.value := by
                simp [PolyShape.exprValue, values, cert_h2b229ca1]; ring
              rw [e1, m1, modEq_p_iff] at vEX
              rw [e8, m8, modEq_p_iff] at cfx
              rw [e9, m9, modEq_p_iff] at cfy
              push_cast at vEX cfx cfy
              have hE : OnCurve (EX.value : Fp) (AY.value : Fp) := by rw [vEX]; exact hAon
              have pE : mkPoint hE = mkPoint hAon := mkPoint_inj.mpr ⟨vEX, rfl⟩
              obtain ⟨hFon, pF⟩ := chord_point hT2on hRon dgF.2.2.2.2 crF.1 crF.2
              have hUon : OnCurve (UX.value : Fp) (UY.value : Fp) := by
                rw [hUX, hUY, selElem_value b2 T2X FX, selElem_value b2 T2Y FY]
                cases b2
                · exact hFon
                · exact hT2on
              have pU : mkPoint hUon = if b2 then mkPoint hT2on else mkPoint hFon := by
                cases b2
                · simp only [Bool.false_eq_true, if_false]
                  exact mkPoint_inj.mpr ⟨by rw [hUX, selElem_value _ T2X FX]; rfl, by rw [hUY, selElem_value _ T2Y FY]; rfl⟩
                · simp only [if_true]
                  exact mkPoint_inj.mpr ⟨by rw [hUX, selElem_value _ T2X FX]; rfl, by rw [hUY, selElem_value _ T2Y FY]; rfl⟩
              have hVon : OnCurve (VX.value : Fp) (VY.value : Fp) := by
                rw [hVX, hVY, selElem_value b1 PRX QX, selElem_value b1 SPY QY]
                cases b1
                · exact hQ'
                · exact hRon
              have pV : mkPoint hVon = if b1 then mkPoint hRon else mkPoint hQ' := by
                cases b1
                · simp only [Bool.false_eq_true, if_false]
                  exact mkPoint_inj.mpr ⟨by rw [hVX, selElem_value _ PRX QX]; rfl, by rw [hVY, selElem_value _ SPY QY]; rfl⟩
                · show mkPoint hVon = mkPoint hRon
                  exact mkPoint_inj.mpr ⟨by rw [hVX, selElem_value _ PRX QX]; rfl, by rw [hVY, selElem_value _ SPY QY]; rfl⟩
              obtain ⟨hGon, pG⟩ := chord_point hVon hUon dgG.2.2.2.2 crG.1 crG.2
              have hWon : OnCurve (WX.value : Fp) (WY.value : Fp) := by
                rw [hWX, hWY, selElem_value b1 UX GX, selElem_value b1 UY GY]
                cases b1
                · exact hGon
                · exact hUon
              have pW : mkPoint hWon = if b1 then mkPoint hUon else mkPoint hGon := by
                cases b1
                · simp only [Bool.false_eq_true, if_false]
                  exact mkPoint_inj.mpr ⟨by rw [hWX, selElem_value _ UX GX]; rfl, by rw [hWY, selElem_value _ UY GY]; rfl⟩
                · simp only [if_true]
                  exact mkPoint_inj.mpr ⟨by rw [hWX, selElem_value _ UX GX]; rfl, by rw [hWY, selElem_value _ UY GY]; rfl⟩
              have pT : mkPoint hE = mkPoint hWon := mkPoint_inj.mpr ⟨by linear_combination cfx, by linear_combination cfy⟩
              have hb1' := bitI_eq_of_sel hbits (a := 1) (by norm_num) (b := b1) (by rw [← hb1, vget_getD]; try rfl)
              have hb2' := bitI_eq_of_sel hbits (a := 130) (by norm_num) (b := b2) (by rw [← hb2, vget_getD]; try rfl)
              have hcl := ladder_close b1 b2 hinv hAeq hdl hT2eq pE pF pU pV pG (pT.trans pW)
              rw [← hb1', ← hb2'] at hcl
              obtain ⟨u, v, huv, hu, hv⟩ : ∃ u v : ℤ, u • mkPoint hQ' + v • mkPoint hRon = 0 ∧
                  u = chunk g402 1 129 ∧ v = chunk g402 130 129 :=
                ⟨_, _, hcl,
                  by simp only [chunk, Finset.sum_range_succ, Finset.sum_range_zero, Nat.reduceAdd, runQ, runR,
                    List.foldl_cons, List.foldl_nil, Fin.coe_ofNat_eq_mod, Nat.reduceMod]; ring,
                  by simp only [chunk, Finset.sum_range_succ, Finset.sum_range_zero, Nat.reduceAdd, runQ, runR,
                    List.foldl_cons, List.foldl_nil, Fin.coe_ofNat_eq_mod, Nat.reduceMod]; ring⟩
              have hrel : chunk g402 1 129 • mkPoint hQ' + chunk g402 130 129 • mkPoint hRon = 0 := by
                rw [← hu, ← hv]; exact huv
              have eR : cert_hb0ad1306.exprValue (values [⟨8, S1⟩, ⟨5, SD⟩, ⟨5, NUM⟩]) =
                  S1.value * SD.value + NUM.value := by
                simp [PolyShape.exprValue, values, cert_hb0ad1306]; try ring
              have mR : (cert_hb0ad1306.m : ℤ) = n := rfl
              have vSD : SD.value = (1 - 2 * bitI g402 0) * chunk g402 130 129 := by
                rw [hSD, mkElem5_value, ← rec5_limbs129]; simp only [rec5]; ring
              have vNUM : NUM.value = chunk g402 1 129 := by rw [hNUM, mkElem5_value, rec5_limbs129]
              have hS1v : S1.value = if b then H.value else S0.value := by rw [hS1, selElem_value]
              rw [eR, mR, vSD, vNUM, hS1v] at c18
              have eH : cert_h93312e5c.exprValue (values [⟨8, S0⟩, ⟨8, constElem inv2Limbs⟩]) =
                  S0.value * (constElem inv2Limbs).value := by
                simp [PolyShape.exprValue, values, cert_h93312e5c]; try ring
              have mH : (cert_h93312e5c.m : ℤ) = n := rfl
              rw [eH, mH, constElem_value] at vH
              have hh : H.value * 2 ≡ S0.value [ZMOD n] :=
                calc H.value * 2 ≡ S0.value * rec8 inv2Limbs * 2 [ZMOD n] := vH.mul_right 2
                  _ = S0.value * (rec8 inv2Limbs * 2) := by ring
                  _ ≡ S0.value * 1 [ZMOD n] := inv2_spec.mul_left _
                  _ = S0.value := mul_one _
              have e0 : cert_h57d6a69c.exprValue (values [⟨8, S⟩]) = S.value := by
                simp [PolyShape.exprValue, values, cert_h57d6a69c]
              have m0 : (cert_h57d6a69c.m : ℤ) = n := rfl
              rw [e0, m0] at vS0
              have hRε : mkPoint hRon = (1 - 2 * bitI g402 0) • mkPoint hPRon := by
                rcases hs1 with h1 | h1
                · rw [h1, one_zsmul]; exact mkPoint_inj.mpr ⟨rfl, by rw [vSPY, h1]; push_cast; ring⟩
                · rw [h1, neg_one_zsmul]
                  obtain ⟨hn, hne⟩ := neg_mkPoint hPRon
                  rw [hne]; exact mkPoint_inj.mpr ⟨rfl, by rw [vSPY, h1]; push_cast; ring⟩
              have cden := chunk_bounds hbits (a := 130) (w := 129) (by norm_num)
              have hlt : (2 : ℤ) ^ 129 - 1 < n := by norm_num [n]
              have hfin := scalar_close (Q := mkPoint hQ) b hs1 ⟨hden, lt_of_le_of_lt cden.2 hlt⟩ c18 hrel hRε hQ'pt hh vS0
              refine ⟨PRX, PRY, hPRXb, hPRYb, k_of_limbs hk (by limbs_tac [hPRX]) (by limbs_tac [hPRY]), hPRon, hfin⟩

end ZolanaVE.P256
