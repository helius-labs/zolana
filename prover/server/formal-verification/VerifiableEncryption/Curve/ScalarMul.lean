import VerifiableEncryption.Curve.Bits
import VerifiableEncryption.Curve.Ladder

/-!
Soundness of the extracted variable-base scalar multiplication
`ScalarMulChecked` (`ladder.go`).
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

/-- Idealised soundness of the packed ladder table lookup: the returned row is
the row at the index. -/
def RowLookupSound : Prop :=
  ∀ (rows : List.Vector (List.Vector F 12) 16) (idx : F) (k : List.Vector F 12 → Prop),
    RowLookup_12_16 rows idx k → ∃ i : Fin 16, idx = ((i : ℕ) : F) ∧ k (rows.get i)

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
  -- BLOCKED: the extracted model of `api.Add` with more than two operands binds each
  -- chained intermediate to itself (`∃ g, g = g + x`), so the denominator-nonzero check
  -- and the packed-table selectors are not faithful to the circuit (see report).
  sorry

end ZolanaVE.P256
