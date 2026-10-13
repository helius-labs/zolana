import VerifiableEncryption.Curve.QuadStep
import VerifiableEncryption.Curve.LadderAux
import VerifiableEncryption.Curve.BitElem

/-!
`completeAdd`: addition or doubling of two points, rejecting inverse points.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem completeAdd_sound (hl : LookupSound RangeCheck 11) (PX PY QX QY : ElemVal 8)
    (hPX : PX.bnd = reducedC) (hPY : PY.bnd = reducedC) (hQX : QX.bnd = reducedC) (hQY : QY.bnd = reducedC)
    (hP : OnCurve (PX.value : Fp) (PY.value : Fp)) (hQ : OnCurve (QX.value : Fp) (QY.value : Fp))
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : CompleteAdd_8_8_8_8_h3f5cf0cd PX.limbs PY.limbs QX.limbs QY.limbs k) :
    ∃ RX RY : ElemVal 8, RX.bnd = reducedC ∧ RY.bnd = reducedC ∧
      k (RX.limbs ::ᵥ RY.limbs ::ᵥ List.Vector.nil) ∧
      ∃ hR : OnCurve (RX.value : Fp) (RY.value : Fp), mkPoint hR = mkPoint hP + mkPoint hQ := by
  unfold CompleteAdd_8_8_8_8_h3f5cf0cd CompleteAdd_8_8_8_8_h3f5cf0cd_p1 at h
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, GatesDef.sub,
    GatesDef.eq, GatesDef.ne, exists_eq_left] at h
  obtain ⟨g0, hbool, p2, pz2, p6, p5, p17, pz17, p20, pz20, pfin, q2, qz2, q6, q5, q17, qz17, q20, qz20, qfin,
    hxe, hcx, hcy, g141, g142, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17,
    r18, r19, r20, r21, r22, r23, hlam, h⟩ := h
  have cP : AssertCanonical_8_0_hcc2f8a19 PX.limbs := by
    unfold AssertCanonical_8_0_hcc2f8a19
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, GatesDef.sub,
      GatesDef.eq, exists_eq_left]
    exact ⟨p2, pz2, p6, p5, p17, pz17, p20, pz20, pfin, trivial⟩
  have cQ : AssertCanonical_8_0_hcc2f8a19 QX.limbs := by
    unfold AssertCanonical_8_0_hcc2f8a19
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, GatesDef.sub,
      GatesDef.eq, exists_eq_left]
    exact ⟨q2, qz2, q6, q5, q17, qz17, q20, qz20, qfin, trivial⟩
  clear p2 pz2 p6 p5 p17 pz17 p20 pz20 pfin q2 qz2 q6 q5 q17 qz17 q20 qz20 qfin
  obtain ⟨la, va⟩ := reduced_vals hPX
  obtain ⟨lb, vb⟩ := reduced_vals hQX
  have lP := assertCanonical_p_sound _ la cP
  have lQ := assertCanonical_p_sound _ lb cQ
  have hp : ∀ i : Fin 8, PieceRC g142 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  obtain ⟨b, hb⟩ := bool_of_is_bool hbool
  set L := mkElem _ _ (bal_fits hl hp) with hL
  set XD := linElem [(1, QX), (-1, PX)] with hXD
  set YD := linElem [(1, QY), (-1, PY)] with hYD
  have cx := CheckPolynomial_9_hd299af1e_sound hl [⟨1, bitElem b⟩, ⟨8, XD⟩]
    (elemsMatch_of (by
      show [(bitElem b).bnd, XD.bnd] = _
      rw [hXD, linElem_bnd]; simp only [List.map]; rw [hQX, hPX]; rfl))
    _ (by limbs_tac [hXD, bitElem, ← hb]) hcx
  have cy := CheckPolynomial_9_hd299af1e_sound hl [⟨1, bitElem b⟩, ⟨8, YD⟩]
    (elemsMatch_of (by
      show [(bitElem b).bnd, YD.bnd] = _
      rw [hYD, linElem_bnd]; simp only [List.map]; rw [hQY, hPY]; rfl))
    _ (by limbs_tac [hYD, bitElem, ← hb]) hcy
  have cl := CheckPolynomial_49_h8f49f727_sound hl
    [⟨8, L⟩, ⟨8, XD⟩, ⟨1, bitElem b⟩, ⟨8, PY⟩, ⟨8, PX⟩, ⟨8, aElem⟩, ⟨8, YD⟩]
    (elemsMatch_of (by
      show [L.bnd, XD.bnd, (bitElem b).bnd, PY.bnd, PX.bnd, aElem.bnd, YD.bnd] = _
      rw [hXD, hYD, linElem_bnd, linElem_bnd]; simp only [List.map]; rw [hQX, hPX, hQY, hPY]; rfl))
    _ (by limbs_tac [hL, hXD, hYD, bitElem, ← hb, aElem, aLimbs]) hlam
  obtain ⟨RX, hRXlo, hRXhi, hRXvlo, hRXvhi, h, vRX⟩ :=
    CheckPolynomial_24_h42186a27_sound hl [⟨8, L⟩, ⟨8, PX⟩, ⟨8, QX⟩]
      (elemsMatch_of (by show [L.bnd, PX.bnd, QX.bnd] = _; rw [hPX, hQX]; rfl)) _ (by limbs_tac [hL]) h
  have hRXb := eval_bnd hRXlo hRXhi hRXvlo hRXvhi rfl
  clear hRXlo hRXhi hRXvlo hRXvhi
  elim_gates h
  set XR := linElem [(1, PX), (-1, RX)] with hXR
  obtain ⟨RY, hRYlo, hRYhi, hRYvlo, hRYvhi, hk, vRY⟩ :=
    CheckPolynomial_24_h2629e496_sound hl [⟨8, L⟩, ⟨8, XR⟩, ⟨8, PY⟩]
      (elemsMatch_of (by
        show [L.bnd, XR.bnd, PY.bnd] = _
        rw [hXR, linElem_bnd]; simp only [List.map]; rw [hPX, hRXb, hPY]; rfl))
      _ (by limbs_tac [hL, hXR]) h
  have hRYb := eval_bnd hRYlo hRYhi hRYvlo hRYvhi rfl
  clear hRYlo hRYhi hRYvlo hRYvhi
  refine ⟨RX, RY, hRXb, hRYb, hk, ?_⟩
  have m9 : (cert_hd299af1e.m : ℤ) = p := rfl
  have m49 : (cert_h8f49f727.m : ℤ) = p := rfl
  have mX : (cert_h42186a27.m : ℤ) = p := rfl
  have mY : (cert_h2629e496.m : ℤ) = p := rfl
  have e9x : cert_hd299af1e.exprValue (values [⟨1, bitElem b⟩, ⟨8, XD⟩]) = (bitElem b).value * XD.value := by
    simp [PolyShape.exprValue, values, cert_hd299af1e]
  have e9y : cert_hd299af1e.exprValue (values [⟨1, bitElem b⟩, ⟨8, YD⟩]) = (bitElem b).value * YD.value := by
    simp [PolyShape.exprValue, values, cert_hd299af1e]
  have e49 : cert_h8f49f727.exprValue
      (values [⟨8, L⟩, ⟨8, XD⟩, ⟨1, bitElem b⟩, ⟨8, PY⟩, ⟨8, PX⟩, ⟨8, aElem⟩, ⟨8, YD⟩]) =
      L.value * XD.value + 2 * L.value * (bitElem b).value * PY.value -
        3 * (bitElem b).value * PX.value * PX.value - (bitElem b).value * aElem.value - YD.value := by
    simp [PolyShape.exprValue, values, cert_h8f49f727]; try ring
  have eX : cert_h42186a27.exprValue (values [⟨8, L⟩, ⟨8, PX⟩, ⟨8, QX⟩]) =
      L.value * L.value - PX.value - QX.value := by
    simp [PolyShape.exprValue, values, cert_h42186a27]; try ring
  have eY : cert_h2629e496.exprValue (values [⟨8, L⟩, ⟨8, XR⟩, ⟨8, PY⟩]) = L.value * XR.value - PY.value := by
    simp [PolyShape.exprValue, values, cert_h2629e496]; try ring
  have vXD : XD.value = QX.value - PX.value := by rw [hXD, linElem_value]; simp; try ring
  have vYD : YD.value = QY.value - PY.value := by rw [hYD, linElem_value]; simp; try ring
  have vXR : XR.value = PX.value - RX.value := by rw [hXR, linElem_value]; simp; try ring
  rw [e9x, m9, vXD, bitElem_value, modEq_p_iff] at cx
  rw [e9y, m9, vYD, bitElem_value, modEq_p_iff] at cy
  rw [e49, m49, vXD, vYD, bitElem_value, aElem_value, modEq_p_iff] at cl
  rw [eX, mX] at vRX
  rw [eY, mY, vXR] at vRY
  have hp0 : ((p : ℤ) : Fp) = 0 := by push_cast; exact ZMod.natCast_self p
  cases b
  · simp only [Bool.false_eq_true, ↓reduceIte] at hb cl
    have hsq := sameX_flag hxe hb one_ne_zero
    have hs : ∑ i : Fin 8, (PX.limbs.get i - QX.limbs.get i) ^ 2 ≠ 0 := by
      intro h0
      apply hsq
      rw [Fin.sum_univ_eight] at h0
      linear_combination h0
    have hx := distinctX_guard (a := fun i => PX.limbs.get i) (c := fun i => QX.limbs.get i) la lb
      (by rw [← p256P_eq]; exact lP) (by rw [← p256P_eq]; exact lQ) hs
    have hx' : (PX.value : Fp) ≠ (QX.value : Fp) := by
      rw [← va, ← vb]
      exact_mod_cast hx
    obtain ⟨hS, pS⟩ := slope_add_int (l := L.value) (xs := RX.value) (ys := RY.value) hP hQ hx'
      (by rw [modEq_p_iff]; push_cast at cl ⊢; linear_combination cl) (by rw [sq]; exact vRX) vRY
    exact ⟨hS, pS.symm⟩
  · simp only [↓reduceIte] at hb cx cy cl
    push_cast at cx cy cl
    have pQ : mkPoint hQ = mkPoint hP :=
      mkPoint_inj.mpr ⟨by linear_combination cx, by linear_combination cy⟩
    obtain ⟨hD, pD⟩ := tangent_double_int (l := L.value) (xd := RX.value) (yd := RY.value) hP
      (by rw [modEq_p_iff]; push_cast at hp0 ⊢; linear_combination cl - (L.value : Fp) * cx + cy + hp0)
      (by rw [modEq_p_iff] at vRX ⊢; push_cast at vRX ⊢; linear_combination vRX - cx) vRY
    exact ⟨hD, by rw [pQ, ← pD, two_nsmul]⟩

end ZolanaVE.P256
