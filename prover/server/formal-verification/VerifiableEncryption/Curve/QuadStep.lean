import VerifiableEncryption.Curve.AddStep
import VerifiableEncryption.Curve.QuadAdd
import VerifiableEncryption.Field.Instances2
import VerifiableEncryption.Field.Instances3
import VerifiableEncryption.Field.Instances4
import VerifiableEncryption.Field.Instances5

/-!
The extracted `QuadrupleAndAddLazy` step gadgets.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

/-- The P-256 coefficient `a = p - 3` as the constant element `Field.Const`. -/
def aLimbs (i : Fin 8) : ℤ := [4294967292, 4294967295, 4294967295, 0, 0, 0, 1, 4294967295].getD i 0

def aC : ElemC := ⟨List.ofFn aLimbs, List.ofFn aLimbs, rec8 aLimbs, rec8 aLimbs⟩

theorem a_fits : Fits aLimbs aC := by
  refine ⟨rfl, rfl, fun i => ?_, le_rfl, le_rfl⟩
  fin_cases i <;> exact ⟨le_rfl, le_rfl⟩

def aElem : ElemVal 8 := mkElem aLimbs aC a_fits

theorem aElem_value : aElem.value = p - 3 := by
  rw [aElem, mkElem_value]
  rfl

/-- Bounds of a lazy check's output. -/
def lazyOut (c : LazyParams) : ElemC := ⟨c.outLo, c.outHi, c.outVlo, c.outVhi⟩

/-- Bounds of `curve.unpackedY`: three packed groups at limbs 0, 3 and 6. -/
def unpackC : ElemC := cert_hdaa6ee4a.elems.getD 2 default

theorem quadAdd_h320f0a4e_sound (hl : LookupSound RangeCheck 11) (AX AY SX SY : ElemVal 8)
    (hAX : AX.bnd = lazyOut lazy_h9c68f146) (hAY : AY.bnd = lazyOut lazy_hee995b41)
    (hSX : SX.bnd = reducedC) (hSY : SY.bnd = unpackC) {hs : F}
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : QuadrupleAndAddLazy_8_8_8_8_h320f0a4e AX.limbs AY.limbs SX.limbs SY.limbs hs k) :
    ∃ OX OY : ElemVal 8, OX.bnd = lazyOut lazy_h9c68f146 ∧ OY.bnd = lazyOut lazy_hee995b41 ∧
      k (OX.limbs ::ᵥ OY.limbs ::ᵥ List.Vector.nil) ∧
      ∃ L : ElemVal 8, L.bnd = balC ∧
        slopeFactor (((L.value : ℤ) : F) - hs) * slopeFactor (((L.value : ℤ) : F) + hs) ≠ 0 ∧
        ∃ dX dY μ ν iX : Fp, QuadAddCons (AX.value : Fp) (AY.value : Fp) (SX.value : Fp) (SY.value : Fp)
          (L.value : Fp) dX dY μ ν iX (OX.value : Fp) (OY.value : Fp) := by
  unfold QuadrupleAndAddLazy_8_8_8_8_h320f0a4e QuadrupleAndAddLazy_8_8_8_8_h320f0a4e_p1
    QuadrupleAndAddLazy_8_8_8_8_h320f0a4e_p2 at h
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
  have hLb : L.bnd = balC := rfl
  have c1 := CheckPolynomial_32_h6485b116_sound hl [⟨8, L⟩, ⟨8, AY⟩, ⟨8, AX⟩, ⟨8, aElem⟩]
    (elemsMatch_of (by show [L.bnd, AY.bnd, AX.bnd, aElem.bnd] = _; rw [hAY, hAX]; rfl)) _
    (by limbs_tac [hL, aElem, aLimbs]) hc1
  obtain ⟨DX, hDXlo, hDXhi, hDXvlo, hDXvhi, h, vDX⟩ :=
    Lazy_16_h53928760_sound [⟨8, L⟩, ⟨8, AX⟩]
      (elemsMatch_of (by show [L.bnd, AX.bnd] = _; rw [hAX]; rfl)) _ (by limbs_tac [hL]) h
  have hDXb := lazy_bnd hDXlo hDXhi hDXvlo hDXvhi
  clear hDXlo hDXhi hDXvlo hDXvhi
  elim_gates h
  set AmD := linElem [(1, AX), (-1, DX)] with hAmD
  obtain ⟨DY, hDYlo, hDYhi, hDYvlo, hDYvhi, h, vDY⟩ :=
    Lazy_24_h31bd1a61_sound [⟨8, L⟩, ⟨8, AmD⟩, ⟨8, AY⟩]
      (elemsMatch_of (by show [L.bnd, AmD.bnd, AY.bnd] = _; rw [hAmD, linElem_bnd]; simp only [List.map]; rw [hAX, hDXb, hAY]; rfl))
      _ (by limbs_tac [hL, hAmD]) h
  have hDYb := lazy_bnd hDYlo hDYhi hDYvlo hDYvhi
  clear hDYlo hDYhi hDYvlo hDYvhi
  elim_gates h
  obtain ⟨g149, g150, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17,
    r18, r19, r20, r21, r22, r23, h⟩ := h
  have hp2 : ∀ i : Fin 8, PieceRC g150 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set M := mkElem _ _ (bal_fits hl hp2) with hM
  have hMb : M.bnd = balC := rfl
  set XD := linElem [(1, SX), (-1, DX)] with hXD
  obtain ⟨hc3, hds, h⟩ := h
  have c3 := CheckPolynomial_32_hdaa6ee4a_sound hl [⟨8, M⟩, ⟨8, XD⟩, ⟨8, SY⟩, ⟨8, DY⟩]
    (elemsMatch_of (by
      show [M.bnd, XD.bnd, SY.bnd, DY.bnd] = _
      rw [hXD, linElem_bnd]; simp only [List.map]; rw [hSX, hDXb, hSY, hDYb]; rfl))
    _ (by limbs_tac [hM, hXD]) hc3
  have gs := assertDistinctSlope_sound (Λ := L) (o := hs) (by
    convert hds using 2
    apply List.Vector.toList_injective
    limbs_tac [hL])
  clear hds
  obtain ⟨IX, hIXlo, hIXhi, hIXvlo, hIXvhi, h, vIX⟩ :=
    Lazy_24_hdbbbc800_sound [⟨8, M⟩, ⟨8, DX⟩, ⟨8, SX⟩]
      (elemsMatch_of (by show [M.bnd, DX.bnd, SX.bnd] = _; rw [hDXb, hSX]; rfl))
      _ (by limbs_tac [hM]) h
  have hIXb := lazy_bnd hIXlo hIXhi hIXvlo hIXvhi
  clear hIXlo hIXhi hIXvlo hIXvhi
  elim_gates h
  obtain ⟨g234, g235, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17,
    r18, r19, r20, r21, r22, r23, h⟩ := h
  have hp3 : ∀ i : Fin 8, PieceRC g235 (0 + 3 * i.val) := by
    intro i
    fin_cases i
    exacts [⟨rc_getD r0, rc_getD r1, rc_getD r2⟩, ⟨rc_getD r3, rc_getD r4, rc_getD r5⟩,
      ⟨rc_getD r6, rc_getD r7, rc_getD r8⟩, ⟨rc_getD r9, rc_getD r10, rc_getD r11⟩,
      ⟨rc_getD r12, rc_getD r13, rc_getD r14⟩, ⟨rc_getD r15, rc_getD r16, rc_getD r17⟩,
      ⟨rc_getD r18, rc_getD r19, rc_getD r20⟩, ⟨rc_getD r21, rc_getD r22, rc_getD r23⟩]
  clear r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23
  set N := mkElem _ _ (bal_fits hl hp3) with hN
  have hNb : N.bnd = balC := rfl
  set IXD := linElem [(1, IX), (-1, DX)] with hIXD
  obtain ⟨hc4, h⟩ := h
  have c4 := CheckPolynomial_40_h4960297a_sound hl [⟨8, N⟩, ⟨8, IXD⟩, ⟨8, M⟩, ⟨8, XD⟩, ⟨8, SY⟩]
    (elemsMatch_of (by
      show [N.bnd, IXD.bnd, M.bnd, XD.bnd, SY.bnd] = _
      rw [hIXD, hXD, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hIXb, hDXb, hSX, hSY]; rfl))
    _ (by limbs_tac [hN, hIXD, hM, hXD]) hc4
  set NM := linElem [(1, N), (2, M)] with hNM
  obtain ⟨OX, hOXlo, hOXhi, hOXvlo, hOXvhi, h, vOX⟩ :=
    Lazy_24_h9c68f146_sound [⟨8, N⟩, ⟨8, NM⟩, ⟨8, SX⟩]
      (elemsMatch_of (by
        show [N.bnd, NM.bnd, SX.bnd] = _
        rw [hNM, linElem_bnd]; simp only [List.map]; rw [hSX]; rfl))
      _ (by limbs_tac [hN, hNM, hM]) h
  have hOXb := lazy_bnd hOXlo hOXhi hOXvlo hOXvhi
  clear hOXlo hOXhi hOXvlo hOXvhi
  elim_gates h
  set MN := linElem [(1, M), (1, N)] with hMN
  set OXD := linElem [(1, OX), (-1, DX)] with hOXD
  obtain ⟨OY, hOYlo, hOYhi, hOYvlo, hOYvhi, h, vOY⟩ :=
    Lazy_40_hee995b41_sound [⟨8, MN⟩, ⟨8, OXD⟩, ⟨8, M⟩, ⟨8, XD⟩, ⟨8, SY⟩]
      (elemsMatch_of (by
        show [MN.bnd, OXD.bnd, M.bnd, XD.bnd, SY.bnd] = _
        rw [hMN, hOXD, hXD, linElem_bnd, linElem_bnd, linElem_bnd]; simp only [List.map]
        rw [hOXb, hDXb, hSX, hSY]; rfl))
      _ (by limbs_tac [hMN, hOXD, hM, hN, hXD]) h
  have hOYb := lazy_bnd hOYlo hOYhi hOYvlo hOYvhi
  clear hOYlo hOYhi hOYvlo hOYvhi
  refine ⟨OX, OY, hOXb, hOYb, by convert h using 2, L, hLb, gs, DX.value, DY.value, M.value, N.value,
    IX.value, ?_⟩
  have e1 : cert_h6485b116.exprValue (values [⟨8, L⟩, ⟨8, AY⟩, ⟨8, AX⟩, ⟨8, aElem⟩]) =
      2 * (L.value * AY.value) - 3 * (AX.value * AX.value) - aElem.value := by
    simp [PolyShape.exprValue, values, cert_h6485b116]; ring
  have e2 : lazy_h53928760.exprValue (values [⟨8, L⟩, ⟨8, AX⟩]) = L.value * L.value - 2 * AX.value := by
    simp [PolyShape.exprValue, values, lazy_h53928760]; ring
  have e3 : lazy_h31bd1a61.exprValue (values [⟨8, L⟩, ⟨8, AmD⟩, ⟨8, AY⟩]) =
      L.value * AmD.value - AY.value := by
    simp [PolyShape.exprValue, values, lazy_h31bd1a61]; ring
  have e4 : cert_hdaa6ee4a.exprValue (values [⟨8, M⟩, ⟨8, XD⟩, ⟨8, SY⟩, ⟨8, DY⟩]) =
      M.value * XD.value - SY.value + DY.value := by
    simp [PolyShape.exprValue, values, cert_hdaa6ee4a]; ring
  have e5 : lazy_hdbbbc800.exprValue (values [⟨8, M⟩, ⟨8, DX⟩, ⟨8, SX⟩]) =
      M.value * M.value - DX.value - SX.value := by
    simp [PolyShape.exprValue, values, lazy_hdbbbc800]; ring
  have e6 : cert_h4960297a.exprValue (values [⟨8, N⟩, ⟨8, IXD⟩, ⟨8, M⟩, ⟨8, XD⟩, ⟨8, SY⟩]) =
      N.value * IXD.value + 2 * (M.value * XD.value) - 2 * SY.value := by
    simp [PolyShape.exprValue, values, cert_h4960297a]; ring
  have e7 : lazy_h9c68f146.exprValue (values [⟨8, N⟩, ⟨8, NM⟩, ⟨8, SX⟩]) =
      N.value * NM.value + SX.value := by
    simp [PolyShape.exprValue, values, lazy_h9c68f146]
  have e8 : lazy_hee995b41.exprValue (values [⟨8, MN⟩, ⟨8, OXD⟩, ⟨8, M⟩, ⟨8, XD⟩, ⟨8, SY⟩]) =
      MN.value * OXD.value + M.value * XD.value - SY.value := by
    simp [PolyShape.exprValue, values, lazy_hee995b41]; ring
  have m1 : (cert_h6485b116.m : ℤ) = p := rfl
  have m2 : (lazy_h53928760.m : ℤ) = p := rfl
  have m3 : (lazy_h31bd1a61.m : ℤ) = p := rfl
  have m4 : (cert_hdaa6ee4a.m : ℤ) = p := rfl
  have m5 : (lazy_hdbbbc800.m : ℤ) = p := rfl
  have m6 : (cert_h4960297a.m : ℤ) = p := rfl
  have m7 : (lazy_h9c68f146.m : ℤ) = p := rfl
  have m8 : (lazy_hee995b41.m : ℤ) = p := rfl
  rw [e1, m1, modEq_p_iff] at c1
  rw [e2, m2, modEq_p_iff] at vDX
  rw [e3, m3, modEq_p_iff] at vDY
  rw [e4, m4, modEq_p_iff] at c3
  rw [e5, m5, modEq_p_iff] at vIX
  rw [e6, m6, modEq_p_iff] at c4
  rw [e7, m7, modEq_p_iff] at vOX
  rw [e8, m8, modEq_p_iff] at vOY
  have va : ((aElem.value : ℤ) : Fp) = -3 := by
    rw [aElem_value]; push_cast; rw [ZMod.natCast_self]; ring
  have vAmD : AmD.value = AX.value - DX.value := by rw [hAmD, linElem_value]; simp; try ring
  have vXD : XD.value = SX.value - DX.value := by rw [hXD, linElem_value]; simp; try ring
  have vIXD : IXD.value = IX.value - DX.value := by rw [hIXD, linElem_value]; simp; try ring
  have vNM : NM.value = N.value + 2 * M.value := by rw [hNM, linElem_value]; simp; try ring
  have vMN : MN.value = M.value + N.value := by rw [hMN, linElem_value]; simp; try ring
  have vOXD : OXD.value = OX.value - DX.value := by rw [hOXD, linElem_value]; simp; try ring
  rw [vAmD] at vDY
  rw [vXD] at c3 c4 vOY
  rw [vIXD] at c4
  rw [vNM] at vOX
  rw [vMN, vOXD] at vOY
  push_cast at c1 vDX vDY c3 vIX c4 vOX vOY
  rw [va] at c1
  exact ⟨by linear_combination c1, by linear_combination vDX, by linear_combination vDY,
    by linear_combination c3, by linear_combination vIX, by linear_combination c4,
    by linear_combination vOX, by linear_combination vOY⟩

end ZolanaVE.P256
