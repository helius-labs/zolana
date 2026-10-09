import VerifiableEncryption.Curve.Pieces
import VerifiableEncryption.Curve.Steps
import VerifiableEncryption.Field.Instances

/-!
`curve.add` (incomplete affine addition with hinted result coordinates).
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

/-- The two cross-multiplied chord equations of `curve.add`, on integer
values modulo `p`; `chord_add_int` turns them into the group law. -/
theorem modEq_p_iff {a b : ℤ} : a ≡ b [ZMOD p] ↔ ((a : ℤ) : Fp) = ((b : ℤ) : Fp) :=
  (ZMod.intCast_eq_intCast_iff a b p).symm

def ChordRel (xp yp xq yq xs ys : ℤ) : Prop :=
  (xs + xp + xq) * (xq - xp) ^ 2 - (yq - yp) ^ 2 ≡ 0 [ZMOD p] ∧
    (yq - yp) * (xs - xp) + (ys + yp) * (xq - xp) ≡ 0 [ZMOD p]

theorem toList_cons8 {α : Type*} (a0 a1 a2 a3 a4 a5 a6 a7 : α) :
    (a0 ::ᵥ a1 ::ᵥ a2 ::ᵥ a3 ::ᵥ a4 ::ᵥ a5 ::ᵥ a6 ::ᵥ a7 ::ᵥ List.Vector.nil).toList =
      [a0, a1, a2, a3, a4, a5, a6, a7] := rfl

/-- `Lin([1, -1])` of two limbs, in the extracted gate form. -/
def linSub (a b : F) : F := Gates.add (Gates.add 0 (Gates.mul a 1)) (Gates.mul b (-1))

theorem linSub_cast (a b : ℤ) : linSub (a : F) (b : F) = ((a - b : ℤ) : F) := by
  simp only [linSub, Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul]
  push_cast; ring

theorem sub_hxs (A B : ElemVal 8) {c : ElemC} (hf : Fits (fun i => A.ints.get i - B.ints.get i) c) :
    limbLists [⟨8, mkElem _ c hf⟩] =
      [[linSub (A.limbs.get 0) (B.limbs.get 0), linSub (A.limbs.get 1) (B.limbs.get 1),
        linSub (A.limbs.get 2) (B.limbs.get 2), linSub (A.limbs.get 3) (B.limbs.get 3),
        linSub (A.limbs.get 4) (B.limbs.get 4), linSub (A.limbs.get 5) (B.limbs.get 5),
        linSub (A.limbs.get 6) (B.limbs.get 6), linSub (A.limbs.get 7) (B.limbs.get 7)]] := by
  simp only [limbLists, List.map, mkElem_limbs, ElemVal.limb_eq, linSub_cast]

theorem add_hd2848b17_sound (hl : LookupSound RangeCheck 11) (PX PY QX QY : ElemVal 8)
    (hPX : PX.bnd = reducedC) (hPY : PY.bnd = reducedC) (hQX : QX.bnd = reducedC)
    (hQY : QY.bnd = reducedC) {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : Add_8_8_8_8_hd2848b17 PX.limbs PY.limbs QX.limbs QY.limbs k) :
    ∃ SX SY : ElemVal 8, SX.bnd = reducedC ∧ SY.bnd = reducedC ∧
      k (SX.limbs ::ᵥ SY.limbs ::ᵥ List.Vector.nil) ∧
      ChordRel PX.value PY.value QX.value QY.value SX.value SY.value := by
  unfold Add_8_8_8_8_hd2848b17 Add_8_8_8_8_hd2848b17_p1 at h
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
  set DY := mkElem _ _ (sub_red_fits hQY hPY) with hDY
  have e24 : cert_h4c8a98c4.elems = [uniC 0 (3 * (2 ^ 32 - 1)) 0 (3 * (2 ^ 256 - 1)),
      ⟨lazy_h12f7d03a.outLo, lazy_h12f7d03a.outHi, lazy_h12f7d03a.outVlo, lazy_h12f7d03a.outVhi⟩,
      subRedC] := rfl
  have c24 := CheckPolynomial_24_h4c8a98c4_sound hl [⟨8, XS⟩, ⟨8, D2⟩, ⟨8, DY⟩]
    (elemsMatch_of (by rw [e24]; show [XS.bnd, D2.bnd, DY.bnd] = _; rw [hD2b]; rfl)) _ (by limbs_tac [hXS, hDY, hSX]) hc24
  set SXP := mkElem _ _ (sub_red_fits hSXb hPX) with hSXP
  set SYP := mkElem _ _ (add_red_fits hSYb hPY) with hSYP
  have e32 : cert_hf6aee3c9.elems = [subRedC, subRedC, uniC 0 (2 * (2 ^ 32 - 1)) 0 (2 * (2 ^ 256 - 1)),
      subRedC] := rfl
  have c32 := CheckPolynomial_32_hf6aee3c9_sound hl [⟨8, DY⟩, ⟨8, SXP⟩, ⟨8, SYP⟩, ⟨8, DX⟩]
    (elemsMatch_of (by rw [e32]; rfl)) _ (by limbs_tac [hDY, hSXP, hSYP, hDX, hSX, hSY]) hc32
  refine ⟨SX, SY, rfl, rfl, ?_, ?_⟩
  · convert hk using 3
    · apply List.Vector.toList_injective
      limbs_tac [hSX]
    · apply List.Vector.toList_injective
      limbs_tac [hSY]
  · have m24 : (cert_h4c8a98c4.m : ℤ) = p := rfl
    have m32 : (cert_hf6aee3c9.m : ℤ) = p := rfl
    have ml : (lazy_h12f7d03a.m : ℤ) = p := rfl
    rw [m24] at c24
    rw [m32] at c32
    rw [ml] at hD2v
    have x24 : cert_h4c8a98c4.exprValue (values [⟨8, XS⟩, ⟨8, D2⟩, ⟨8, DY⟩]) =
        XS.value * D2.value - DY.value * DY.value := by
      simp [PolyShape.exprValue, values, cert_h4c8a98c4]; ring
    have x32 : cert_hf6aee3c9.exprValue (values [⟨8, DY⟩, ⟨8, SXP⟩, ⟨8, SYP⟩, ⟨8, DX⟩]) =
        DY.value * SXP.value + SYP.value * DX.value := by
      simp [PolyShape.exprValue, values, cert_hf6aee3c9]
    have xl : lazy_h12f7d03a.exprValue (values [⟨8, DX⟩]) = DX.value * DX.value := by
      simp [PolyShape.exprValue, values, lazy_h12f7d03a]
    rw [x24] at c24
    rw [x32] at c32
    rw [xl] at hD2v
    have vXS : XS.value = SX.value + PX.value + QX.value := by
      rw [hXS, mkElem_value, rec8_add, rec8_add, ← SX.value_eq, ← PX.value_eq, ← QX.value_eq]
    have vDY : DY.value = QY.value - PY.value := by
      rw [hDY, mkElem_value, rec8_sub, ← QY.value_eq, ← PY.value_eq]
    have vDX : DX.value = QX.value - PX.value := by
      rw [hDX, mkElem_value, rec8_sub, ← QX.value_eq, ← PX.value_eq]
    have vSXP : SXP.value = SX.value - PX.value := by
      rw [hSXP, mkElem_value, rec8_sub, ← SX.value_eq, ← PX.value_eq]
    have vSYP : SYP.value = SY.value + PY.value := by
      rw [hSYP, mkElem_value, rec8_add, ← SY.value_eq, ← PY.value_eq]
    rw [modEq_p_iff] at c24 c32 hD2v
    push_cast [vXS, vDY, vDX, vSXP, vSYP] at c24 c32 hD2v
    constructor
    · rw [modEq_p_iff]
      push_cast
      linear_combination c24 - (SX.value + PX.value + QX.value : Fp) * hD2v
    · rw [modEq_p_iff]
      push_cast
      linear_combination c32

end ZolanaVE.P256
