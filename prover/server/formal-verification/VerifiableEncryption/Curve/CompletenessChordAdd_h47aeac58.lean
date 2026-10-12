import VerifiableEncryption.Curve.CompletenessChordAdd
import VerifiableEncryption.Field.CompletenessGeneratedChain_5
import VerifiableEncryption.Field.CompletenessGeneratedChain_9

/-! Exact arithmetic instantiation for an extracted chord-add variant.
Validation is recorded separately. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem add_h47aeac58_complete (hr : RangeComplete) (PX PY QX QY : ElemVal 8)
    (hPX : PX.bnd = reducedC) (hPY : PY.bnd = selC)
    (hQX : QX.bnd = reducedC) (hQY : QY.bnd = reducedC)
    (hP : OnCurve (PX.value : Fp) (PY.value : Fp))
    (hQ : OnCurve (QX.value : Fp) (QY.value : Fp))
    (hx : (PX.value : Fp) ≠ (QX.value : Fp)) :
    ∃ SX SY : ElemVal 8, SX.bnd = reducedC ∧ SY.bnd = reducedC ∧
      limbNat SX.limbs < p ∧ limbNat SY.limbs < p ∧
      (∃ hS : OnCurve (SX.value : Fp) (SY.value : Fp), mkPoint hS = mkPoint hP + mkPoint hQ) ∧
      ∀ k : List.Vector (List.Vector F 8) 2 → Prop,
        k (SX.limbs ::ᵥ SY.limbs ::ᵥ List.Vector.nil) →
        Add_8_8_8_8_h47aeac58 PX.limbs PY.limbs QX.limbs QY.limbs k := by
  let l : Fp := ((QY.value : Fp) - (PY.value : Fp)) / ((QX.value : Fp) - (PX.value : Fp))
  have hl : l * ((QX.value : Fp) - (PX.value : Fp)) = (QY.value : Fp) - (PY.value : Fp) :=
    div_mul_cancel₀ _ (sub_ne_zero.mpr hx.symm)
  let sx : Fp := l ^ 2 - (PX.value : Fp) - (QX.value : Fp)
  let sy : Fp := l * ((PX.value : Fp) - sx) - (PY.value : Fp)
  obtain ⟨hOut, pOut⟩ := slope_add hP hQ hx hl (show sx = _ from rfl) (show sy = _ from rfl)
  let SX := canonicalFpElem sx
  let SY := canonicalFpElem sy
  have hSX : SX.bnd = reducedC := rfl
  have hSY : SY.bnd = reducedC := rfl
  have cSX : (SX.value : Fp) = sx := canonicalFpElem_cast sx
  have cSY : (SY.value : Fp) = sy := canonicalFpElem_cast sy
  let XD := linElem [(1, QX), (-1, PX)]
  have vXD : XD.value = QX.value - PX.value := by simp [XD, linElem_value]; ring
  have hbD : ElemsMatch [⟨8, XD⟩] lazy_h12f7d03a.elems := elemsMatch_of (by
    show [XD.bnd] = _
    dsimp only [XD]
    rw [linElem_bnd]; simp only [List.map]; rw [hQX, hPX]; rfl)
  obtain ⟨D2, hD2, vD2, dActual⟩ := Lazy_8_h12f7d03a_complete _ hbD
    (addDifferenceInput QX.limbs PX.limbs) (by
      simp only [limbLists, List.map_cons, List.map_nil]
      rw [vec8_toList XD.limbs]
      simp only [addDifferenceInput, XD, linPair_limb,
        List.Vector.get_cons_zero, List.Vector.get_cons_succ,
        Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod,
        Int.cast_one, Int.cast_neg, one_mul, neg_one_mul, sub_eq_add_neg]
      rfl)
  have eeD : lazy_h12f7d03a.exprValue (values [⟨8, XD⟩]) = XD.value ^ 2 := by
    simp [PolyShape.exprValue, values, lazy_h12f7d03a]; ring
  rw [eeD, vXD, show (lazy_h12f7d03a.m : ℤ) = p from rfl, modEq_p_iff] at vD2
  push_cast at vD2
  let XS := linElem [(1, SX), (1, PX), (1, QX)]
  let YD := linElem [(1, QY), (-1, PY)]
  have vXS : XS.value = SX.value + PX.value + QX.value := by simp [XS, linElem_value]; ring
  have vYD : YD.value = QY.value - PY.value := by simp [YD, linElem_value]; ring
  have hbF : ElemsMatch [⟨8, XS⟩, ⟨8, D2⟩, ⟨8, YD⟩] cert_h85e25851.elems := elemsMatch_of (by
    show [XS.bnd, D2.bnd, YD.bnd] = _
    dsimp only [XS, YD]
    rw [linElem_bnd, linElem_bnd]; simp only [List.map]
    rw [hSX, hPX, hQX, hPY, hQY, hD2]; rfl)
  have zF : cert_h85e25851.exprValue (values [⟨8, XS⟩, ⟨8, D2⟩, ⟨8, YD⟩])
      ≡ 0 [ZMOD (cert_h85e25851.m : ℤ)] := by
    have ee : cert_h85e25851.exprValue (values [⟨8, XS⟩, ⟨8, D2⟩, ⟨8, YD⟩]) =
        XS.value * D2.value - YD.value ^ 2 := by
      simp [PolyShape.exprValue, values, cert_h85e25851]; ring
    rw [ee, vXS, vYD, show (cert_h85e25851.m : ℤ) = p from rfl, modEq_p_iff]
    push_cast
    rw [cSX, vD2, ← hl]
    dsimp [sx]
    ring
  have first := CheckPolynomial_24_h85e25851_complete _ hbF
    (addFirstInput SX.limbs PX.limbs QX.limbs D2.limbs QY.limbs PY.limbs) (by
      simp only [limbLists, List.map_cons, List.map_nil]
      rw [vec8_toList XS.limbs, vec8_toList D2.limbs, vec8_toList YD.limbs]
      simp only [addFirstInput, XS, YD, linTriple_limb, linPair_limb,
        List.Vector.get_cons_zero, List.Vector.get_cons_succ,
        Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod,
        Int.cast_one, Int.cast_neg, one_mul, neg_one_mul, sub_eq_add_neg]
      rfl) hr zF
  let XP := linElem [(1, SX), (-1, PX)]
  let YP := linElem [(1, SY), (1, PY)]
  have vXP : XP.value = SX.value - PX.value := by simp [XP, linElem_value]; ring
  have vYP : YP.value = SY.value + PY.value := by simp [YP, linElem_value]
  have hbS : ElemsMatch [⟨8, YD⟩, ⟨8, XP⟩, ⟨8, YP⟩, ⟨8, XD⟩] cert_h03b2b1ec.elems :=
    elemsMatch_of (by
      show [YD.bnd, XP.bnd, YP.bnd, XD.bnd] = _
      dsimp only [YD, XP, YP, XD]
      rw [linElem_bnd, linElem_bnd, linElem_bnd, linElem_bnd]
      simp only [List.map]; rw [hSX, hSY, hPX, hPY, hQX, hQY]; rfl)
  have zS : cert_h03b2b1ec.exprValue (values [⟨8, YD⟩, ⟨8, XP⟩, ⟨8, YP⟩, ⟨8, XD⟩])
      ≡ 0 [ZMOD (cert_h03b2b1ec.m : ℤ)] := by
    have ee : cert_h03b2b1ec.exprValue (values [⟨8, YD⟩, ⟨8, XP⟩, ⟨8, YP⟩, ⟨8, XD⟩]) =
        YD.value * XP.value + YP.value * XD.value := by
      simp [PolyShape.exprValue, values, cert_h03b2b1ec]
    rw [ee, vYD, vXP, vYP, vXD, show (cert_h03b2b1ec.m : ℤ) = p from rfl, modEq_p_iff]
    push_cast
    rw [cSX, cSY, ← hl]
    dsimp [sy]
    ring
  have second := CheckPolynomial_32_h03b2b1ec_complete _ hbS
    (addSecondInput QY.limbs PY.limbs SX.limbs PX.limbs SY.limbs QX.limbs) (by
      simp only [limbLists, List.map_cons, List.map_nil]
      rw [vec8_toList YD.limbs, vec8_toList XP.limbs, vec8_toList YP.limbs, vec8_toList XD.limbs]
      simp only [addSecondInput, YD, XP, YP, XD, linPair_limb,
        List.Vector.get_cons_zero, List.Vector.get_cons_succ,
        Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod,
        Int.cast_one, Int.cast_neg, one_mul, neg_one_mul, sub_eq_add_neg]
      rfl) hr zS
  obtain ⟨px, rx, vx⟩ := unsigned8_pieces_complete hr sx.val
  obtain ⟨py, ry, vy⟩ := unsigned8_pieces_complete hr sy.val
  let pieces := jointPieces px py
  have nativeSX (i : Fin 8) : SX.limbs.get i =
      pieces.get ⟨3 * i.val, by omega⟩ + pieces.get ⟨3 * i.val + 1, by omega⟩ * 2048 +
      pieces.get ⟨3 * i.val + 2, by omega⟩ * 4194304 := by
    change (canonicalFpElem sx).limbs.get i = _
    rw [congrArg (fun v : List.Vector F 8 => v.get i) (canonicalFpElem_native sx)]
    dsimp only [pieces]
    rw [jointPieces_left px py ⟨3 * i.val, by omega⟩,
      jointPieces_left px py ⟨3 * i.val + 1, by omega⟩,
      jointPieces_left px py ⟨3 * i.val + 2, by omega⟩]
    exact vx i
  have nativeSY (i : Fin 8) : SY.limbs.get i =
      pieces.get ⟨24 + 3 * i.val, by omega⟩ + pieces.get ⟨24 + 3 * i.val + 1, by omega⟩ * 2048 +
      pieces.get ⟨24 + 3 * i.val + 2, by omega⟩ * 4194304 := by
    change (canonicalFpElem sy).limbs.get i = _
    rw [congrArg (fun v : List.Vector F 8 => v.get i) (canonicalFpElem_native sy)]
    dsimp only [pieces]
    simp only [Nat.add_assoc]
    rw [jointPieces_right px py ⟨3 * i.val, by omega⟩,
      jointPieces_right px py ⟨3 * i.val + 1, by omega⟩,
      jointPieces_right px py ⟨3 * i.val + 2, by omega⟩]
    exact vy i
  have hS : OnCurve (SX.value : Fp) (SY.value : Fp) := by rw [cSX, cSY]; exact hOut
  have pS : mkPoint hS = mkPoint hP + mkPoint hQ := by
    rw [pOut]
    exact mkPoint_inj.mpr ⟨cSX, cSY⟩
  refine ⟨SX, SY, hSX, hSY, ?_, ?_, ⟨hS, pS⟩, ?_⟩
  · change limbNat (canonicalFpElem sx).limbs < p
    unfold canonicalFpElem
    rw [canonicalNatElem_limbNat]; exact ZMod.val_lt sx
  · change limbNat (canonicalFpElem sy).limbs < p
    unfold canonicalFpElem
    rw [canonicalNatElem_limbNat]; exact ZMod.val_lt sy
  · intro k hk
    have nativeSX0 (i : Fin 8) : SX.limbs.get i =
        pieces.get ⟨0 + 3 * i.val, by omega⟩ +
        pieces.get ⟨0 + 3 * i.val + 1, by omega⟩ * 2048 +
        pieces.get ⟨0 + 3 * i.val + 2, by omega⟩ * 4194304 := by
      simpa only [Nat.zero_add] using nativeSX i
    apply Add_8_8_8_8_h47aeac58_compose PX.limbs PY.limbs QX.limbs QY.limbs SX.limbs SY.limbs D2.limbs
      pieces (jointPieces_ranges px py rx ry) nativeSX0 nativeSY dActual first second k
    exact hk

end ZolanaVE.P256.Completeness
