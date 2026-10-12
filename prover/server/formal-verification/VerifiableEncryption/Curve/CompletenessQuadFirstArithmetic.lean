import VerifiableEncryption.Curve.CompletenessTripleArithmetic
import VerifiableEncryption.Curve.CompletenessQuadMath
import VerifiableEncryption.Curve.CompletenessCanonical
import VerifiableEncryption.Field.CompletenessGeneratedChain_22
import VerifiableEncryption.Field.CompletenessGeneratedChain_27
import VerifiableEncryption.Field.CompletenessGeneratedChain_78
import VerifiableEncryption.Field.CompletenessGeneratedLazy_13
import VerifiableEncryption.Field.CompletenessGeneratedLazy_33
import VerifiableEncryption.Field.CompletenessGeneratedLazy_38
import VerifiableEncryption.Field.CompletenessGeneratedLazy_58

/-! First-quad arithmetic with abstract bounded elements. All eager native
primitive calls are constructed; geometry supplies the field equations. -/

namespace ZolanaVE.P256.Completeness
open ZolanaVE.Field ZolanaVE.EmcurveChecks

attribute [local irreducible] CheckPolynomial_32_h35a4bc86
  CheckPolynomial_32_hf71c5652 CheckPolynomial_49_h8696e642 CheckPolynomial_40_h78e663c8
  Lazy_16_h30893ad5 Lazy_24_h846878ce Lazy_24_h33616364 Lazy_24_h9c68f146 Lazy_40_h57fc266d

structure QuadFirstArithmeticWitness (L M N AX AY SX SY : ElemVal 8) (hs : F) where
  DX : ElemVal 8
  DY : ElemVal 8
  IX : ElemVal 8
  OX : ElemVal 8
  OY : ElemVal 8
  b : Bool
  oxBound : OX.bnd = lazyOut lazy_h9c68f146
  oyBound : OY.bnd = lazyOut lazy_h57fc266d
  outputPoint : ∃ hO : OnCurve (OX.value : Fp) (OY.value : Fp),
    ∀ (hA : OnCurve (AX.value : Fp) (AY.value : Fp))
      (hT : OnCurve (SX.value : Fp) (SY.value : Fp)),
      mkPoint hO = 4 • mkPoint hA + mkPoint hT
  tangent : CheckPolynomial_32_h35a4bc86
    (quadTangentInput L.limbs AY.limbs AX.limbs)
  doubleX : ∀ k : List.Vector F 8 → Prop, k DX.limbs →
    Lazy_16_h30893ad5 (quadDoubleXInput L.limbs AX.limbs) k
  doubleY : ∀ k : List.Vector F 8 → Prop, k DY.limbs →
    Lazy_24_h846878ce (quadDoubleYInput L.limbs AX.limbs DX.limbs AY.limbs) k
  chord : CheckPolynomial_32_hf71c5652
    (quadChordInput M.limbs SX.limbs DX.limbs SY.limbs DY.limbs)
  nativeFlag : GatesDef.is_zero (quadNativeProduct L.limbs hs) (if b then 1 else 0)
  flagCheck : CheckPolynomial_49_h8696e642
    (quadFlagInput b M.limbs DY.limbs SY.limbs DX.limbs SX.limbs)
  intermediateX : ∀ k : List.Vector F 8 → Prop, k IX.limbs →
    Lazy_24_h33616364 (quadIntermediateInput M.limbs DX.limbs SX.limbs) k
  second : CheckPolynomial_40_h78e663c8
    (quadSecondInput N.limbs IX.limbs DX.limbs M.limbs SX.limbs SY.limbs)
  outX : ∀ k : List.Vector F 8 → Prop, k OX.limbs →
    Lazy_24_h9c68f146 (quadOutXInput N.limbs M.limbs SX.limbs) k
  outY : ∀ k : List.Vector F 8 → Prop, k OY.limbs →
    Lazy_40_h57fc266d (quadOutYInput M.limbs N.limbs
      OX.limbs DX.limbs SX.limbs SY.limbs) k

theorem quadFirst_arithmetic_complete (hr : RangeComplete) (L M N AX AY SX SY : ElemVal 8)
    (hL : L.bnd = balC) (hM : M.bnd = balC) (hN : N.bnd = balC)
    (hAX : AX.bnd = reducedC) (hAY : AY.bnd = reducedC)
    (hSX : SX.bnd = reducedC) (hSY : SY.bnd = unpackC) (hs : F)
    (hA : OnCurve (AX.value : Fp) (AY.value : Fp))
    (hT : OnCurve (SX.value : Fp) (SY.value : Fp))
    (l dx dy m v ix ox oy : Fp)
    (hLc : (L.value : Fp) = l) (hMc : (M.value : Fp) = m) (hNc : (N.value : Fp) = v)
    (cons : QuadAddCons (AX.value : Fp) (AY.value : Fp) (SX.value : Fp) (SY.value : Fp)
      l dx dy m v ix ox oy)
    (last : LastSlope (SX.value : Fp) (SY.value : Fp) dx dy m)
    (hOut : OnCurve ox oy) (pOut : mkPoint hOut = 4 • mkPoint hA + mkPoint hT) :
    Nonempty (QuadFirstArithmeticWitness L M N AX AY SX SY hs) := by
  classical
  have hb1 := tripleTangent_match L AY AX hL hAY hAX
  have hl : 2 * (L.value : Fp) * (AY.value : Fp) = 3 * (AX.value : Fp) ^ 2 - 3 := by
    rw [hLc]
    exact cons.tangent
  have tan := CheckPolynomial_32_h35a4bc86_complete _ hb1
    (quadTangentInput L.limbs AY.limbs AX.limbs) (tripleTangent_layout L AY AX)
    hr (tripleTangent_zero L AY AX hl)
  obtain ⟨DX, hDX, vDX, dxActual⟩ := Lazy_16_h30893ad5_complete _
    (tripleDoubleX_match L AX hL hAX)
    (quadDoubleXInput L.limbs AX.limbs) (tripleDoubleX_layout L AX)
  have cDX : (DX.value : Fp) = dx := by
    rw [tripleDoubleX_value L AX DX vDX, hLc, cons.dx]
  let AD := linElem [(1, AX), (-1, DX)]
  have valAD : AD.value = AX.value - DX.value := by simp [AD, linElem_value] <;> ring
  have hbDY : ElemsMatch [⟨8, L⟩, ⟨8, AD⟩, ⟨8, AY⟩] lazy_h846878ce.elems :=
    elemsMatch_of (by
      show [L.bnd, AD.bnd, AY.bnd] = _
      dsimp only [AD]; rw [linElem_bnd]; simp only [List.map]; rw [hL, hAX, hDX, hAY]; rfl)
  obtain ⟨DY, hDY, vDY, dyActual⟩ := Lazy_24_h846878ce_complete _ hbDY
    (quadDoubleYInput L.limbs AX.limbs DX.limbs AY.limbs) (by
      simp only [limbLists, List.map_cons, List.map_nil]
      rw [vec8_toList L.limbs, vec8_toList AD.limbs, vec8_toList AY.limbs]
      norm_num only [quadDoubleYInput, AD, linPair_limb, sub_eq_add_neg, List.Vector.get_cons_zero, List.Vector.get_cons_succ, Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod, Int.cast_one, Int.cast_neg, Int.cast_ofNat, one_mul, neg_one_mul, sub_eq_add_neg] <;> rfl)
  have eeDY : lazy_h846878ce.exprValue (values [⟨8, L⟩, ⟨8, AD⟩, ⟨8, AY⟩]) =
      L.value * AD.value - AY.value := by simp [PolyShape.exprValue, values, lazy_h846878ce] <;> ring
  rw [eeDY, valAD, show (lazy_h846878ce.m : ℤ) = p from rfl, modEq_p_iff] at vDY
  push_cast at vDY
  rw [hLc, cDX] at vDY
  have cDY : (DY.value : Fp) = dy := by rw [vDY, cons.dy]
  let XD := linElem [(1, SX), (-1, DX)]
  have valXD : XD.value = SX.value - DX.value := by simp [XD, linElem_value] <;> ring
  have hb3 : ElemsMatch [⟨8, M⟩, ⟨8, XD⟩, ⟨8, SY⟩, ⟨8, DY⟩] cert_hf71c5652.elems :=
    elemsMatch_of (by
      show [M.bnd, XD.bnd, SY.bnd, DY.bnd] = _
      dsimp only [XD]; rw [linElem_bnd]; simp only [List.map]; rw [hM, hSX, hDX, hSY, hDY]; rfl)
  have z3 : cert_hf71c5652.exprValue (values [⟨8, M⟩, ⟨8, XD⟩, ⟨8, SY⟩, ⟨8, DY⟩])
      ≡ 0 [ZMOD (cert_hf71c5652.m : ℤ)] := by
    have ee : cert_hf71c5652.exprValue (values [⟨8, M⟩, ⟨8, XD⟩, ⟨8, SY⟩, ⟨8, DY⟩]) =
        M.value * XD.value - SY.value + DY.value := by
      simp [PolyShape.exprValue, values, cert_hf71c5652] <;> ring
    rw [ee, valXD, show (cert_hf71c5652.m : ℤ) = p from rfl, modEq_p_iff]
    push_cast
    rw [hMc, cDX, cDY]
    exact cons.chord
  have chord := CheckPolynomial_32_hf71c5652_complete _ hb3
    (quadChordInput M.limbs SX.limbs DX.limbs SY.limbs DY.limbs) (by
      simp only [limbLists, List.map_cons, List.map_nil]
      rw [vec8_toList M.limbs, vec8_toList XD.limbs, vec8_toList SY.limbs, vec8_toList DY.limbs]
      norm_num only [quadChordInput, XD, linPair_limb, sub_eq_add_neg, List.Vector.get_cons_zero, List.Vector.get_cons_succ, Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod, Int.cast_one, Int.cast_neg, Int.cast_ofNat, one_mul, neg_one_mul, sub_eq_add_neg] <;> rfl) hr z3
  let b : Bool := decide (quadNativeProduct L.limbs hs = 0)
  have nativeFlag : GatesDef.is_zero (quadNativeProduct L.limbs hs) (if b then 1 else 0) := by
    have hz := zeroIndicator_native_spec (quadNativeProduct L.limbs hs)
    by_cases hp : quadNativeProduct L.limbs hs = 0 <;>
      simpa [b, zeroIndicator, hp] using hz
  let YS := linElem [(1, DY), (1, SY)]
  let XS := linElem [(1, DX), (1, SX)]
  have valYS : YS.value = DY.value + SY.value := by simp [YS, linElem_value] <;> ring
  have valXS : XS.value = DX.value + SX.value := by simp [XS, linElem_value] <;> ring
  have hb5 : ElemsMatch [⟨1, bitElem b⟩, ⟨8, M⟩, ⟨8, YS⟩, ⟨8, XS⟩, ⟨8, DX⟩, ⟨8, SX⟩, ⟨8, aElem⟩]
      cert_h8696e642.elems := elemsMatch_of (by
    show [(bitElem b).bnd, M.bnd, YS.bnd, XS.bnd, DX.bnd, SX.bnd, aElem.bnd] = _
    dsimp only [YS, XS]; rw [linElem_bnd, linElem_bnd]; simp only [List.map]; rw [hM, hDY, hSY, hDX, hSX]; rfl)
  have z5 : cert_h8696e642.exprValue (values
      [⟨1, bitElem b⟩, ⟨8, M⟩, ⟨8, YS⟩, ⟨8, XS⟩, ⟨8, DX⟩, ⟨8, SX⟩, ⟨8, aElem⟩])
      ≡ 0 [ZMOD (cert_h8696e642.m : ℤ)] := by
    have ee : cert_h8696e642.exprValue (values
        [⟨1, bitElem b⟩, ⟨8, M⟩, ⟨8, YS⟩, ⟨8, XS⟩, ⟨8, DX⟩, ⟨8, SX⟩, ⟨8, aElem⟩]) =
        (bitElem b).value * (M.value * YS.value - XS.value * XS.value + DX.value * SX.value - aElem.value) := by
      simp [PolyShape.exprValue, values, cert_h8696e642] <;> ring
    rw [ee, valYS, valXS, show (cert_h8696e642.m : ℤ) = p from rfl, modEq_p_iff]
    push_cast
    rw [hMc, cDX, cDY, aElem_cast]
    have hh : m * (dy + (SY.value : Fp)) - (dx + (SX.value : Fp)) ^ 2 + dx * (SX.value : Fp) + 3 = 0 := last
    rw [pow_two] at hh
    linear_combination ((bitElem b).value : Fp) * hh
  have flagCheck := CheckPolynomial_49_h8696e642_complete _ hb5
    (quadFlagInput b M.limbs DY.limbs SY.limbs DX.limbs SX.limbs) (by
      simp only [limbLists, List.map_cons, List.map_nil]
      rw [vec8_toList M.limbs, vec8_toList YS.limbs, vec8_toList XS.limbs,
        vec8_toList DX.limbs, vec8_toList SX.limbs, vec8_toList aElem.limbs]
      rw [triple_aElem_native]
      cases b <;> norm_num only [quadFlagInput, quadCompositionA, bitElem, YS, XS,
        linPair_limb, List.Vector.get_cons_zero, List.Vector.get_cons_succ, Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod, Int.cast_one, Int.cast_neg, Int.cast_ofNat, one_mul, neg_one_mul, sub_eq_add_neg] <;> rfl) hr z5
  have hbIX : ElemsMatch [⟨8, M⟩, ⟨8, DX⟩, ⟨8, SX⟩] lazy_h33616364.elems :=
    elemsMatch_of (by show [M.bnd, DX.bnd, SX.bnd] = _; rw [hM, hDX, hSX]; rfl)
  obtain ⟨IX, hIX, vIX, ixActual⟩ := Lazy_24_h33616364_complete _ hbIX
    (quadIntermediateInput M.limbs DX.limbs SX.limbs) (by
      simp only [limbLists, List.map_cons, List.map_nil]
      rw [vec8_toList M.limbs, vec8_toList DX.limbs, vec8_toList SX.limbs]
      rfl)
  have eeIX : lazy_h33616364.exprValue (values [⟨8, M⟩, ⟨8, DX⟩, ⟨8, SX⟩]) =
      M.value * M.value - DX.value - SX.value := by
    simp [PolyShape.exprValue, values, lazy_h33616364] <;> ring
  rw [eeIX, show (lazy_h33616364.m : ℤ) = p from rfl, modEq_p_iff] at vIX
  push_cast at vIX
  rw [hMc, cDX] at vIX
  have cIX : (IX.value : Fp) = ix := by rw [vIX, cons.ix] <;> ring
  let IXD := linElem [(1, IX), (-1, DX)]
  have valIXD : IXD.value = IX.value - DX.value := by simp [IXD, linElem_value] <;> ring
  have hb4 : ElemsMatch [⟨8, N⟩, ⟨8, IXD⟩, ⟨8, M⟩, ⟨8, XD⟩, ⟨8, SY⟩] cert_h78e663c8.elems :=
    elemsMatch_of (by
      show [N.bnd, IXD.bnd, M.bnd, XD.bnd, SY.bnd] = _
      dsimp only [IXD, XD]; rw [linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hN, hM, hIX, hDX, hSX, hSY]; rfl)
  have z4 : cert_h78e663c8.exprValue (values [⟨8, N⟩, ⟨8, IXD⟩, ⟨8, M⟩, ⟨8, XD⟩, ⟨8, SY⟩])
      ≡ 0 [ZMOD (cert_h78e663c8.m : ℤ)] := by
    have ee : cert_h78e663c8.exprValue (values [⟨8, N⟩, ⟨8, IXD⟩, ⟨8, M⟩, ⟨8, XD⟩, ⟨8, SY⟩]) =
        N.value * IXD.value + 2 * M.value * XD.value - 2 * SY.value := by
      simp [PolyShape.exprValue, values, cert_h78e663c8] <;> ring
    rw [ee, valIXD, valXD, show (cert_h78e663c8.m : ℤ) = p from rfl, modEq_p_iff]
    push_cast
    rw [hNc,
      hMc, cIX, cDX]
    exact cons.second
  have second := CheckPolynomial_40_h78e663c8_complete _ hb4
    (quadSecondInput N.limbs IX.limbs DX.limbs M.limbs SX.limbs SY.limbs) (by
      simp only [limbLists, List.map_cons, List.map_nil]
      rw [vec8_toList N.limbs, vec8_toList IXD.limbs, vec8_toList M.limbs,
        vec8_toList XD.limbs, vec8_toList SY.limbs]
      norm_num only [quadSecondInput, IXD, XD, linPair_limb, sub_eq_add_neg, List.Vector.get_cons_zero, List.Vector.get_cons_succ, Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod, Int.cast_one, Int.cast_neg, Int.cast_ofNat, one_mul, neg_one_mul, sub_eq_add_neg] <;> rfl) hr z4
  let NM := linElem [(1, N), (2, M)]
  have valNM : NM.value = N.value + 2 * M.value := by simp [NM, linElem_value] <;> ring
  have hbOX : ElemsMatch [⟨8, N⟩, ⟨8, NM⟩, ⟨8, SX⟩] lazy_h9c68f146.elems :=
    elemsMatch_of (by
      show [N.bnd, NM.bnd, SX.bnd] = _
      dsimp only [NM]; rw [linElem_bnd]; simp only [List.map]; rw [hN, hM, hSX]; rfl)
  obtain ⟨OX, hOX, vOX, oxActual⟩ := Lazy_24_h9c68f146_complete _ hbOX
    (quadOutXInput N.limbs M.limbs SX.limbs) (by
      simp only [limbLists, List.map_cons, List.map_nil]
      rw [vec8_toList N.limbs, vec8_toList NM.limbs, vec8_toList SX.limbs]
      norm_num only [quadOutXInput, NM, linPair_limb, List.Vector.get_cons_zero, List.Vector.get_cons_succ, Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod, Int.cast_one, Int.cast_neg, Int.cast_ofNat, one_mul, neg_one_mul, sub_eq_add_neg] <;> rfl)
  have eeOX : lazy_h9c68f146.exprValue (values [⟨8, N⟩, ⟨8, NM⟩, ⟨8, SX⟩]) =
      N.value * NM.value + SX.value := by simp [PolyShape.exprValue, values, lazy_h9c68f146]
  rw [eeOX, valNM, show (lazy_h9c68f146.m : ℤ) = p from rfl, modEq_p_iff] at vOX
  push_cast at vOX
  rw [hNc,
    hMc] at vOX
  have cOX : (OX.value : Fp) = ox := by rw [vOX, cons.ox]
  let MN := linElem [(1, M), (1, N)]
  let OXD := linElem [(1, OX), (-1, DX)]
  have valMN : MN.value = M.value + N.value := by simp [MN, linElem_value] <;> ring
  have valOXD : OXD.value = OX.value - DX.value := by simp [OXD, linElem_value] <;> ring
  have hbOY : ElemsMatch [⟨8, MN⟩, ⟨8, OXD⟩, ⟨8, M⟩, ⟨8, XD⟩, ⟨8, SY⟩] lazy_h57fc266d.elems :=
    elemsMatch_of (by
      show [MN.bnd, OXD.bnd, M.bnd, XD.bnd, SY.bnd] = _
      dsimp only [MN, OXD, XD]; rw [linElem_bnd, linElem_bnd, linElem_bnd]; simp only [List.map]
      rw [hM, hN, hOX, hDX, hSX, hSY]; rfl)
  obtain ⟨OY, hOY, vOY, oyActual⟩ := Lazy_40_h57fc266d_complete _ hbOY
    (quadOutYInput M.limbs N.limbs OX.limbs DX.limbs SX.limbs SY.limbs) (by
      simp only [limbLists, List.map_cons, List.map_nil]
      rw [vec8_toList MN.limbs, vec8_toList OXD.limbs, vec8_toList M.limbs,
        vec8_toList XD.limbs, vec8_toList SY.limbs]
      norm_num only [quadOutYInput, MN, OXD, XD, linPair_limb, sub_eq_add_neg, List.Vector.get_cons_zero, List.Vector.get_cons_succ, Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod, Int.cast_one, Int.cast_neg, Int.cast_ofNat, one_mul, neg_one_mul, sub_eq_add_neg] <;> rfl)
  have eeOY : lazy_h57fc266d.exprValue (values [⟨8, MN⟩, ⟨8, OXD⟩, ⟨8, M⟩, ⟨8, XD⟩, ⟨8, SY⟩]) =
      MN.value * OXD.value + M.value * XD.value - SY.value := by
    simp [PolyShape.exprValue, values, lazy_h57fc266d] <;> ring
  rw [eeOY, valMN, valOXD, valXD, show (lazy_h57fc266d.m : ℤ) = p from rfl, modEq_p_iff] at vOY
  push_cast at vOY
  rw [hNc,
    hMc, cOX, cDX] at vOY
  have cOY : (OY.value : Fp) = oy := by rw [vOY, cons.oy]
  have hO : OnCurve (OX.value : Fp) (OY.value : Fp) := by rw [cOX, cOY]; exact hOut
  have pO : mkPoint hO = 4 • mkPoint hA + mkPoint hT := by
    rw [← pOut]
    exact mkPoint_inj.mpr ⟨cOX, cOY⟩
  exact ⟨⟨DX, DY, IX, OX, OY, b, hOX, hOY,
    ⟨hO, fun _ _ => pO⟩, tan, dxActual, dyActual, chord, nativeFlag, flagCheck,
    ixActual, second, oxActual, oyActual⟩⟩

end ZolanaVE.P256.Completeness
