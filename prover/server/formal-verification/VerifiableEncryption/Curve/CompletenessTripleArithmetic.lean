import VerifiableEncryption.Curve.CompletenessTripleX
import VerifiableEncryption.Field.CompletenessGeneratedChain_4
import VerifiableEncryption.Field.CompletenessGeneratedChain_11
import VerifiableEncryption.Field.CompletenessGeneratedLazy_1

/-! Actual tangent, doubled-x and return-slope witnesses for the ordinary
triple. These constructors take arithmetic equations, which the finite-point
geometry proves, and construct the extracted predicates. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

attribute [local irreducible] CheckPolynomial_32_h35a4bc86
  Lazy_16_h30893ad5 CheckPolynomial_24_h6ce7114d

def tripleInputGroups16 (V : List.Vector F 16) : List (List F) :=
  [[V.get 0, V.get 1, V.get 2, V.get 3, V.get 4, V.get 5, V.get 6, V.get 7],
    [V.get 8, V.get 9, V.get 10, V.get 11, V.get 12, V.get 13, V.get 14, V.get 15]]

def tripleInputGroups32 (V : List.Vector F 32) : List (List F) :=
  [[V.get 0, V.get 1, V.get 2, V.get 3, V.get 4, V.get 5, V.get 6, V.get 7],
    [V.get 8, V.get 9, V.get 10, V.get 11, V.get 12, V.get 13, V.get 14, V.get 15],
    [V.get 16, V.get 17, V.get 18, V.get 19, V.get 20, V.get 21, V.get 22, V.get 23],
    [V.get 24, V.get 25, V.get 26, V.get 27, V.get 28, V.get 29, V.get 30, V.get 31]]

theorem triple_aElem_native : aElem.limbs = quadCompositionA := by
  apply List.Vector.toList_injective
  change (mkElem aLimbs aC a_fits).limbs.toList = _
  rw [mkElem_limbs]
  change [(aLimbs 0 : F), aLimbs 1, aLimbs 2, aLimbs 3,
    aLimbs 4, aLimbs 5, aLimbs 6, aLimbs 7] =
    [4294967292, 4294967295, 4294967295, 0, 0, 0, 1, 4294967295]
  norm_num [aLimbs, Fin.coe_ofNat_eq_mod]

theorem tripleTangent_layout (L Y X : ElemVal 8) :
    limbLists [⟨8, L⟩, ⟨8, Y⟩, ⟨8, X⟩, ⟨8, aElem⟩] =
      tripleInputGroups32 (quadTangentInput L.limbs Y.limbs X.limbs) := by
  simp only [limbLists, List.map_cons, List.map_nil]
  rw [triple_aElem_native, vec8_toList L.limbs, vec8_toList Y.limbs,
    vec8_toList X.limbs, vec8_toList quadCompositionA]
  simp only [tripleInputGroups32, quadTangentInput, List.Vector.get_cons_zero,
    List.Vector.get_cons_succ, Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod]
  rfl

theorem tripleDoubleX_layout (L X : ElemVal 8) :
    limbLists [⟨8, L⟩, ⟨8, X⟩] =
      tripleInputGroups16 (quadDoubleXInput L.limbs X.limbs) := by
  simp only [limbLists, List.map_cons, List.map_nil]
  rw [vec8_toList L.limbs, vec8_toList X.limbs]
  simp only [tripleInputGroups16, quadDoubleXInput, List.Vector.get_cons_zero,
    List.Vector.get_cons_succ, Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod]
  rfl

theorem linSingleton_limb (a : ℤ) (A : ElemVal 8) (i : Fin 8) :
    (linElem [(a, A)]).limbs.get i = (a : F) * A.limbs.get i := by
  rw [linElem, mkElem_limb]
  simp only [linX, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
  push_cast
  rw [← A.limb_eq]
  ring

theorem tripleRatio_layout (R X DX Y : ElemVal 8) :
    limbLists [⟨8, R⟩, ⟨8, linElem [(1, X), (-1, DX)]⟩,
      ⟨8, linElem [(2, Y)]⟩] =
      outputCheckInputs (tripleRatioInput R.limbs X.limbs DX.limbs Y.limbs) := by
  simp only [limbLists, List.map_cons, List.map_nil, outputCheckInputs]
  rw [vec8_toList R.limbs, vec8_toList (linElem [(1, X), (-1, DX)]).limbs,
    vec8_toList (linElem [(2, Y)]).limbs]
  simp only [tripleRatioInput, linPair_limb, linSingleton_limb,
    List.Vector.get_cons_zero, List.Vector.get_cons_succ,
    Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod,
    Int.cast_one, Int.cast_neg, Int.cast_ofNat, one_mul, neg_one_mul, sub_eq_add_neg]
  rfl

theorem tripleTangent_match (L Y X : ElemVal 8)
    (hL : L.bnd = balC) (hY : Y.bnd = reducedC) (hX : X.bnd = reducedC) :
    ElemsMatch [⟨8, L⟩, ⟨8, Y⟩, ⟨8, X⟩, ⟨8, aElem⟩] cert_h35a4bc86.elems :=
  elemsMatch_of (by show [L.bnd, Y.bnd, X.bnd, aElem.bnd] = _; rw [hL, hY, hX]; rfl)

theorem tripleTangent_expr (L Y X : ElemVal 8) :
    cert_h35a4bc86.exprValue (values [⟨8, L⟩, ⟨8, Y⟩, ⟨8, X⟩, ⟨8, aElem⟩]) =
      2 * L.value * Y.value - 3 * X.value * X.value - aElem.value := by
  simp [PolyShape.exprValue, values, cert_h35a4bc86]
  ring

theorem tripleTangent_zero (L Y X : ElemVal 8)
    (hl : 2 * (L.value : Fp) * (Y.value : Fp) = 3 * (X.value : Fp) ^ 2 - 3) :
    cert_h35a4bc86.exprValue (values [⟨8, L⟩, ⟨8, Y⟩, ⟨8, X⟩, ⟨8, aElem⟩])
      ≡ 0 [ZMOD (cert_h35a4bc86.m : ℤ)] := by
  rw [tripleTangent_expr, show (cert_h35a4bc86.m : ℤ) = p from rfl, modEq_p_iff]
  push_cast
  rw [aElem_cast]
  linear_combination hl

theorem tripleTangent_complete (hr : RangeComplete) (X Y : ElemVal 8)
    (hX : X.bnd = reducedC) (hY : Y.bnd = reducedC) (l : Fp)
    (hl : 2 * l * (Y.value : Fp) = 3 * (X.value : Fp) ^ 2 - 3) :
    CheckPolynomial_32_h35a4bc86
      (quadTangentInput (slopeElem l).limbs Y.limbs X.limbs) := by
  let L := slopeElem l
  have hb : ElemsMatch [⟨8, L⟩, ⟨8, Y⟩, ⟨8, X⟩, ⟨8, aElem⟩] cert_h35a4bc86.elems :=
    tripleTangent_match L Y X rfl hY hX
  have hL : 2 * (L.value : Fp) * (Y.value : Fp) = 3 * (X.value : Fp) ^ 2 - 3 :=
    (congrArg (fun z : Fp => 2 * z * (Y.value : Fp)) (slopeElem_cast l)).trans hl
  have hz := tripleTangent_zero L Y X hL
  exact CheckPolynomial_32_h35a4bc86_complete _ hb
    (quadTangentInput L.limbs Y.limbs X.limbs) (tripleTangent_layout L Y X) hr hz

theorem tripleDoubleX_match (L X : ElemVal 8)
    (hL : L.bnd = balC) (hX : X.bnd = reducedC) :
    ElemsMatch [⟨8, L⟩, ⟨8, X⟩] lazy_h30893ad5.elems :=
  elemsMatch_of (by show [L.bnd, X.bnd] = _; rw [hL, hX]; rfl)

theorem tripleDoubleX_expr (L X : ElemVal 8) :
    lazy_h30893ad5.exprValue (values [⟨8, L⟩, ⟨8, X⟩]) =
      L.value * L.value - 2 * X.value := by
  simp [PolyShape.exprValue, values, lazy_h30893ad5]
  ring

theorem tripleDoubleX_value (L X DX : ElemVal 8)
    (hv : DX.value ≡ lazy_h30893ad5.exprValue (values [⟨8, L⟩, ⟨8, X⟩])
      [ZMOD (lazy_h30893ad5.m : ℤ)]) :
    (DX.value : Fp) = (L.value : Fp) ^ 2 - 2 * (X.value : Fp) := by
  rw [tripleDoubleX_expr, show (lazy_h30893ad5.m : ℤ) = p from rfl, modEq_p_iff] at hv
  push_cast at hv
  rw [hv]
  ring

theorem tripleDoubleX_complete (X : ElemVal 8) (hX : X.bnd = reducedC) (l : Fp) :
    ∃ DX : ElemVal 8, DX.bnd = lazyOut lazy_h30893ad5 ∧
      (DX.value : Fp) = l ^ 2 - 2 * (X.value : Fp) ∧
      ∀ k : List.Vector F 8 → Prop, k DX.limbs →
        Lazy_16_h30893ad5 (quadDoubleXInput (slopeElem l).limbs X.limbs) k := by
  let L := slopeElem l
  have hb : ElemsMatch [⟨8, L⟩, ⟨8, X⟩] lazy_h30893ad5.elems :=
    tripleDoubleX_match L X rfl hX
  obtain ⟨DX, hDX, hv, ha⟩ := Lazy_16_h30893ad5_complete _ hb
    (quadDoubleXInput L.limbs X.limbs) (tripleDoubleX_layout L X)
  exact ⟨DX, hDX, (tripleDoubleX_value L X DX hv).trans
    (congrArg (fun z : Fp => z ^ 2 - 2 * (X.value : Fp)) (slopeElem_cast l)), ha⟩

theorem tripleRatio_match (R X DX Y : ElemVal 8)
    (hR : R.bnd = balC) (hX : X.bnd = reducedC)
    (hDX : DX.bnd = lazyOut lazy_h30893ad5) (hY : Y.bnd = reducedC) :
    ElemsMatch [⟨8, R⟩, ⟨8, linElem [(1, X), (-1, DX)]⟩,
      ⟨8, linElem [(2, Y)]⟩] cert_h6ce7114d.elems := by
  apply elemsMatch_of
  show [R.bnd, (linElem [(1, X), (-1, DX)]).bnd, (linElem [(2, Y)]).bnd] = _
  rw [linElem_bnd, linElem_bnd]
  simp only [List.map]
  rw [hR, hX, hDX, hY]
  rfl

theorem tripleRatio_expr (R X DX Y : ElemVal 8) :
    cert_h6ce7114d.exprValue (values [⟨8, R⟩, ⟨8, linElem [(1, X), (-1, DX)]⟩,
      ⟨8, linElem [(2, Y)]⟩]) =
      R.value * (X.value - DX.value) - 2 * Y.value := by
  simp [PolyShape.exprValue, values, cert_h6ce7114d, linElem_value]
  ring

theorem tripleRatio_zero (R X DX Y : ElemVal 8)
    (he : (R.value : Fp) * ((X.value : Fp) - (DX.value : Fp)) = 2 * (Y.value : Fp)) :
    cert_h6ce7114d.exprValue (values [⟨8, R⟩, ⟨8, linElem [(1, X), (-1, DX)]⟩,
      ⟨8, linElem [(2, Y)]⟩]) ≡ 0 [ZMOD (cert_h6ce7114d.m : ℤ)] := by
  rw [tripleRatio_expr, show (cert_h6ce7114d.m : ℤ) = p from rfl, modEq_p_iff]
  push_cast
  linear_combination he

theorem tripleRatio_complete (hr : RangeComplete) (X DX Y : ElemVal 8)
    (hX : X.bnd = reducedC) (hDX : DX.bnd = lazyOut lazy_h30893ad5)
    (hY : Y.bnd = reducedC) (r : Fp)
    (he : r * ((X.value : Fp) - (DX.value : Fp)) = 2 * (Y.value : Fp)) :
    CheckPolynomial_24_h6ce7114d
      (tripleRatioInput (slopeElem r).limbs X.limbs DX.limbs Y.limbs) := by
  let R := slopeElem r
  have hb := tripleRatio_match R X DX Y rfl hX hDX hY
  have hR : (R.value : Fp) * ((X.value : Fp) - (DX.value : Fp)) = 2 * (Y.value : Fp) :=
    (congrArg (fun z : Fp => z * ((X.value : Fp) - (DX.value : Fp)))
      (slopeElem_cast r)).trans he
  have hz := tripleRatio_zero R X DX Y hR
  exact CheckPolynomial_24_h6ce7114d_complete _ hb _
    (tripleRatio_layout R X DX Y) hr hz

end ZolanaVE.P256.Completeness
