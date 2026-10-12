import VerifiableEncryption.Curve.CompletenessReducedOutput
import VerifiableEncryption.Curve.CompletenessLadderInputs
import VerifiableEncryption.Curve.CompletenessGeneratedTripleAddComposition
import VerifiableEncryption.Field.CompletenessGeneratedEval_5

/-! The actual reduced x output of a triple, separated from the geometric
existence proof. Its only input obligations are the literal arithmetic bounds
and the value equation supplied by the mathematical triple construction. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

attribute [local irreducible] CheckPolynomial_24_h38fe3d8b

noncomputable def tripleXElems (X DX : ElemVal 8) (l r : Fp) : List (Σ w, ElemVal w) :=
  [⟨8, linElem [(1, slopeElem r), (-1, slopeElem l)]⟩, ⟨8, X⟩, ⟨8, DX⟩]

theorem tripleXElems_match (X DX : ElemVal 8)
    (hX : X.bnd = reducedC) (hDX : DX.bnd = lazyOut lazy_h30893ad5)
    (l r : Fp) : ElemsMatch (tripleXElems X DX l r) cert_h38fe3d8b.elems := by
  apply elemsMatch_of
  show [(linElem [(1, slopeElem r), (-1, slopeElem l)]).bnd, X.bnd, DX.bnd] = _
  rw [linElem_bnd]
  simp only [List.map]
  rw [hX, hDX]
  rfl

theorem tripleX_expr (X DX L R : ElemVal 8) :
    cert_h38fe3d8b.exprValue (values
      [⟨8, linElem [(1, R), (-1, L)]⟩, ⟨8, X⟩, ⟨8, DX⟩]) =
      (R.value - L.value) ^ 2 - X.value - DX.value := by
  simp [PolyShape.exprValue, values, cert_h38fe3d8b, linElem_value]
  ring

theorem tripleXElems_cast (X DX : ElemVal 8)
    (hX : X.bnd = reducedC) (hDX : DX.bnd = lazyOut lazy_h30893ad5)
    (l r : Fp) :
    ((canonicalFoldedOutput cert_h38fe3d8b (tripleXElems X DX l r)).value : Fp) =
      (r - l) ^ 2 - (X.value : Fp) - (DX.value : Fp) := by
  calc
    _ = (cert_h38fe3d8b.exprValue (values (tripleXElems X DX l r)) : Fp) :=
      canonicalFoldedOutput_cast cert_h38fe3d8b (tripleXElems X DX l r)
        cert_h38fe3d8b_sound rfl rfl (tripleXElems_match X DX hX hDX l r)
    _ = ((((slopeElem r).value - (slopeElem l).value) ^ 2 - X.value - DX.value : ℤ) : Fp) :=
      congrArg (fun z : ℤ => (z : Fp)) (tripleX_expr X DX (slopeElem l) (slopeElem r))
    _ = _ := by
      push_cast
      rw [slopeElem_cast r, slopeElem_cast l]

theorem tripleX_layout (X DX L R : ElemVal 8) :
    limbLists [⟨8, linElem [(1, R), (-1, L)]⟩, ⟨8, X⟩, ⟨8, DX⟩] =
      outputCheckInputs (tripleXInput R.limbs L.limbs X.limbs DX.limbs) := by
  simp only [limbLists, List.map_cons, List.map_nil, outputCheckInputs]
  rw [vec8_toList (linElem [(1, R), (-1, L)]).limbs,
    vec8_toList X.limbs, vec8_toList DX.limbs]
  simp only [tripleXInput, linPair_limb, List.Vector.get_cons_zero,
    List.Vector.get_cons_succ, Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod,
    Int.cast_one, Int.cast_neg, one_mul, neg_one_mul, sub_eq_add_neg]
  rfl

theorem tripleXElems_layout (X DX : ElemVal 8) (l r : Fp) :
    limbLists (tripleXElems X DX l r) = outputCheckInputs
      (tripleXInput (slopeElem r).limbs (slopeElem l).limbs X.limbs DX.limbs) :=
  tripleX_layout X DX (slopeElem l) (slopeElem r)

theorem tripleXElems_native (X DX : ElemVal 8)
    (hX : X.bnd = reducedC) (hDX : DX.bnd = lazyOut lazy_h30893ad5)
    (l r x3 : Fp)
    (hx3 : x3 = (r - l) ^ 2 - (X.value : Fp) - (DX.value : Fp)) :
    (canonicalFpElem x3).limbs = natLimbVector8
      ((foldedValue basis cert_h38fe3d8b (tripleXElems X DX l r) %
        (cert_h38fe3d8b.m : ℤ)).toNat) := by
  have hc := (tripleXElems_cast X DX hX hDX l r).trans hx3.symm
  have hn : (canonicalFpElem x3).limbs = natLimbVector8 x3.val :=
    winX_native x3.val (lt_trans (ZMod.val_lt x3) p_lt_two_pow)
  have hm := canonicalFoldedOutput_native_of_cast cert_h38fe3d8b (tripleXElems X DX l r) x3 hc
  simpa only [show cert_h38fe3d8b.m = p from rfl] using
    hn.trans (hm.symm.trans (canonicalFoldedOutput_native cert_h38fe3d8b (tripleXElems X DX l r)))

theorem tripleX_complete (hr : RangeComplete) (X DX : ElemVal 8)
    (hX : X.bnd = reducedC) (hDX : DX.bnd = lazyOut lazy_h30893ad5)
    (l r x3 : Fp)
    (hx3 : x3 = (r - l) ^ 2 - (X.value : Fp) - (DX.value : Fp)) :
    ∀ k : List.Vector F 8 → Prop, k (canonicalFpElem x3).limbs →
      CheckPolynomial_24_h38fe3d8b
        (tripleXInput (slopeElem r).limbs (slopeElem l).limbs X.limbs DX.limbs) k := by
  intro k hk
  apply CheckPolynomial_24_h38fe3d8b_complete (tripleXElems X DX l r)
    (tripleXElems_match X DX hX hDX l r) _ (tripleXElems_layout X DX l r) hr k
  exact (congrArg k (tripleXElems_native X DX hX hDX l r x3 hx3)).mp hk

end ZolanaVE.P256.Completeness
