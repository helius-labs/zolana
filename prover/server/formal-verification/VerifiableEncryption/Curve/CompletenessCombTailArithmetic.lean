import VerifiableEncryption.Curve.CompletenessAddOutputs
import VerifiableEncryption.Field.CompletenessCombReduce
import VerifiableEncryption.Field.CompletenessCombRecover

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

def combTailVector (L WX EX WY : List.Vector F 8) : List.Vector F 24 :=
  vec![L.get 0, L.get 1, L.get 2, L.get 3, L.get 4, L.get 5, L.get 6, L.get 7,
    WX.get 0 - EX.get 0, WX.get 1 - EX.get 1, WX.get 2 - EX.get 2, WX.get 3 - EX.get 3,
    WX.get 4 - EX.get 4, WX.get 5 - EX.get 5, WX.get 6 - EX.get 6, WX.get 7 - EX.get 7,
    WY.get 0, WY.get 1, WY.get 2, WY.get 3, WY.get 4, WY.get 5, WY.get 6, WY.get 7]

theorem combTailVector_eq (L WX EX WY : ElemVal 8) :
    combTailVector L.limbs WX.limbs EX.limbs WY.limbs =
      vec3 L (linElem [(1, WX), (-1, EX)]) WY := by
  apply List.Vector.toList_injective
  simp [combTailVector, vec3, linDiff_limb]
  simpa only [← List.Vector.get_zero] using (linDiff_limb WX EX 0).symm

theorem combTailReduce_match (X : ElemVal 8) (hX : X.bnd = lazyOut lazy_h7e1bb4d8) :
    ElemsMatch [⟨8, X⟩] cert_h78194ae0.elems :=
  elemsMatch_of (by show [X.bnd] = _; rw [hX]; rfl)

theorem combTailReduce_expr (X : ElemVal 8) :
    cert_h78194ae0.exprValue (values [⟨8, X⟩]) = X.value := by
  simp [PolyShape.exprValue, values, cert_h78194ae0]

theorem combTailReduce_complete (hr : RangeComplete) (X : ElemVal 8)
    (hX : X.bnd = lazyOut lazy_h7e1bb4d8) :
    ∀ k : List.Vector F 8 → Prop, k (canonicalFpElem (X.value : Fp)).limbs →
      CheckPolynomial_8_h78194ae0 X.limbs k := by
  have hb := combTailReduce_match X hX
  have hc : ((canonicalFoldedOutput cert_h78194ae0 [⟨8, X⟩]).value : Fp) = (X.value : Fp) :=
    (canonicalFoldedOutput_cast cert_h78194ae0 _ cert_h78194ae0_sound rfl rfl hb).trans
      (congrArg (fun z : ℤ => (z : Fp)) (combTailReduce_expr X))
  intro k hk
  apply combReduce_complete _ hb _ rfl hr k
  exact (congrArg k (addCanonical_native cert_h78194ae0 _ (X.value : Fp) rfl hc)).mp hk

noncomputable def combTailRecoverElems (L WX EX WY : ElemVal 8) : List (Σ w, ElemVal w) :=
  [⟨8, L⟩, ⟨8, linElem [(1, WX), (-1, EX)]⟩, ⟨8, WY⟩]

theorem combTailRecover_match (L WX EX WY : ElemVal 8)
    (hL : L.bnd = balC) (hWX : WX.bnd = reducedC) (hEX : EX.bnd = reducedC) (hWY : WY.bnd = packC) :
    ElemsMatch (combTailRecoverElems L WX EX WY) cert_h0845ed76.elems := by
  apply elemsMatch_of
  show [L.bnd, (linElem [(1, WX), (-1, EX)]).bnd, WY.bnd] = _
  rw [linElem_bnd]
  simp only [List.map]
  rw [hL, hWX, hEX, hWY]
  rfl

theorem combTailRecover_expr (L WX EX WY : ElemVal 8) :
    cert_h0845ed76.exprValue (values (combTailRecoverElems L WX EX WY)) =
      L.value * (WX.value - EX.value) - WY.value := by
  simp [combTailRecoverElems, PolyShape.exprValue, values, cert_h0845ed76, linElem_value]
  ring

theorem combTailRecover_field (L WX EX WY X : ElemVal 8)
    (hEX : (EX.value : Fp) = (X.value : Fp)) :
    ((L.value * (WX.value - EX.value) - WY.value : ℤ) : Fp) =
      ((L.value * (WX.value - X.value) - WY.value : ℤ) : Fp) := by
  push_cast
  rw [hEX]

theorem combTailRecover_layout (L WX EX WY : ElemVal 8) :
    limbLists (combTailRecoverElems L WX EX WY) =
      outputCheckInputs (combTailVector L.limbs WX.limbs EX.limbs WY.limbs) := by
  rw [combTailVector_eq]
  exact vec3_inputs L (linElem [(1, WX), (-1, EX)]) WY

theorem combTailRecover_complete (hr : RangeComplete) (L WX EX WY X : ElemVal 8)
    (hL : L.bnd = balC) (hWX : WX.bnd = reducedC) (hEX : EX.bnd = reducedC) (hWY : WY.bnd = packC)
    (hcEX : (EX.value : Fp) = (X.value : Fp)) :
    ∀ k : List.Vector F 8 → Prop,
      k (canonicalFpElem ((L.value * (WX.value - X.value) - WY.value : ℤ) : Fp)).limbs →
      CheckPolynomial_24_h0845ed76 (combTailVector L.limbs WX.limbs EX.limbs WY.limbs) k := by
  have hb := combTailRecover_match L WX EX WY hL hWX hEX hWY
  have hc : ((canonicalFoldedOutput cert_h0845ed76 (combTailRecoverElems L WX EX WY)).value : Fp) =
      ((L.value * (WX.value - X.value) - WY.value : ℤ) : Fp) :=
    (canonicalFoldedOutput_cast cert_h0845ed76 _ cert_h0845ed76_sound rfl rfl hb).trans
      ((congrArg (fun z : ℤ => (z : Fp)) (combTailRecover_expr L WX EX WY)).trans
        (combTailRecover_field L WX EX WY X hcEX))
  intro k hk
  apply combRecover_complete _ hb _ (combTailRecover_layout L WX EX WY) hr k
  exact (congrArg k (addCanonical_native cert_h0845ed76 _ _ rfl hc)).mp hk

end ZolanaVE.P256.Completeness
