import VerifiableEncryption.Curve.CompletenessAddLayout
import VerifiableEncryption.Curve.CompletenessReducedOutput
import VerifiableEncryption.Curve.CompletenessLadderInputs

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem addCanonical_native (c : PlainCheckParams) (es : List (Σ w, ElemVal w)) (x : Fp)
    (hm : c.m = p) (hx : ((canonicalFoldedOutput c es).value : Fp) = x) :
    (canonicalFpElem x).limbs = natLimbVector8 ((foldedValue basis c es % (c.m : ℤ)).toNat) := by
  have hn : (canonicalFpElem x).limbs = natLimbVector8 x.val :=
    winX_native x.val (lt_trans (ZMod.val_lt x) p_lt_two_pow)
  have he := canonicalFoldedOutput_native_of_cast c es x hx
  simpa only [hm] using hn.trans (he.symm.trans (canonicalFoldedOutput_native c es))

theorem addX_match (L PX QX : ElemVal 8)
    (hL : L.bnd = balC) (hPX : PX.bnd = reducedC) (hQX : QX.bnd = reducedC) :
    ElemsMatch [⟨8, L⟩, ⟨8, PX⟩, ⟨8, QX⟩] cert_h42186a27.elems :=
  elemsMatch_of (by show [L.bnd, PX.bnd, QX.bnd] = _; rw [hL, hPX, hQX]; rfl)

theorem addX_expr (L PX QX : ElemVal 8) :
    cert_h42186a27.exprValue (values [⟨8, L⟩, ⟨8, PX⟩, ⟨8, QX⟩]) =
      L.value ^ 2 - PX.value - QX.value := by
  simp [PolyShape.exprValue, values, cert_h42186a27]
  ring

theorem addX_field (L PX QX : ElemVal 8) (l x : Fp) (hL : (L.value : Fp) = l)
    (hx : x = l ^ 2 - (PX.value : Fp) - (QX.value : Fp)) :
    ((L.value ^ 2 - PX.value - QX.value : ℤ) : Fp) = x := by
  push_cast
  rw [hL]
  exact hx.symm

theorem addX_complete (hr : RangeComplete) (L PX QX : ElemVal 8)
    (hL : L.bnd = balC) (hPX : PX.bnd = reducedC) (hQX : QX.bnd = reducedC)
    (l x : Fp) (hcL : (L.value : Fp) = l)
    (hx : x = l ^ 2 - (PX.value : Fp) - (QX.value : Fp)) :
    ∀ k : List.Vector F 8 → Prop, k (canonicalFpElem x).limbs →
      CheckPolynomial_24_h42186a27 (vec3 L PX QX) k := by
  have hb := addX_match L PX QX hL hPX hQX
  have hv : ((canonicalFoldedOutput cert_h42186a27 [⟨8, L⟩, ⟨8, PX⟩, ⟨8, QX⟩]).value : Fp) = x :=
    (canonicalFoldedOutput_cast cert_h42186a27 _ cert_h42186a27_sound rfl rfl hb).trans
      ((congrArg (fun z : ℤ => (z : Fp)) (addX_expr L PX QX)).trans
        (addX_field L PX QX l x hcL hx))
  intro k hk
  apply unifiedX_complete _ hb _ (vec3_inputs L PX QX) hr k
  exact (congrArg k (addCanonical_native cert_h42186a27 _ x rfl hv)).mp hk

noncomputable def addYElems (L PX RX PY : ElemVal 8) : List (Σ w, ElemVal w) :=
  [⟨8, L⟩, ⟨8, linElem [(1, PX), (-1, RX)]⟩, ⟨8, PY⟩]

theorem addY_match (L PX RX PY : ElemVal 8)
    (hL : L.bnd = balC) (hPX : PX.bnd = reducedC) (hRX : RX.bnd = reducedC) (hPY : PY.bnd = reducedC) :
    ElemsMatch (addYElems L PX RX PY) cert_h2629e496.elems := by
  apply elemsMatch_of
  show [L.bnd, (linElem [(1, PX), (-1, RX)]).bnd, PY.bnd] = _
  rw [linElem_bnd]
  simp only [List.map]
  rw [hL, hPX, hRX, hPY]
  rfl

theorem addY_expr (L PX RX PY : ElemVal 8) :
    cert_h2629e496.exprValue (values (addYElems L PX RX PY)) =
      L.value * (PX.value - RX.value) - PY.value := by
  simp [addYElems, PolyShape.exprValue, values, cert_h2629e496, linElem_value]
  ring

theorem addY_field (L PX RX PY : ElemVal 8) (l y : Fp) (hL : (L.value : Fp) = l)
    (hy : y = l * ((PX.value : Fp) - (RX.value : Fp)) - (PY.value : Fp)) :
    ((L.value * (PX.value - RX.value) - PY.value : ℤ) : Fp) = y := by
  push_cast
  rw [hL]
  exact hy.symm

theorem addY_complete (hr : RangeComplete) (L PX RX PY : ElemVal 8)
    (hL : L.bnd = balC) (hPX : PX.bnd = reducedC) (hRX : RX.bnd = reducedC) (hPY : PY.bnd = reducedC)
    (l y : Fp) (hcL : (L.value : Fp) = l)
    (hy : y = l * ((PX.value : Fp) - (RX.value : Fp)) - (PY.value : Fp)) :
    ∀ k : List.Vector F 8 → Prop, k (canonicalFpElem y).limbs →
      CheckPolynomial_24_h2629e496 (vec3 L (linElem [(1, PX), (-1, RX)]) PY) k := by
  have hb := addY_match L PX RX PY hL hPX hRX hPY
  have hv : ((canonicalFoldedOutput cert_h2629e496 (addYElems L PX RX PY)).value : Fp) = y :=
    (canonicalFoldedOutput_cast cert_h2629e496 _ cert_h2629e496_sound rfl rfl hb).trans
      ((congrArg (fun z : ℤ => (z : Fp)) (addY_expr L PX RX PY)).trans
        (addY_field L PX RX PY l y hcL hy))
  intro k hk
  apply unifiedY_complete _ hb _ (vec3_inputs L (linElem [(1, PX), (-1, RX)]) PY) hr k
  exact (congrArg k (addCanonical_native cert_h2629e496 _ y rfl hv)).mp hk

end ZolanaVE.P256.Completeness
