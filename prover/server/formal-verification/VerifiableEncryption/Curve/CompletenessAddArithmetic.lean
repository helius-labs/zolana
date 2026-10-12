import VerifiableEncryption.Curve.CompletenessAddLayout

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem addFlag_match (P Q : ElemVal 8) (b : Bool)
    (hP : P.bnd = reducedC) (hQ : Q.bnd = reducedC) :
    ElemsMatch [⟨1, bitElem b⟩, ⟨8, linElem [(1, Q), (-1, P)]⟩] cert_hd299af1e.elems := by
  apply elemsMatch_of
  show [(bitElem b).bnd, (linElem [(1, Q), (-1, P)]).bnd] = _
  rw [linElem_bnd]
  simp only [List.map]
  rw [hQ, hP]
  rfl

theorem addFlag_expr_general (P Q : ElemVal 8) (B : ElemVal 1) :
    cert_hd299af1e.exprValue (values [⟨1, B⟩, ⟨8, linElem [(1, Q), (-1, P)]⟩]) =
      B.value * (Q.value - P.value) := by
  simp [PolyShape.exprValue, values, cert_hd299af1e, linElem_value, sub_eq_add_neg]

theorem addFlag_expr (P Q : ElemVal 8) (b : Bool) :
    cert_hd299af1e.exprValue (values [⟨1, bitElem b⟩, ⟨8, linElem [(1, Q), (-1, P)]⟩]) =
      (bitElem b).value * (Q.value - P.value) := addFlag_expr_general P Q (bitElem b)

theorem addFlag_zero (P Q : ElemVal 8) (b : Bool)
    (hz : (if b then (1 : Fp) else 0) * ((Q.value : Fp) - (P.value : Fp)) = 0) :
    cert_hd299af1e.exprValue (values [⟨1, bitElem b⟩, ⟨8, linElem [(1, Q), (-1, P)]⟩])
      ≡ 0 [ZMOD (cert_hd299af1e.m : ℤ)] := by
  rw [addFlag_expr, show (cert_hd299af1e.m : ℤ) = p from rfl, modEq_p_iff, bitElem_value]
  cases b <;> push_cast <;> simpa using hz

theorem addFlag_complete (hr : RangeComplete) (P Q : ElemVal 8) (b : Bool)
    (hP : P.bnd = reducedC) (hQ : Q.bnd = reducedC)
    (hz : (if b then (1 : Fp) else 0) * ((Q.value : Fp) - (P.value : Fp)) = 0) :
    CheckPolynomial_9_hd299af1e (flagVector b (linElem [(1, Q), (-1, P)])) := by
  exact flagProduct_complete _ (addFlag_match P Q b hP hQ) _
    (flagVector_inputs b (linElem [(1, Q), (-1, P)])) hr (addFlag_zero P Q b hz)

noncomputable def addSlopeElems (L PX PY QX QY : ElemVal 8) (b : Bool) : List (Σ w, ElemVal w) :=
  [⟨8, L⟩, ⟨8, linElem [(1, QX), (-1, PX)]⟩, ⟨1, bitElem b⟩,
    ⟨8, PY⟩, ⟨8, PX⟩, ⟨8, aElem⟩, ⟨8, linElem [(1, QY), (-1, PY)]⟩]

theorem addSlope_match (L PX PY QX QY : ElemVal 8) (b : Bool)
    (hL : L.bnd = balC) (hPX : PX.bnd = reducedC) (hPY : PY.bnd = reducedC)
    (hQX : QX.bnd = reducedC) (hQY : QY.bnd = reducedC) :
    ElemsMatch (addSlopeElems L PX PY QX QY b) cert_h8f49f727.elems := by
  apply elemsMatch_of
  show [L.bnd, (linElem [(1, QX), (-1, PX)]).bnd, (bitElem b).bnd,
    PY.bnd, PX.bnd, aElem.bnd, (linElem [(1, QY), (-1, PY)]).bnd] = _
  rw [linElem_bnd, linElem_bnd]
  simp only [List.map]
  rw [hL, hPX, hPY, hQX, hQY]
  rfl

theorem addSlope_expr (L PX PY QX QY : ElemVal 8) (b : Bool) :
    cert_h8f49f727.exprValue (values (addSlopeElems L PX PY QX QY b)) =
      L.value * (QX.value - PX.value) + 2 * L.value * (bitElem b).value * PY.value -
        3 * (bitElem b).value * PX.value ^ 2 - (bitElem b).value * aElem.value -
        (QY.value - PY.value) := by
  simp [addSlopeElems, PolyShape.exprValue, values, cert_h8f49f727, linElem_value]
  ring

theorem addSlope_zero (L PX PY QX QY : ElemVal 8) (b : Bool) (l : Fp)
    (hL : (L.value : Fp) = l)
    (hz : l * ((QX.value : Fp) - (PX.value : Fp)) +
      2 * l * (if b then 1 else 0) * (PY.value : Fp) -
      3 * (if b then 1 else 0) * (PX.value : Fp) ^ 2 +
      3 * (if b then 1 else 0) - ((QY.value : Fp) - (PY.value : Fp)) = 0) :
    cert_h8f49f727.exprValue (values (addSlopeElems L PX PY QX QY b))
      ≡ 0 [ZMOD (cert_h8f49f727.m : ℤ)] := by
  rw [addSlope_expr, show (cert_h8f49f727.m : ℤ) = p from rfl, modEq_p_iff, bitElem_value]
  cases b <;> push_cast <;> rw [hL, aElem_cast] <;>
    simp only [Bool.false_eq_true, if_false, if_true] at hz ⊢ <;>
    linear_combination hz

theorem addSlope_complete (hr : RangeComplete) (PX PY QX QY : ElemVal 8) (b : Bool)
    (hPX : PX.bnd = reducedC) (hPY : PY.bnd = reducedC)
    (hQX : QX.bnd = reducedC) (hQY : QY.bnd = reducedC) (l : Fp)
    (hz : l * ((QX.value : Fp) - (PX.value : Fp)) +
      2 * l * (if b then 1 else 0) * (PY.value : Fp) -
      3 * (if b then 1 else 0) * (PX.value : Fp) ^ 2 +
      3 * (if b then 1 else 0) - ((QY.value : Fp) - (PY.value : Fp)) = 0) :
    CheckPolynomial_49_h8f49f727 (slopeVector (slopeElem l)
      (linElem [(1, QX), (-1, PX)]) b PY PX (linElem [(1, QY), (-1, PY)])) := by
  exact unifiedSlope_complete _ (addSlope_match (slopeElem l) PX PY QX QY b rfl hPX hPY hQX hQY) _
    (slopeVector_inputs (slopeElem l) (linElem [(1, QX), (-1, PX)]) b PY PX
      (linElem [(1, QY), (-1, PY)])) hr
    (addSlope_zero (slopeElem l) PX PY QX QY b l (slopeElem_cast l) hz)

end ZolanaVE.P256.Completeness
