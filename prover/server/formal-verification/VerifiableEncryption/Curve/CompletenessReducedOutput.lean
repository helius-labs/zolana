import VerifiableEncryption.Curve.CompletenessCoordinates

/-! Identify constructed reduced outputs directly from the integer remainder.
This requires certificate soundness and bounded mathematical inputs, never
lookup soundness or an assumed successful extracted predicate. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

def canonicalFoldedOutput (c : PlainCheckParams) (es : List (Σ w, ElemVal w)) : ElemVal 8 :=
  winX ((foldedValue basis c es % (p : ℤ)).toNat) (p_remainder_width _)

theorem canonicalFoldedOutput_bound (c : PlainCheckParams) (es : List (Σ w, ElemVal w)) :
    (canonicalFoldedOutput c es).bnd = reducedC := rfl

theorem canonicalFoldedOutput_lt (c : PlainCheckParams) (es : List (Σ w, ElemVal w)) :
    limbNat (canonicalFoldedOutput c es).limbs < p := canonicalRemainder_lt _

theorem canonicalFoldedOutput_native (c : PlainCheckParams) (es : List (Σ w, ElemVal w)) :
    (canonicalFoldedOutput c es).limbs =
      natLimbVector8 ((foldedValue basis c es % (p : ℤ)).toNat) := winX_native _ _

theorem canonicalFoldedOutput_cast (c : PlainCheckParams) (es : List (Σ w, ElemVal w))
    (hc : c.sound basis = true) (hf : c.fold = true) (hm : c.m = p)
    (hb : ElemsMatch es c.elems) :
    ((canonicalFoldedOutput c es).value : Fp) = (c.exprValue (values es) : Fp) := by
  have he := foldedValue_congr basis c basis_sound hc hf es hb
  rw [hm] at he
  have ho := (Int.mod_modEq (foldedValue basis c es) p).trans he
  rw [← canonicalRemainder_value (foldedValue basis c es), modEq_p_iff] at ho
  exact ho

theorem canonicalFoldedOutput_native_of_cast (c : PlainCheckParams)
    (es : List (Σ w, ElemVal w)) (x : Fp)
    (hx : ((canonicalFoldedOutput c es).value : Fp) = x) :
    (canonicalFoldedOutput c es).limbs = natLimbVector8 x.val := by
  rw [canonicalFoldedOutput, canonicalRemainder_value] at hx
  have hv := congrArg (fun z : Fp => (z.val : ℤ)) hx
  change (((foldedValue basis c es % (p : ℤ) : ℤ) : Fp).val : ℤ) = (x.val : ℤ) at hv
  rw [ZMod.val_intCast, Int.emod_emod] at hv
  have hn := congrArg Int.toNat hv
  simp only [Int.toNat_natCast] at hn
  rw [canonicalFoldedOutput_native, hn]

end ZolanaVE.P256.Completeness
