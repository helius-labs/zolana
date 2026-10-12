import VerifiableEncryption.Field.CompletenessGeneratedEval_8
import VerifiableEncryption.Curve.Elem

/-! Construct the actual final fixed-base x reduction with its own certificate
and extracted predicate. The complete remainder, quotient and carry witnesses
come from the checked generated primitive. -/

namespace ZolanaVE.Field

open ZolanaVE.EmcurveChecks

def combReduceInputs (L : List.Vector F 8) : List (List F) := [L.toList]

theorem combReduce_check_of_model (L : List.Vector F 8) (k : List.Vector F 8 → Prop)
    (h : CheckPolynomial.circuit basis cert_h78194ae0 (combReduceInputs L)
      (LookupCheck RangeCheck 11) (fun o => ∃ v : List.Vector F 8, o = some v.toList ∧ k v)) :
    CheckPolynomial_8_h78194ae0 L k := by
  apply CheckPolynomial_8_h78194ae0_of_model L k
  simpa only [combReduceInputs, vec8_toList] using h

theorem combReduce_quotient_lower :
    foldedMagnitude basis cert_h78194ae0 + (cert_h78194ae0.m : ℤ) - 1 ≤
      (cert_h78194ae0.offset : ℤ) * cert_h78194ae0.m :=
  CheckPolynomial_8_h78194ae0_quotient_lower

theorem combReduce_quotient_upper :
    foldedMagnitude basis cert_h78194ae0 <
      ((2 : ℤ) ^ cert_h78194ae0.quotientBits - cert_h78194ae0.offset) * cert_h78194ae0.m :=
  CheckPolynomial_8_h78194ae0_quotient_upper

theorem combReduce_carry_capacity :
    CarryCapacity (cert_h78194ae0.residualBound basis) cert_h78194ae0.positions
      cert_h78194ae0.carryPositions cert_h78194ae0.groups 0 none :=
  CheckPolynomial_8_h78194ae0_carry_capacity

theorem combReduce_complete (es : List (Σ w, ElemVal w))
    (hb : ElemsMatch es cert_h78194ae0.elems) (L : List.Vector F 8)
    (hxs : limbLists es = combReduceInputs L)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (k : List.Vector F 8 → Prop)
    (hk : k (natLimbVector8 ((foldedValue basis cert_h78194ae0 es % (cert_h78194ae0.m : ℤ)).toNat))) :
    CheckPolynomial_8_h78194ae0 L k := by
  exact CheckPolynomial_8_h78194ae0_complete es hb L
    (by simpa only [combReduceInputs, vec8_toList] using hxs) hl k hk

end ZolanaVE.Field
