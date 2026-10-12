import VerifiableEncryption.Field.CompletenessUnifiedX
import VerifiableEncryption.Field.CompletenessGeneratedEval_4

/-! Unified-addition y witnesses through the checked generated constructor. -/

namespace ZolanaVE.Field
open ZolanaVE.EmcurveChecks

theorem unifiedY_check_of_model (L : List.Vector F 24) (k : List.Vector F 8 → Prop)
    (h : CheckPolynomial.circuit basis cert_h2629e496 (outputCheckInputs L)
      (LookupCheck RangeCheck 11) (fun o => ∃ v : List.Vector F 8, o = some v.toList ∧ k v)) :
    CheckPolynomial_24_h2629e496 L k :=
  CheckPolynomial_24_h2629e496_of_model L k h

theorem unifiedY_quotient_lower :
    foldedMagnitude basis cert_h2629e496 + (cert_h2629e496.m : ℤ) - 1 ≤
      (cert_h2629e496.offset : ℤ) * cert_h2629e496.m :=
  CheckPolynomial_24_h2629e496_quotient_lower

theorem unifiedY_quotient_upper :
    foldedMagnitude basis cert_h2629e496 <
      ((2 : ℤ) ^ cert_h2629e496.quotientBits - cert_h2629e496.offset) * cert_h2629e496.m :=
  CheckPolynomial_24_h2629e496_quotient_upper

theorem unifiedY_carry_capacity :
    CarryCapacity (cert_h2629e496.residualBound basis) cert_h2629e496.positions
      cert_h2629e496.carryPositions cert_h2629e496.groups 0 none :=
  CheckPolynomial_24_h2629e496_carry_capacity

theorem unifiedY_complete (es : List (Σ w, ElemVal w))
    (hb : ElemsMatch es cert_h2629e496.elems) (L : List.Vector F 24)
    (hxs : limbLists es = outputCheckInputs L)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (k : List.Vector F 8 → Prop)
    (hk : k (natLimbVector8 ((foldedValue basis cert_h2629e496 es % (cert_h2629e496.m : ℤ)).toNat))) :
    CheckPolynomial_24_h2629e496 L k := by
  exact CheckPolynomial_24_h2629e496_complete es hb L hxs hl k hk

end ZolanaVE.Field
