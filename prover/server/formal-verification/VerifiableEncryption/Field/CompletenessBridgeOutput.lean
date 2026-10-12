import VerifiableEncryption.Field.CompletenessRemainder
import VerifiableEncryption.Field.CompletenessGeneratedEval_6

/-! Exact reverse bridge for the actual unified-addition x-output predicate.
All remainder, range, carry and continuation obligations are constructed by
the checked generated primitive. -/

namespace ZolanaVE.Field
open ZolanaVE.EmcurveChecks

theorem unifiedX_check_of_model (L : List.Vector F 24) (k : List.Vector F 8 → Prop)
    (h : CheckPolynomial.circuit basis cert_h42186a27 (outputCheckInputs L)
      (LookupCheck RangeCheck 11) (fun o => ∃ v : List.Vector F 8, o = some v.toList ∧ k v)) :
    CheckPolynomial_24_h42186a27 L k :=
  CheckPolynomial_24_h42186a27_of_model L k h

end ZolanaVE.Field
