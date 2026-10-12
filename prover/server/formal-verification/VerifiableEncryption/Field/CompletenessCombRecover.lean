import VerifiableEncryption.Field.CompletenessGeneratedEval_3
import VerifiableEncryption.Field.CompletenessRemainder

/-! The final implicit-y recovery retains its packed-y input bounds and own
actual extracted predicate. Its witnesses and numerical capacities are
provided by the checked generated primitive. -/

namespace ZolanaVE.Field

open ZolanaVE.EmcurveChecks

theorem combRecover_check_of_model (L : List.Vector F 24) (k : List.Vector F 8 → Prop)
    (h : CheckPolynomial.circuit basis cert_h0845ed76 (outputCheckInputs L)
      (LookupCheck RangeCheck 11) (fun o => ∃ v : List.Vector F 8, o = some v.toList ∧ k v)) :
    CheckPolynomial_24_h0845ed76 L k :=
  CheckPolynomial_24_h0845ed76_of_model L k h

theorem combRecover_quotient_lower :
    foldedMagnitude basis cert_h0845ed76 + (cert_h0845ed76.m : ℤ) - 1 ≤
      (cert_h0845ed76.offset : ℤ) * cert_h0845ed76.m :=
  CheckPolynomial_24_h0845ed76_quotient_lower

theorem combRecover_quotient_upper :
    foldedMagnitude basis cert_h0845ed76 <
      ((2 : ℤ) ^ cert_h0845ed76.quotientBits - cert_h0845ed76.offset) * cert_h0845ed76.m :=
  CheckPolynomial_24_h0845ed76_quotient_upper

theorem combRecover_carry_capacity :
    CarryCapacity (cert_h0845ed76.residualBound basis) cert_h0845ed76.positions
      cert_h0845ed76.carryPositions cert_h0845ed76.groups 0 none :=
  CheckPolynomial_24_h0845ed76_carry_capacity

theorem combRecover_complete (es : List (Σ w, ElemVal w))
    (hb : ElemsMatch es cert_h0845ed76.elems) (L : List.Vector F 24)
    (hxs : limbLists es = outputCheckInputs L)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (k : List.Vector F 8 → Prop)
    (hk : k (natLimbVector8 ((foldedValue basis cert_h0845ed76 es % (cert_h0845ed76.m : ℤ)).toNat))) :
    CheckPolynomial_24_h0845ed76 L k :=
  CheckPolynomial_24_h0845ed76_complete es hb L hxs hl k hk

end ZolanaVE.Field
