import VerifiableEncryption.Field.CompletenessGeneratedChain_79

/-! Actual unified-addition primitive through its generated witness constructor. -/

namespace ZolanaVE.Field
open ZolanaVE.EmcurveChecks

def unifiedSlopeInputs (L : List.Vector F 49) : List (List F) :=
  [[L.get 0, L.get 1, L.get 2, L.get 3, L.get 4, L.get 5, L.get 6, L.get 7],
   [L.get 8, L.get 9, L.get 10, L.get 11, L.get 12, L.get 13, L.get 14, L.get 15], [L.get 16],
   [L.get 17, L.get 18, L.get 19, L.get 20, L.get 21, L.get 22, L.get 23, L.get 24],
   [L.get 25, L.get 26, L.get 27, L.get 28, L.get 29, L.get 30, L.get 31, L.get 32],
   [L.get 33, L.get 34, L.get 35, L.get 36, L.get 37, L.get 38, L.get 39, L.get 40],
   [L.get 41, L.get 42, L.get 43, L.get 44, L.get 45, L.get 46, L.get 47, L.get 48]]

theorem unifiedSlope_check_of_model (L : List.Vector F 49)
    (h : CheckPolynomial.circuit basis cert_h8f49f727 (unifiedSlopeInputs L)
      (LookupCheck RangeCheck 11) (fun _ => True)) : CheckPolynomial_49_h8f49f727 L :=
  CheckPolynomial_49_h8f49f727_of_model L h

theorem unifiedSlope_quotient_lower : foldedMagnitude basis cert_h8f49f727 ≤
    (cert_h8f49f727.offset : ℤ) * cert_h8f49f727.m :=
  CheckPolynomial_49_h8f49f727_quotient_lower

theorem unifiedSlope_quotient_upper : foldedMagnitude basis cert_h8f49f727 <
    ((2 : ℤ) ^ cert_h8f49f727.quotientBits - cert_h8f49f727.offset) * cert_h8f49f727.m :=
  CheckPolynomial_49_h8f49f727_quotient_upper

theorem unifiedSlope_capacity : CarryCapacity (cert_h8f49f727.residualBound basis)
    cert_h8f49f727.positions cert_h8f49f727.carryPositions cert_h8f49f727.groups 0 none :=
  CheckPolynomial_49_h8f49f727_carry_capacity

theorem unifiedSlope_complete (es : List (Σ w, ElemVal w))
    (hb : ElemsMatch es cert_h8f49f727.elems) (L : List.Vector F 49)
    (hxs : limbLists es = unifiedSlopeInputs L)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (hzero : cert_h8f49f727.exprValue (values es) ≡ 0 [ZMOD (cert_h8f49f727.m : ℤ)]) :
    CheckPolynomial_49_h8f49f727 L := by
  exact CheckPolynomial_49_h8f49f727_complete es hb L hxs hl hzero

end ZolanaVE.Field
