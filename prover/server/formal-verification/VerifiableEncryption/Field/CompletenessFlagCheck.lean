import VerifiableEncryption.Field.CompletenessGeneratedChain_82

/-! Actual unified-addition primitive through its generated witness constructor. -/

namespace ZolanaVE.Field
open ZolanaVE.EmcurveChecks

def flagCheckInputs (L : List.Vector F 9) : List (List F) :=
  [[L.get 0], [L.get 1, L.get 2, L.get 3, L.get 4, L.get 5, L.get 6, L.get 7, L.get 8]]

theorem flagProduct_check_of_model (L : List.Vector F 9)
    (h : CheckPolynomial.circuit basis cert_hd299af1e (flagCheckInputs L)
      (LookupCheck RangeCheck 11) (fun _ => True)) : CheckPolynomial_9_hd299af1e L :=
  CheckPolynomial_9_hd299af1e_of_model L h

theorem flagProduct_quotient_lower : foldedMagnitude basis cert_hd299af1e ≤
    (cert_hd299af1e.offset : ℤ) * cert_hd299af1e.m :=
  CheckPolynomial_9_hd299af1e_quotient_lower

theorem flagProduct_quotient_upper : foldedMagnitude basis cert_hd299af1e <
    ((2 : ℤ) ^ cert_hd299af1e.quotientBits - cert_hd299af1e.offset) * cert_hd299af1e.m :=
  CheckPolynomial_9_hd299af1e_quotient_upper

theorem flagProduct_capacity : CarryCapacity (cert_hd299af1e.residualBound basis)
    cert_hd299af1e.positions cert_hd299af1e.carryPositions cert_hd299af1e.groups 0 none :=
  CheckPolynomial_9_hd299af1e_carry_capacity

theorem flagProduct_complete (es : List (Σ w, ElemVal w))
    (hb : ElemsMatch es cert_hd299af1e.elems) (L : List.Vector F 9)
    (hxs : limbLists es = flagCheckInputs L)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (hzero : cert_hd299af1e.exprValue (values es) ≡ 0 [ZMOD (cert_hd299af1e.m : ℤ)]) :
    CheckPolynomial_9_hd299af1e L := by
  exact CheckPolynomial_9_hd299af1e_complete es hb L hxs hl hzero

end ZolanaVE.Field
