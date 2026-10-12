import VerifiableEncryption.Field.CompletenessEval
import VerifiableEncryption.Field.CompletenessBridge
import VerifiableEncryption.Field.CompletenessBridgeChain

/-!
Construct the actual first fixed-base slope assertion from its mathematical
modular equation and bounded limbs. Numerical obligations describe only the
literal certificate. They do not assume successful operations or hints.
The reverse constructors and static capacities come from checked generated
primitives.
-/

namespace ZolanaVE.Field

open ZolanaVE.EmcurveChecks

theorem firstSlope_quotient_lower :
    foldedMagnitude basis cert_hb838cae4 ≤
      (cert_hb838cae4.offset : ℤ) * cert_hb838cae4.m :=
  CheckPolynomial_32_hb838cae4_quotient_lower

theorem firstSlope_quotient_upper :
    foldedMagnitude basis cert_hb838cae4 <
      ((2 : ℤ) ^ cert_hb838cae4.quotientBits - cert_hb838cae4.offset) * cert_hb838cae4.m :=
  CheckPolynomial_32_hb838cae4_quotient_upper

theorem firstSlope_carry_capacity :
    CarryCapacity (cert_hb838cae4.residualBound basis) cert_hb838cae4.positions
      cert_hb838cae4.carryPositions cert_hb838cae4.groups 0 none :=
  CheckPolynomial_32_hb838cae4_carry_capacity

theorem firstSlope_complete (es : List (Σ w, ElemVal w))
    (hb : ElemsMatch es cert_hb838cae4.elems) (L : List.Vector F 32)
    (hxs : limbLists es = chainCheckInputs L)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (hzero : cert_hb838cae4.exprValue (values es) ≡ 0 [ZMOD (cert_hb838cae4.m : ℤ)]) :
    CheckPolynomial_32_hb838cae4 L :=
  CheckPolynomial_32_hb838cae4_complete es hb L hxs hl hzero

theorem secondChainSlope_quotient_lower :
    foldedMagnitude basis cert_hd6f972c2 ≤
      (cert_hd6f972c2.offset : ℤ) * cert_hd6f972c2.m :=
  CheckPolynomial_48_hd6f972c2_quotient_lower

theorem secondChainSlope_quotient_upper :
    foldedMagnitude basis cert_hd6f972c2 <
      ((2 : ℤ) ^ cert_hd6f972c2.quotientBits - cert_hd6f972c2.offset) * cert_hd6f972c2.m :=
  CheckPolynomial_48_hd6f972c2_quotient_upper

theorem secondChainSlope_carry_capacity :
    CarryCapacity (cert_hd6f972c2.residualBound basis) cert_hd6f972c2.positions
      cert_hd6f972c2.carryPositions cert_hd6f972c2.groups 0 none :=
  CheckPolynomial_48_hd6f972c2_carry_capacity

theorem secondChainSlope_complete (es : List (Σ w, ElemVal w))
    (hb : ElemsMatch es cert_hd6f972c2.elems) (L : List.Vector F 48)
    (hxs : limbLists es = chainCheckInputs48 L)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (hzero : cert_hd6f972c2.exprValue (values es) ≡ 0 [ZMOD (cert_hd6f972c2.m : ℤ)]) :
    CheckPolynomial_48_hd6f972c2 L :=
  CheckPolynomial_48_hd6f972c2_complete es hb L hxs hl hzero

end ZolanaVE.Field
