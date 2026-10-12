import VerifiableEncryption.Field.CompletenessBridgeOutput

/-! Unified-addition x witness construction through the checked generated reverse bridge. -/

namespace ZolanaVE.Field
open ZolanaVE.EmcurveChecks

theorem unifiedX_quotient_lower :
    foldedMagnitude basis cert_h42186a27 + (cert_h42186a27.m : ℤ) - 1 ≤
      (cert_h42186a27.offset : ℤ) * cert_h42186a27.m :=
  CheckPolynomial_24_h42186a27_quotient_lower

theorem unifiedX_quotient_upper :
    foldedMagnitude basis cert_h42186a27 <
      ((2 : ℤ) ^ cert_h42186a27.quotientBits - cert_h42186a27.offset) * cert_h42186a27.m :=
  CheckPolynomial_24_h42186a27_quotient_upper

theorem unifiedX_carry_capacity :
    CarryCapacity (cert_h42186a27.residualBound basis) cert_h42186a27.positions
      cert_h42186a27.carryPositions cert_h42186a27.groups 0 none :=
  CheckPolynomial_24_h42186a27_carry_capacity

/-- For every bounded input tuple, construct the actual extracted reduced
x-output check and preserve an arbitrary continuation at the explicit
canonical remainder. All certificate capacities are closed source proofs. -/
theorem unifiedX_complete (es : List (Σ w, ElemVal w))
    (hb : ElemsMatch es cert_h42186a27.elems) (L : List.Vector F 24)
    (hxs : limbLists es = outputCheckInputs L)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (k : List.Vector F 8 → Prop)
    (hk : k (natLimbVector8 ((foldedValue basis cert_h42186a27 es % (cert_h42186a27.m : ℤ)).toNat))) :
    CheckPolynomial_24_h42186a27 L k := by
  exact CheckPolynomial_24_h42186a27_complete es hb L hxs hl k hk

end ZolanaVE.Field
