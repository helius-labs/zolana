import VerifiableEncryption.Curve.CompletenessCoordinates
import VerifiableEncryption.Curve.CompletenessGeneratedTripleAddComposition

/-! Assemble a triple from constructed slopes and individual actual arithmetic
primitives. The outer geometric constructor supplies every primitive premise. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field

theorem triple_h2c0228bb_of_arithmetic (hr : RangeComplete)
    (X Y DX RX RY : List.Vector F 8) (l r : Fp)
    (hTangent : CheckPolynomial_32_h35a4bc86
      (quadTangentInput (slopeElem l).limbs Y X))
    (hDX : ∀ k : List.Vector F 8 → Prop, k DX →
      Lazy_16_h30893ad5 (quadDoubleXInput (slopeElem l).limbs X) k)
    (hRatio : CheckPolynomial_24_h6ce7114d
      (tripleRatioInput (slopeElem r).limbs X DX Y))
    (hRX : ∀ k : List.Vector F 8 → Prop, k RX →
      CheckPolynomial_24_h38fe3d8b
        (tripleXInput (slopeElem r).limbs (slopeElem l).limbs X DX) k)
    (hRY : ∀ k : List.Vector F 8 → Prop, k RY →
      CheckPolynomial_24_ha082c489
        (tripleYInput (slopeElem r).limbs (slopeElem l).limbs X RX Y) k)
    (k : List.Vector (List.Vector F 8) 2 → Prop)
    (hk : k (RX ::ᵥ RY ::ᵥ List.Vector.nil)) :
    Triple_8_8_h2c0228bb X Y k := by
  exact Triple_8_8_h2c0228bb_compose X Y (slopeElem l).limbs (slopeElem r).limbs DX RX RY
    (rawSlopePieces l) (rawSlopePieces r) (slopePieces l) (slopePieces r)
    (slopePieces_ranges hr l) (slopePieces_limb l)
    (slopePieces_ranges hr r) (slopePieces_limb r)
    hTangent hDX hRatio hRX hRY k hk

end ZolanaVE.P256.Completeness
