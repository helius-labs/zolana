import VerifiableEncryption.Curve.CompletenessTripleArithmetic
import VerifiableEncryption.Field.CompletenessGeneratedChain_16
import VerifiableEncryption.Field.CompletenessGeneratedChain_3

/-! The selected-y triple uses the ordinary layouts and value equations,
with its own signed-y certificate bounds and actual extracted predicates. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

attribute [local irreducible] CheckPolynomial_32_h8cfcaa46 CheckPolynomial_24_h6a3ed603

theorem tripleSelectedTangent_match (L Y X : ElemVal 8)
    (hL : L.bnd = balC) (hY : Y.bnd = selC) (hX : X.bnd = reducedC) :
    ElemsMatch [⟨8, L⟩, ⟨8, Y⟩, ⟨8, X⟩, ⟨8, aElem⟩] cert_h8cfcaa46.elems :=
  elemsMatch_of (by show [L.bnd, Y.bnd, X.bnd, aElem.bnd] = _; rw [hL, hY, hX]; rfl)

theorem tripleSelectedTangent_zero (L Y X : ElemVal 8)
    (hl : 2 * (L.value : Fp) * (Y.value : Fp) = 3 * (X.value : Fp) ^ 2 - 3) :
    cert_h8cfcaa46.exprValue (values [⟨8, L⟩, ⟨8, Y⟩, ⟨8, X⟩, ⟨8, aElem⟩])
      ≡ 0 [ZMOD (cert_h8cfcaa46.m : ℤ)] := by
  change cert_h35a4bc86.exprValue (values [⟨8, L⟩, ⟨8, Y⟩, ⟨8, X⟩, ⟨8, aElem⟩])
    ≡ 0 [ZMOD (cert_h35a4bc86.m : ℤ)]
  exact tripleTangent_zero L Y X hl

theorem tripleSelectedTangent_complete (hr : RangeComplete) (X Y : ElemVal 8)
    (hX : X.bnd = reducedC) (hY : Y.bnd = selC) (l : Fp)
    (hl : 2 * l * (Y.value : Fp) = 3 * (X.value : Fp) ^ 2 - 3) :
    CheckPolynomial_32_h8cfcaa46
      (quadTangentInput (slopeElem l).limbs Y.limbs X.limbs) := by
  let L := slopeElem l
  have hb := tripleSelectedTangent_match L Y X rfl hY hX
  have hL : 2 * (L.value : Fp) * (Y.value : Fp) = 3 * (X.value : Fp) ^ 2 - 3 :=
    (congrArg (fun z : Fp => 2 * z * (Y.value : Fp)) (slopeElem_cast l)).trans hl
  exact CheckPolynomial_32_h8cfcaa46_complete _ hb _ (tripleTangent_layout L Y X)
    hr (tripleSelectedTangent_zero L Y X hL)

theorem tripleSelectedRatio_match (R X DX Y : ElemVal 8)
    (hR : R.bnd = balC) (hX : X.bnd = reducedC)
    (hDX : DX.bnd = lazyOut lazy_h30893ad5) (hY : Y.bnd = selC) :
    ElemsMatch [⟨8, R⟩, ⟨8, linElem [(1, X), (-1, DX)]⟩,
      ⟨8, linElem [(2, Y)]⟩] cert_h6a3ed603.elems := by
  apply elemsMatch_of
  show [R.bnd, (linElem [(1, X), (-1, DX)]).bnd, (linElem [(2, Y)]).bnd] = _
  rw [linElem_bnd, linElem_bnd]
  simp only [List.map]
  rw [hR, hX, hDX, hY]
  rfl

theorem tripleSelectedRatio_zero (R X DX Y : ElemVal 8)
    (he : (R.value : Fp) * ((X.value : Fp) - (DX.value : Fp)) = 2 * (Y.value : Fp)) :
    cert_h6a3ed603.exprValue (values [⟨8, R⟩, ⟨8, linElem [(1, X), (-1, DX)]⟩,
      ⟨8, linElem [(2, Y)]⟩]) ≡ 0 [ZMOD (cert_h6a3ed603.m : ℤ)] := by
  change cert_h6ce7114d.exprValue (values [⟨8, R⟩, ⟨8, linElem [(1, X), (-1, DX)]⟩,
    ⟨8, linElem [(2, Y)]⟩]) ≡ 0 [ZMOD (cert_h6ce7114d.m : ℤ)]
  exact tripleRatio_zero R X DX Y he

theorem tripleSelectedRatio_complete (hr : RangeComplete) (X DX Y : ElemVal 8)
    (hX : X.bnd = reducedC) (hDX : DX.bnd = lazyOut lazy_h30893ad5)
    (hY : Y.bnd = selC) (r : Fp)
    (he : r * ((X.value : Fp) - (DX.value : Fp)) = 2 * (Y.value : Fp)) :
    CheckPolynomial_24_h6a3ed603
      (tripleRatioInput (slopeElem r).limbs X.limbs DX.limbs Y.limbs) := by
  let R := slopeElem r
  have hb := tripleSelectedRatio_match R X DX Y rfl hX hDX hY
  have hR : (R.value : Fp) * ((X.value : Fp) - (DX.value : Fp)) = 2 * (Y.value : Fp) :=
    (congrArg (fun z : Fp => z * ((X.value : Fp) - (DX.value : Fp)))
      (slopeElem_cast r)).trans he
  exact CheckPolynomial_24_h6a3ed603_complete _ hb _ (tripleRatio_layout R X DX Y)
    hr (tripleSelectedRatio_zero R X DX Y hR)

/-- Native composition of the constructed selected-y arithmetic primitives.
The outer finite-point theorem supplies all primitive witnesses. -/
theorem triple_hffcb8921_of_arithmetic (hr : RangeComplete)
    (X Y DX RX RY : List.Vector F 8) (l r : Fp)
    (hTangent : CheckPolynomial_32_h8cfcaa46
      (quadTangentInput (slopeElem l).limbs Y X))
    (hDX : ∀ k : List.Vector F 8 → Prop, k DX →
      Lazy_16_h30893ad5 (quadDoubleXInput (slopeElem l).limbs X) k)
    (hRatio : CheckPolynomial_24_h6a3ed603
      (tripleRatioInput (slopeElem r).limbs X DX Y))
    (hRX : ∀ k : List.Vector F 8 → Prop, k RX →
      CheckPolynomial_24_h38fe3d8b
        (tripleXInput (slopeElem r).limbs (slopeElem l).limbs X DX) k)
    (hRY : ∀ k : List.Vector F 8 → Prop, k RY →
      CheckPolynomial_24_h70dd0288
        (tripleYInput (slopeElem r).limbs (slopeElem l).limbs X RX Y) k)
    (k : List.Vector (List.Vector F 8) 2 → Prop)
    (hk : k (RX ::ᵥ RY ::ᵥ List.Vector.nil)) :
    Triple_8_8_hffcb8921 X Y k := by
  exact Triple_8_8_hffcb8921_compose X Y (slopeElem l).limbs (slopeElem r).limbs DX RX RY
    (rawSlopePieces l) (rawSlopePieces r) (slopePieces l) (slopePieces r)
    (slopePieces_ranges hr l) (slopePieces_limb l)
    (slopePieces_ranges hr r) (slopePieces_limb r)
    hTangent hDX hRatio hRX hRY k hk

end ZolanaVE.P256.Completeness
