import VerifiableEncryption.Curve.CompletenessTripleY
import VerifiableEncryption.Field.CompletenessGeneratedEval_7

/-! Construct the selected-y triple's canonical y output from its bounded
arithmetic inputs. Layout identities are proved with abstract elements before
substituting the mathematical slopes. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

attribute [local irreducible] CheckPolynomial_24_h70dd0288

theorem tripleSelectedYElems_match (X RX Y L R : ElemVal 8)
    (hX : X.bnd = reducedC) (hRX : RX.bnd = reducedC) (hY : Y.bnd = selC)
    (hL : L.bnd = balC) (hR : R.bnd = balC) :
    ElemsMatch (tripleYElems X RX Y L R) cert_h70dd0288.elems := by
  apply elemsMatch_of
  show [(linElem [(1, R), (-1, L)]).bnd,
    (linElem [(1, X), (-1, RX)]).bnd, Y.bnd] = _
  rw [linElem_bnd, linElem_bnd]
  simp only [List.map]
  rw [hX, hRX, hY, hL, hR]
  rfl

theorem tripleSelectedY_expr (X RX Y L R : ElemVal 8) :
    cert_h70dd0288.exprValue (values (tripleYElems X RX Y L R)) =
      (R.value - L.value) * (X.value - RX.value) - Y.value := by
  change cert_ha082c489.exprValue (values (tripleYElems X RX Y L R)) = _
  exact tripleY_expr X RX Y L R

theorem tripleSelectedY_field (X RX Y L R : ElemVal 8) (l r y3 : Fp)
    (hL : (L.value : Fp) = l) (hR : (R.value : Fp) = r)
    (hy3 : y3 = (r - l) * ((X.value : Fp) - (RX.value : Fp)) - (Y.value : Fp)) :
    (((R.value - L.value) * (X.value - RX.value) - Y.value : ℤ) : Fp) = y3 := by
  push_cast
  rw [hL, hR]
  exact hy3.symm

theorem tripleSelectedY_complete (hr : RangeComplete) (X RX Y : ElemVal 8)
    (hX : X.bnd = reducedC) (hRX : RX.bnd = reducedC) (hY : Y.bnd = selC)
    (l r y3 : Fp)
    (hy3 : y3 = (r - l) * ((X.value : Fp) - (RX.value : Fp)) - (Y.value : Fp)) :
    ∀ k : List.Vector F 8 → Prop, k (canonicalFpElem y3).limbs →
      CheckPolynomial_24_h70dd0288
        (tripleYInput (slopeElem r).limbs (slopeElem l).limbs X.limbs RX.limbs Y.limbs) k := by
  have hb := tripleSelectedYElems_match X RX Y (slopeElem l) (slopeElem r) hX hRX hY rfl rfl
  have hc : ((canonicalFoldedOutput cert_h70dd0288
      (tripleYElems X RX Y (slopeElem l) (slopeElem r))).value : Fp) = y3 := by
    calc
      _ = (cert_h70dd0288.exprValue
          (values (tripleYElems X RX Y (slopeElem l) (slopeElem r))) : Fp) :=
        canonicalFoldedOutput_cast cert_h70dd0288 _ cert_h70dd0288_sound rfl rfl hb
      _ = ((((slopeElem r).value - (slopeElem l).value) *
          (X.value - RX.value) - Y.value : ℤ) : Fp) :=
        congrArg (fun z : ℤ => (z : Fp))
          (tripleSelectedY_expr X RX Y (slopeElem l) (slopeElem r))
      _ = y3 := tripleSelectedY_field X RX Y (slopeElem l) (slopeElem r)
        l r y3 (slopeElem_cast l) (slopeElem_cast r) hy3
  have hn : (canonicalFpElem y3).limbs = natLimbVector8 y3.val :=
    winX_native y3.val (lt_trans (ZMod.val_lt y3) p_lt_two_pow)
  have ho : (canonicalFpElem y3).limbs = natLimbVector8
      ((foldedValue basis cert_h70dd0288
        (tripleYElems X RX Y (slopeElem l) (slopeElem r)) %
        (cert_h70dd0288.m : ℤ)).toNat) := by
    have hm := canonicalFoldedOutput_native_of_cast cert_h70dd0288 _ y3 hc
    simpa only [show cert_h70dd0288.m = p from rfl] using
      hn.trans (hm.symm.trans (canonicalFoldedOutput_native cert_h70dd0288 _))
  intro k hk
  apply CheckPolynomial_24_h70dd0288_complete _ hb _
    (tripleY_layout X RX Y (slopeElem l) (slopeElem r)) hr k
  exact (congrArg k ho).mp hk

end ZolanaVE.P256.Completeness
