import VerifiableEncryption.Curve.CompletenessTripleX
import VerifiableEncryption.Field.CompletenessGeneratedEval_8

/-! Construct the ordinary triple's canonical y output from its bounded
arithmetic inputs. Layout identities are proved with abstract elements before
substituting the mathematical slopes. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

attribute [local irreducible] CheckPolynomial_24_ha082c489

noncomputable def tripleYElems (X RX Y L R : ElemVal 8) : List (Σ w, ElemVal w) :=
  [⟨8, linElem [(1, R), (-1, L)]⟩, ⟨8, linElem [(1, X), (-1, RX)]⟩, ⟨8, Y⟩]

theorem tripleYElems_match (X RX Y L R : ElemVal 8)
    (hX : X.bnd = reducedC) (hRX : RX.bnd = reducedC) (hY : Y.bnd = reducedC)
    (hL : L.bnd = balC) (hR : R.bnd = balC) :
    ElemsMatch (tripleYElems X RX Y L R) cert_ha082c489.elems := by
  apply elemsMatch_of
  show [(linElem [(1, R), (-1, L)]).bnd,
    (linElem [(1, X), (-1, RX)]).bnd, Y.bnd] = _
  rw [linElem_bnd, linElem_bnd]
  simp only [List.map]
  rw [hX, hRX, hY, hL, hR]
  rfl

theorem tripleY_expr (X RX Y L R : ElemVal 8) :
    cert_ha082c489.exprValue (values (tripleYElems X RX Y L R)) =
      (R.value - L.value) * (X.value - RX.value) - Y.value := by
  simp [tripleYElems, PolyShape.exprValue, values, cert_ha082c489, linElem_value]
  ring

theorem tripleY_layout (X RX Y L R : ElemVal 8) :
    limbLists (tripleYElems X RX Y L R) =
      outputCheckInputs (tripleYInput R.limbs L.limbs X.limbs RX.limbs Y.limbs) := by
  simp only [tripleYElems, limbLists, List.map_cons, List.map_nil, outputCheckInputs]
  rw [vec8_toList (linElem [(1, R), (-1, L)]).limbs,
    vec8_toList (linElem [(1, X), (-1, RX)]).limbs, vec8_toList Y.limbs]
  simp only [tripleYInput, linPair_limb, List.Vector.get_cons_zero,
    List.Vector.get_cons_succ, Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod,
    Int.cast_one, Int.cast_neg, one_mul, neg_one_mul, sub_eq_add_neg]
  rfl

theorem tripleY_complete (hr : RangeComplete) (X RX Y : ElemVal 8)
    (hX : X.bnd = reducedC) (hRX : RX.bnd = reducedC) (hY : Y.bnd = reducedC)
    (l r y3 : Fp)
    (hy3 : y3 = (r - l) * ((X.value : Fp) - (RX.value : Fp)) - (Y.value : Fp)) :
    ∀ k : List.Vector F 8 → Prop, k (canonicalFpElem y3).limbs →
      CheckPolynomial_24_ha082c489
        (tripleYInput (slopeElem r).limbs (slopeElem l).limbs X.limbs RX.limbs Y.limbs) k := by
  have hb := tripleYElems_match X RX Y (slopeElem l) (slopeElem r) hX hRX hY rfl rfl
  have hc : ((canonicalFoldedOutput cert_ha082c489
      (tripleYElems X RX Y (slopeElem l) (slopeElem r))).value : Fp) = y3 := by
    calc
      _ = (cert_ha082c489.exprValue
          (values (tripleYElems X RX Y (slopeElem l) (slopeElem r))) : Fp) :=
        canonicalFoldedOutput_cast cert_ha082c489 _ cert_ha082c489_sound rfl rfl hb
      _ = ((((slopeElem r).value - (slopeElem l).value) *
          (X.value - RX.value) - Y.value : ℤ) : Fp) :=
        congrArg (fun z : ℤ => (z : Fp))
          (tripleY_expr X RX Y (slopeElem l) (slopeElem r))
      _ = y3 := by
        push_cast
        rw [slopeElem_cast r, slopeElem_cast l]
        exact hy3.symm
  have hn : (canonicalFpElem y3).limbs = natLimbVector8 y3.val :=
    winX_native y3.val (lt_trans (ZMod.val_lt y3) p_lt_two_pow)
  have ho : (canonicalFpElem y3).limbs = natLimbVector8
      ((foldedValue basis cert_ha082c489
        (tripleYElems X RX Y (slopeElem l) (slopeElem r)) %
        (cert_ha082c489.m : ℤ)).toNat) := by
    have hm := canonicalFoldedOutput_native_of_cast cert_ha082c489 _ y3 hc
    simpa only [show cert_ha082c489.m = p from rfl] using
      hn.trans (hm.symm.trans (canonicalFoldedOutput_native cert_ha082c489 _))
  intro k hk
  apply CheckPolynomial_24_ha082c489_complete _ hb _
    (tripleY_layout X RX Y (slopeElem l) (slopeElem r)) hr k
  exact (congrArg k ho).mp hk

end ZolanaVE.P256.Completeness
