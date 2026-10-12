import VerifiableEncryption.Curve.CompletenessTripleArithmetic
import VerifiableEncryption.Curve.CompletenessLadderHalfTangent
import VerifiableEncryption.Field.CompletenessGeneratedLazy_62
import VerifiableEncryption.Field.CompletenessGeneratedChain_23

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

def vec5 (A B C D E : ElemVal 8) : List.Vector F 40 :=
  vec![A.limbs.get 0, A.limbs.get 1, A.limbs.get 2, A.limbs.get 3,
    A.limbs.get 4, A.limbs.get 5, A.limbs.get 6, A.limbs.get 7,
    B.limbs.get 0, B.limbs.get 1, B.limbs.get 2, B.limbs.get 3,
    B.limbs.get 4, B.limbs.get 5, B.limbs.get 6, B.limbs.get 7,
    C.limbs.get 0, C.limbs.get 1, C.limbs.get 2, C.limbs.get 3,
    C.limbs.get 4, C.limbs.get 5, C.limbs.get 6, C.limbs.get 7,
    D.limbs.get 0, D.limbs.get 1, D.limbs.get 2, D.limbs.get 3,
    D.limbs.get 4, D.limbs.get 5, D.limbs.get 6, D.limbs.get 7,
    E.limbs.get 0, E.limbs.get 1, E.limbs.get 2, E.limbs.get 3,
    E.limbs.get 4, E.limbs.get 5, E.limbs.get 6, E.limbs.get 7]

def halfQuarticInputs (V : List.Vector F 40) : List (List F) :=
  [[(V).get 0, (V).get 1,
        (V).get 2, (V).get 3,
        (V).get 4, (V).get 5,
        (V).get 6, (V).get 7],
       [(V).get 8, (V).get 9,
        (V).get 10, (V).get 11,
        (V).get 12, (V).get 13,
        (V).get 14, (V).get 15],
       [(V).get 16, (V).get 17,
        (V).get 18, (V).get 19,
        (V).get 20, (V).get 21,
        (V).get 22, (V).get 23],
       [(V).get 24, (V).get 25,
        (V).get 26, (V).get 27,
        (V).get 28, (V).get 29,
        (V).get 30, (V).get 31],
       [(V).get 32, (V).get 33,
        (V).get 34, (V).get 35,
        (V).get 36, (V).get 37,
        (V).get 38, (V).get 39]]

theorem vec5_inputs (S X L Y A : ElemVal 8) :
    limbLists [⟨8, S⟩, ⟨8, X⟩, ⟨8, L⟩, ⟨8, Y⟩, ⟨8, A⟩] =
      halfQuarticInputs (vec5 S X L Y A) := by
  simp only [limbLists, List.map_cons, List.map_nil]
  rw [vec8_toList S.limbs, vec8_toList X.limbs, vec8_toList L.limbs,
    vec8_toList Y.limbs, vec8_toList A.limbs]
  rfl

theorem halfSquare_layout (L : ElemVal 8) : limbLists [⟨8, L⟩] =
    [[L.limbs.get 0, L.limbs.get 1, L.limbs.get 2, L.limbs.get 3,
      L.limbs.get 4, L.limbs.get 5, L.limbs.get 6, L.limbs.get 7]] := by
  simp only [limbLists, List.map_cons, List.map_nil]
  rw [vec8_toList L.limbs]

theorem halfSquare_expr (L : ElemVal 8) :
    lazy_h158c056f.exprValue (values [⟨8, L⟩]) = L.value * L.value := by
  simp [PolyShape.exprValue, values, lazy_h158c056f]

theorem halfSquare_value (L S : ElemVal 8)
    (hv : S.value ≡ lazy_h158c056f.exprValue (values [⟨8, L⟩]) [ZMOD (lazy_h158c056f.m : ℤ)]) :
    (S.value : Fp) = (L.value : Fp) ^ 2 := by
  rw [halfSquare_expr, show (lazy_h158c056f.m : ℤ) = p from rfl, modEq_p_iff] at hv
  push_cast at hv
  simpa only [pow_two] using hv

theorem halfSquare_complete (L : ElemVal 8) (hL : L.bnd = balC) :
    ∃ S : ElemVal 8, S.bnd = lazyOut lazy_h158c056f ∧
      (S.value : Fp) = (L.value : Fp) ^ 2 ∧
      ∀ k : List.Vector F 8 → Prop, k S.limbs → Lazy_8_h158c056f L.limbs k := by
  have hb : ElemsMatch [⟨8, L⟩] lazy_h158c056f.elems :=
    elemsMatch_of (by show [L.bnd] = _; rw [hL]; rfl)
  obtain ⟨S, hS, hv, ha⟩ := Lazy_8_h158c056f_complete _ hb L.limbs (halfSquare_layout L)
  exact ⟨S, hS, halfSquare_value L S hv, ha⟩

theorem halfQuartic_match (S X L Y : ElemVal 8)
    (hS : S.bnd = lazyOut lazy_h158c056f) (hX : X.bnd = reducedC)
    (hL : L.bnd = balC) (hY : Y.bnd = reducedC) :
    ElemsMatch [⟨8, S⟩, ⟨8, X⟩, ⟨8, L⟩, ⟨8, Y⟩, ⟨8, aElem⟩] cert_h0930c075.elems :=
  elemsMatch_of (by show [S.bnd, X.bnd, L.bnd, Y.bnd, aElem.bnd] = _; rw [hS, hX, hL, hY]; rfl)

theorem halfQuartic_expr (S X L Y : ElemVal 8) :
    cert_h0930c075.exprValue (values [⟨8, S⟩, ⟨8, X⟩, ⟨8, L⟩, ⟨8, Y⟩, ⟨8, aElem⟩]) =
      S.value ^ 2 - 6 * S.value * X.value - 8 * L.value * Y.value -
      3 * X.value ^ 2 - 4 * aElem.value := by
  simp [PolyShape.exprValue, values, cert_h0930c075]
  ring

theorem halfQuartic_zero (S X L Y : ElemVal 8)
    (hS : (S.value : Fp) = (L.value : Fp) ^ 2)
    (hz : halfQuartic (X.value : Fp) (Y.value : Fp) (L.value : Fp) = 0) :
    cert_h0930c075.exprValue (values [⟨8, S⟩, ⟨8, X⟩, ⟨8, L⟩, ⟨8, Y⟩, ⟨8, aElem⟩])
      ≡ 0 [ZMOD (cert_h0930c075.m : ℤ)] := by
  rw [halfQuartic_expr, show (cert_h0930c075.m : ℤ) = p from rfl, modEq_p_iff]
  push_cast
  rw [hS, aElem_cast]
  unfold halfQuartic at hz
  linear_combination hz

theorem halfQuartic_complete (hr : RangeComplete) (S X L Y : ElemVal 8)
    (hS : S.bnd = lazyOut lazy_h158c056f) (hX : X.bnd = reducedC)
    (hL : L.bnd = balC) (hY : Y.bnd = reducedC)
    (hv : (S.value : Fp) = (L.value : Fp) ^ 2)
    (hz : halfQuartic (X.value : Fp) (Y.value : Fp) (L.value : Fp) = 0) :
    CheckPolynomial_40_h0930c075 (vec5 S X L Y aElem) :=
  CheckPolynomial_40_h0930c075_complete _ (halfQuartic_match S X L Y hS hX hL hY) _
    (vec5_inputs S X L Y aElem) hr (halfQuartic_zero S X L Y hv hz)

end ZolanaVE.P256.Completeness
