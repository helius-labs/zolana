import VerifiableEncryption.Curve.CompletenessCanonical
import VerifiableEncryption.Curve.CombWindows
import VerifiableEncryption.Curve.LadderAux
import VerifiableEncryption.Curve.CompletenessLadderHalfTangent
import VerifiableEncryption.Curve.CompletenessLadderSelection

/-! Canonical affine and scalar inputs constructed from mathematical values.
The scalar reduction is a witness construction, not a restriction that the
original 32-byte scalar must already be less than the scalar modulus. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field
open scoped BigOperators

def canonicalNatElem (v : ℕ) (hv : v < 2 ^ 256) : ElemVal 8 := winX v hv

theorem canonicalNatElem_value (v : ℕ) (hv : v < 2 ^ 256) :
    (canonicalNatElem v hv).value = (v : ℤ) := by
  rw [canonicalNatElem, winX, mkElem_value, rec8_xInts hv]

theorem canonicalNatElem_limbNat (v : ℕ) (hv : v < 2 ^ 256) :
    limbNat (canonicalNatElem v hv).limbs = v := by
  have he := (reduced_vals (show (canonicalNatElem v hv).bnd = reducedC from rfl)).2
  rw [canonicalNatElem_value] at he
  exact_mod_cast he

theorem canonicalNatElem_bounds (v : ℕ) (hv : v < 2 ^ 256) :
    ∀ i, ((canonicalNatElem v hv).limbs.get i).val < 2 ^ 32 :=
  (reduced_vals (show (canonicalNatElem v hv).bnd = reducedC from rfl)).1

def canonicalFpElem (x : Fp) : ElemVal 8 :=
  canonicalNatElem x.val (lt_trans (ZMod.val_lt x) p_lt_two_pow)

theorem canonicalFpElem_cast (x : Fp) : ((canonicalFpElem x).value : Fp) = x := by
  rw [canonicalFpElem, canonicalNatElem_value]
  simp only [Int.cast_natCast, ZMod.natCast_zmod_val]

theorem canonicalFpElem_check (x : Fp) :
    AssertCanonical_8_0_hc36017e9 (canonicalFpElem x).limbs := by
  apply canonicalP_complete
  · exact canonicalNatElem_bounds _ _
  · rw [canonicalFpElem, canonicalNatElem_limbNat]
    exact ZMod.val_lt x

/-- Every nonzero group point has canonical bounded affine witnesses. -/
theorem canonicalAffine_exists (Q : P) (hq : Q ≠ 0) :
    ∃ X Y : ElemVal 8, X.bnd = reducedC ∧ Y.bnd = reducedC ∧
      ∃ hxy : OnCurve (X.value : Fp) (Y.value : Fp),
        mkPoint hxy = Q := by
  obtain ⟨x, y, hxy, he⟩ := affine_of_nonzero Q hq
  refine ⟨canonicalFpElem x, canonicalFpElem y, rfl, rfl, ?_⟩
  simpa only [canonicalFpElem_cast] using ⟨hxy, he⟩

theorem canonicalProduct_exists (Q : P) (hq : Q ≠ 0) (scalar : ℤ)
    (hs : (scalar : ScalarField) ≠ 0) :
    ∃ X Y : ElemVal 8, X.bnd = reducedC ∧ Y.bnd = reducedC ∧
      ∃ hxy : OnCurve (X.value : Fp) (Y.value : Fp),
        mkPoint hxy = scalar • Q :=
  canonicalAffine_exists _ (scalar_product_nonzero hq hs)

theorem n_lt_ladder_width : n < 2 ^ 256 := by decide +kernel

def canonicalScalar (original : ℕ) : ElemVal 8 :=
  canonicalNatElem (original % n)
    (lt_trans (Nat.mod_lt _ (by norm_num [n])) n_lt_ladder_width)

theorem canonicalScalar_value (original : ℕ) :
    (canonicalScalar original).value = ((original % n : ℕ) : ℤ) :=
  canonicalNatElem_value _ _

theorem canonicalScalar_cast (original : ℕ) :
    ((canonicalScalar original).value : ScalarField) = (original : ScalarField) := by
  rw [canonicalScalar_value]
  simp only [Int.cast_natCast, ZMod.natCast_mod]

theorem originalScalar_product (original : ℕ) (Q : P) :
    (original % n) • Q = original • Q := by
  have he := congrArg (fun v : ℕ => v • Q) (Nat.mod_add_div original n)
  simpa only [add_nsmul, mul_nsmul, Assumptions.p256_point_order, nsmul_zero, add_zero] using he

/-- For bounded canonical limbs the actual native squared-difference test
vanishes exactly at equality of the represented integers. The strict native
sum bound comes from the independently proved distinct-x completeness fact. -/
theorem canonicalDifference_zero_iff (v w : ℕ) (hv : v < 2 ^ 256) (hw : w < 2 ^ 256) :
    (∑ i : Fin 8,
      ((canonicalNatElem v hv).limbs.get i - (canonicalNatElem w hw).limbs.get i) ^ 2) = 0 ↔
      v = w := by
  constructor
  · intro hz
    by_contra hn
    have hne : limbNat (canonicalNatElem v hv).limbs ≠
        limbNat (canonicalNatElem w hw).limbs := by
      simpa only [canonicalNatElem_limbNat] using hn
    exact distinctX_sum_nonzero _ _ (canonicalNatElem_bounds _ _)
      (canonicalNatElem_bounds _ _) hne hz
  · intro he
    subst w
    simp

end ZolanaVE.P256.Completeness
