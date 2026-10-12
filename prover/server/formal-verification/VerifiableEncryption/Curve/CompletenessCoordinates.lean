import VerifiableEncryption.Curve.CompletenessLimbs
import VerifiableEncryption.Curve.LadderAux
import VerifiableEncryption.Field.CompletenessRemainder
import VerifiableEncryption.Field.CompletenessEval

/-! Pure coordinate witnesses shared by output and curve constructors. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field

theorem aElem_cast : (aElem.value : Fp) = -3 := by
  rw [aElem_value]
  push_cast
  rw [ZMod.natCast_self]
  ring

/-- The unused raw slope-hint vector can also be chosen as the canonical
mathematical slope pieces. Its correspondence with running the Go hint remains
a separate obligation; the extracted gadget only constrains the balanced vector. -/
def rawSlopePieces (l : Fp) : List.Vector F 24 := List.Vector.ofFn (fun j =>
  (((l.val / 2 ^ (32 * (j.val / 3)) % 2 ^ 32) / 2 ^ (11 * (j.val % 3)) %
    2 ^ (min 11 (32 - 11 * (j.val % 3))) : ℕ) : F))

theorem linPair_limb (a b : ℤ) (A B : ElemVal 8) (i : Fin 8) :
    (linElem [(a, A), (b, B)]).limbs.get i = (a : F) * A.limbs.get i + (b : F) * B.limbs.get i := by
  rw [linElem, mkElem_limb]
  simp only [linX, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
  push_cast
  rw [← A.limb_eq, ← B.limb_eq]
  ring

theorem winX_native (v : ℕ) (hv : v < 2 ^ 256) : (winX v hv).limbs = natLimbVector8 v := by
  apply List.Vector.toList_injective
  rw [vec8_toList, natLimbVector8_list]
  simp only [winX, ← List.Vector.get_zero, mkElem_limb, xInts, natLimbs8,
    List.map_cons, List.map_nil, Int.cast_natCast]
  norm_num only [Fin.coe_ofNat_eq_mod, Fin.val_zero, Nat.reduceMod,
    Nat.reduceMul, Nat.reducePow, Nat.div_one]

theorem p_remainder_width (E : ℤ) : (E % (p : ℤ)).toNat < 2 ^ 256 := by
  have hp : (0 : ℤ) < p := by norm_num [p]
  have h0 := Int.emod_nonneg E (by omega : (p : ℤ) ≠ 0)
  have hlt := Int.emod_lt_of_pos E hp
  have hcast := Int.toNat_of_nonneg h0
  have hpW : (p : ℤ) < 2 ^ 256 := by norm_num [p]
  omega

theorem canonicalRemainder_value (E : ℤ) :
    (winX ((E % (p : ℤ)).toNat) (p_remainder_width E)).value = E % (p : ℤ) := by
  rw [winX, mkElem_value, rec8_xInts (p_remainder_width E)]
  exact Int.toNat_of_nonneg (Int.emod_nonneg E (by norm_num [p]))

theorem canonicalRemainder_lt (E : ℤ) :
    limbNat (winX ((E % (p : ℤ)).toNat) (p_remainder_width E)).limbs < p := by
  have hv := (reduced_vals (show
    (winX ((E % (p : ℤ)).toNat) (p_remainder_width E)).bnd = reducedC from rfl)).2
  rw [canonicalRemainder_value] at hv
  have hlt := Int.emod_lt_of_pos E (by norm_num [p] : (0 : ℤ) < p)
  omega

theorem linDiff_limb (A B : ElemVal 8) (i : Fin 8) :
    (linElem [(1, A), (-1, B)]).limbs.get i = A.limbs.get i - B.limbs.get i := by
  rw [linElem, mkElem_limb]
  simp only [linX, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
  push_cast
  rw [← A.limb_eq, ← B.limb_eq]
  ring

def vec3 (A B C : ElemVal 8) : List.Vector F 24 :=
  vec![A.limbs.get 0, A.limbs.get 1, A.limbs.get 2, A.limbs.get 3,
    A.limbs.get 4, A.limbs.get 5, A.limbs.get 6, A.limbs.get 7,
    B.limbs.get 0, B.limbs.get 1, B.limbs.get 2, B.limbs.get 3,
    B.limbs.get 4, B.limbs.get 5, B.limbs.get 6, B.limbs.get 7,
    C.limbs.get 0, C.limbs.get 1, C.limbs.get 2, C.limbs.get 3,
    C.limbs.get 4, C.limbs.get 5, C.limbs.get 6, C.limbs.get 7]

theorem vec3_inputs (A B C : ElemVal 8) :
    limbLists [⟨8, A⟩, ⟨8, B⟩, ⟨8, C⟩] = outputCheckInputs (vec3 A B C) := by
  simp only [limbLists, List.map_cons, List.map_nil]
  rw [vec8_toList A.limbs, vec8_toList B.limbs, vec8_toList C.limbs]
  rfl

end ZolanaVE.P256.Completeness
