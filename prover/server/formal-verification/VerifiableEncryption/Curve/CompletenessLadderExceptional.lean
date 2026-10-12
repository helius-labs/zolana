import VerifiableEncryption.Curve.CompletenessLadderInputs

/-! The six literal equality detectors in ScalarMulChecked main and p1.
Each tests a sum of eight squared 32-bit limb differences. Canonical scalar
witnesses make these native tests coincide with the six scalar-field cases. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field
open scoped BigOperators

def exceptionalNat (i : Fin 6) : ℕ :=
  [1, n - 1, 3, n - 3, (2 * n + 1) / 3, (n - 1) / 3].getD i.val 0

theorem exceptionalNat_lt (i : Fin 6) : exceptionalNat i < n := by
  fin_cases i <;> norm_num [exceptionalNat, n]

def exceptionalLimbs : List.Vector (List.Vector F 8) 6 := vec![
  vec![1, 0, 0, 0, 0, 0, 0, 0],
  vec![4234356048, 4089039554, 2803342980, 3169254061, 4294967295, 4294967295, 0, 4294967295],
  vec![3, 0, 0, 0, 0, 0, 0, 0],
  vec![4234356046, 4089039554, 2803342980, 3169254061, 4294967295, 4294967295, 0, 4294967295],
  vec![2822904033, 1294370604, 437239555, 2112836041, 2863311530, 2863311530, 0, 2863311530],
  vec![1411452016, 2794668950, 2366103425, 1056418020, 1431655765, 1431655765, 0, 1431655765]]

theorem exceptionalLimbs_canonical (i : Fin 6) :
    exceptionalLimbs.get i =
      (canonicalNatElem (exceptionalNat i)
        (lt_trans (exceptionalNat_lt i) n_lt_ladder_width)).limbs := by
  apply List.Vector.ext
  intro j
  rw [canonicalNatElem, winX, mkElem_limb]
  fin_cases i <;> fin_cases j <;>
    norm_num [exceptionalLimbs, exceptionalNat,
      List.Vector.get, List.Vector.head, xInts, n]

def exceptionalSquared (original : ℕ) (i : Fin 6) : F :=
  ∑ j : Fin 8, ((canonicalScalar original).limbs.get j - (exceptionalLimbs.get i).get j) ^ 2

theorem exceptionalSquared_zero_iff (original : ℕ) (i : Fin 6) :
    exceptionalSquared original i = 0 ↔ original % n = exceptionalNat i := by
  rw [exceptionalSquared, exceptionalLimbs_canonical]
  exact canonicalDifference_zero_iff _ _ _ _

def exceptionalFlag (original : ℕ) (i : Fin 6) : F :=
  zeroIndicator (exceptionalSquared original i)

theorem exceptionalFlag_spec (original : ℕ) (i : Fin 6) :
    Gates.is_zero (exceptionalSquared original i) (exceptionalFlag original i) :=
  zeroIndicator_spec _

theorem exceptionalFlag_native_spec (original : ℕ) (i : Fin 6) :
    GatesDef.is_zero (exceptionalSquared original i) (exceptionalFlag original i) :=
  zeroIndicator_native_spec _

theorem exceptionalFlag_eq (original : ℕ) (i : Fin 6) :
    exceptionalFlag original i =
      if original % n = exceptionalNat i then 1 else 0 := by
  simp only [exceptionalFlag, zeroIndicator, exceptionalSquared_zero_iff]

theorem exceptionalNat_scalar (i : Fin 6) :
    (exceptionalNat i : ScalarField) =
      [1, -1, 3, -3, 1 / 3, -(1 / 3)].getD i.val 0 := by
  fin_cases i <;> decide +kernel

theorem exceptionalNat_membership (s : ScalarField) :
    (∃ i : Fin 6, s.val = exceptionalNat i) ↔ Exceptional s := by
  constructor
  · rintro ⟨i, he⟩
    have hs : s = (exceptionalNat i : ScalarField) := by
      rw [← ZMod.natCast_zmod_val s, he]
    rw [hs, exceptionalNat_scalar]
    fin_cases i <;> simp [Exceptional]
  · intro hs
    rcases hs with h | h | h | h | h | h
    · refine ⟨0, ?_⟩
      have he := exceptionalNat_scalar (0 : Fin 6)
      simpa [h, ZMod.val_natCast, Nat.mod_eq_of_lt (exceptionalNat_lt 0)] using
        (congrArg ZMod.val he).symm
    · refine ⟨1, ?_⟩
      have he := exceptionalNat_scalar (1 : Fin 6)
      simpa [h, ZMod.val_natCast, Nat.mod_eq_of_lt (exceptionalNat_lt 1)] using
        (congrArg ZMod.val he).symm
    · refine ⟨2, ?_⟩
      have he := exceptionalNat_scalar (2 : Fin 6)
      simpa [h, ZMod.val_natCast, Nat.mod_eq_of_lt (exceptionalNat_lt 2)] using
        (congrArg ZMod.val he).symm
    · refine ⟨3, ?_⟩
      have he := exceptionalNat_scalar (3 : Fin 6)
      simpa [h, ZMod.val_natCast, Nat.mod_eq_of_lt (exceptionalNat_lt 3)] using
        (congrArg ZMod.val he).symm
    · refine ⟨4, ?_⟩
      have he := exceptionalNat_scalar (4 : Fin 6)
      simpa [h, ZMod.val_natCast, Nat.mod_eq_of_lt (exceptionalNat_lt 4)] using
        (congrArg ZMod.val he).symm
    · refine ⟨5, ?_⟩
      have he := exceptionalNat_scalar (5 : Fin 6)
      simpa [h, ZMod.val_natCast, Nat.mod_eq_of_lt (exceptionalNat_lt 5)] using
        (congrArg ZMod.val he).symm

theorem exceptionalNat_injective : Function.Injective exceptionalNat := by
  intro i j he
  fin_cases i <;> fin_cases j <;> norm_num [exceptionalNat, n] at he ⊢

/-- The actual sum of six native zero flags is exactly a Boolean exceptional
selector. Pairwise distinct canonical residues rule out two active flags. -/
theorem exceptionalFlag_sum (original : ℕ) :
    (∑ i : Fin 6, exceptionalFlag original i) =
      if Exceptional (original : ScalarField) then 1 else 0 := by
  by_cases he : Exceptional (original : ScalarField)
  · obtain ⟨j, hj⟩ := (exceptionalNat_membership (original : ScalarField)).mpr he
    have hj' : original % n = exceptionalNat j := by
      simpa only [ZMod.val_natCast] using hj
    have hflag : ∀ i : Fin 6, exceptionalFlag original i = if i = j then 1 else 0 := by
      intro i
      rw [exceptionalFlag_eq]
      have hiff : original % n = exceptionalNat i ↔ i = j := by
        constructor
        · intro hi
          exact exceptionalNat_injective (hi.symm.trans hj')
        · rintro rfl
          exact hj'
      simp only [hiff]
    simp [hflag, he]
  · have hflag : ∀ i : Fin 6, exceptionalFlag original i = 0 := by
      intro i
      have hi : original % n ≠ exceptionalNat i := by
        intro hi
        exact he ((exceptionalNat_membership (original : ScalarField)).mp
          ⟨i, by simpa only [ZMod.val_natCast] using hi⟩)
      simp only [exceptionalFlag_eq, hi, if_false]
    simp [hflag, he]

def halfScalarElem (original : ℕ) : ElemVal 8 :=
  canonicalNatElem (((original : ScalarField) / 2).val)
    (lt_trans (ZMod.val_lt _) n_lt_ladder_width)

theorem halfScalarElem_cast (original : ℕ) :
    ((halfScalarElem original).value : ScalarField) = (original : ScalarField) / 2 := by
  rw [halfScalarElem, canonicalNatElem_value]
  simp only [Int.cast_natCast, ZMod.natCast_zmod_val]

def selectedScalarElem (original : ℕ) : ElemVal 8 :=
  if Exceptional (original : ScalarField) then halfScalarElem original else canonicalScalar original

theorem selectedScalarElem_bounds (original : ℕ) :
    (selectedScalarElem original).bnd = reducedC := by
  unfold selectedScalarElem
  split_ifs <;> rfl

theorem selectedScalarElem_cast (original : ℕ) :
    ((selectedScalarElem original).value : ScalarField) = selectedScalar (original : ScalarField) := by
  by_cases he : Exceptional (original : ScalarField)
  · simp only [selectedScalarElem, selectedScalar, he, if_true, halfScalarElem_cast]
  · simp only [selectedScalarElem, selectedScalar, he, if_false, canonicalScalar_cast]

/-- Actual per-limb selects at gates 394--401 choose the selected scalar
using precisely the constructed sum of the six native zero flags. -/
theorem selectedScalarElem_select (original : ℕ) (i : Fin 8) :
    Gates.select (∑ j : Fin 6, exceptionalFlag original j)
      ((halfScalarElem original).limbs.get i) ((canonicalScalar original).limbs.get i)
      ((selectedScalarElem original).limbs.get i) := by
  rw [exceptionalFlag_sum]
  by_cases he : Exceptional (original : ScalarField) <;>
    simp [he, selectedScalarElem, Gates, GatesGnark12, GatesGnark9, GatesGnark8,
      GatesDef.select, GatesDef.is_bool]

def selectedPointLimbs (original : ℕ) (doubled unchanged : List.Vector F 8) : List.Vector F 8 :=
  if Exceptional (original : ScalarField) then doubled else unchanged

theorem selectedPointLimbs_native_select (original : ℕ)
    (doubled unchanged : List.Vector F 8) (i : Fin 8) :
    GatesDef.select (∑ j : Fin 6, exceptionalFlag original j)
      (doubled.get i) (unchanged.get i) ((selectedPointLimbs original doubled unchanged).get i) := by
  rw [exceptionalFlag_sum]
  by_cases he : Exceptional (original : ScalarField) <;>
    simp [he, selectedPointLimbs, GatesDef.select, GatesDef.is_bool]

theorem selectedScalarElem_native_select (original : ℕ) (i : Fin 8) :
    GatesDef.select (∑ j : Fin 6, exceptionalFlag original j)
      ((halfScalarElem original).limbs.get i) ((canonicalScalar original).limbs.get i)
      ((selectedScalarElem original).limbs.get i) := by
  simpa only [Gates, GatesGnark12, GatesGnark9, GatesGnark8] using selectedScalarElem_select original i

theorem selectedOriginal_product (original : ℕ) (Q : P) (hq : Q ≠ 0) :
    (selectedScalar (original : ScalarField)).val • selectedPoint (original : ScalarField) Q =
      original • Q := by
  have he := selected_product_eq (original : ScalarField) hq
  rw [ZMod.val_natCast] at he
  exact he.trans (originalScalar_product original Q)

def scalarHalfConstant : ElemVal 8 :=
  canonicalNatElem ((n + 1) / 2) (by norm_num [n])

theorem scalarHalfConstant_native : scalarHalfConstant.limbs =
    vec![2117178025, 2044519777, 3549155138, 3732110678,
      4294967295, 2147483647, 2147483648, 2147483647] := by
  apply List.Vector.ext
  intro i
  rw [scalarHalfConstant, canonicalNatElem, winX, mkElem_limb]
  fin_cases i <;> norm_num [List.Vector.get, List.Vector.head, xInts, n]

theorem scalarHalfConstant_cast : (scalarHalfConstant.value : ScalarField) = 1 / 2 := by
  rw [scalarHalfConstant, canonicalNatElem_value]
  change (((n + 1) / 2 : ℕ) : ScalarField) = 1 / 2
  decide +kernel

/-- The mathematical result required by the actual scalar-halving Eval16
has exactly the two supplied bounded inputs and the canonical half output. -/
theorem halfScalarElem_product (original : ℕ) :
    ((halfScalarElem original).value : ScalarField) =
      ((canonicalScalar original).value : ScalarField) * (scalarHalfConstant.value : ScalarField) := by
  rw [halfScalarElem_cast, canonicalScalar_cast, scalarHalfConstant_cast]
  simp only [div_eq_mul_inv, one_mul]

end ZolanaVE.P256.Completeness
