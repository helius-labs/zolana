import VerifiableEncryption.Curve.Bits
import VerifiableEncryption.Curve.Ladder

/-!
Element-level facts the ladder composition uses repeatedly.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem vec8_eta {α : Type*} (v : List.Vector α 8) :
    (v.get 0 ::ᵥ v.get 1 ::ᵥ v.get 2 ::ᵥ v.get 3 ::ᵥ v.get 4 ::ᵥ v.get 5 ::ᵥ v.get 6 ::ᵥ v.get 7 ::ᵥ
      List.Vector.nil) = v := by
  apply List.Vector.toList_injective
  rw [vec8_toList v]
  rfl

theorem reduced_vals {e : ElemVal 8} (h : e.bnd = reducedC) :
    (∀ i, (e.limbs.get i).val < 2 ^ 32) ∧ (limbNat e.limbs : ℤ) = e.value :=
  e.reduced_limbs (reduced_lohi h)

/-- `AssertDistinctX` on two reduced elements: both canonical, values distinct mod `p`. -/
theorem distinctX_elem {A B : ElemVal 8} (hA : A.bnd = reducedC) (hB : B.bnd = reducedC)
    (h : AssertDistinctX_8_8_h83dcf683 A.limbs B.limbs) :
    0 ≤ A.value ∧ A.value < p ∧ 0 ≤ B.value ∧ B.value < p ∧ (A.value : Fp) ≠ (B.value : Fp) := by
  obtain ⟨la, va⟩ := reduced_vals hA
  obtain ⟨lb, vb⟩ := reduced_vals hB
  obtain ⟨h1, h2, h3⟩ := assertDistinctX_sound la lb h
  refine ⟨by rw [← va]; positivity, by rw [← va]; exact_mod_cast h1, by rw [← vb]; positivity,
    by rw [← vb]; exact_mod_cast h2, ?_⟩
  rw [← va, ← vb]
  exact_mod_cast h3

/-- Limbs of the curve constant `b` as `Field.Const`. -/
def bLimbs (i : Fin 8) : ℤ :=
  [668098635, 1003371582, 3428036854, 1696401072, 1989707452, 3018571093, 2855965671, 1522939352].getD i 0

theorem bConst_value : (constElem bLimbs).value = b := by
  rw [constElem_value]
  rfl

/-- `Select(σ, Neg(y), y)` of a reduced coordinate, with `s = 1 - 2σ`. -/
theorem signed_red_fits {Y : ElemVal 8} (hY : Y.bnd = reducedC) {s : ℤ} (hs : s = 1 ∨ s = -1) :
    Fits (fun i => s * Y.ints.get i) selC := by
  apply fits_uni
  · intro i
    have := uni_limb hY i
    rcases hs with rfl | rfl <;> constructor <;> linarith [this.1, this.2]
  · have hv : rec8 (fun i => s * Y.ints.get i) = s * Y.value := by rw [rec8_smul, Y.value_eq]
    rw [hv]
    have := uni_value hY
    rcases hs with rfl | rfl <;> constructor <;> linarith [this.1, this.2]

@[simp] theorem get2_0 {α : Type*} (a b : α) : (a ::ᵥ b ::ᵥ List.Vector.nil).get 0 = a := rfl
@[simp] theorem get2_1 {α : Type*} (a b : α) : (a ::ᵥ b ::ᵥ List.Vector.nil).get 1 = b := rfl

end ZolanaVE.P256
