import VerifiableEncryption.Curve.Select

/-!
Hinted bits: `api.AssertIsBoolean`, `api.FromBinary` chunks and the
129-bit integers of `scalarFromBits`.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field

/-- The integer a native value stands for, as a bit. -/
def bitI {n : ℕ} (g : List.Vector F n) (j : ℕ) : ℤ := ((g.toList.getD j 0).val : ℤ)

theorem bitI_of_bool {n : ℕ} {g : List.Vector F n} {j : ℕ} (h : GatesDef.is_bool (g.toList.getD j 0)) :
    (bitI g j = 0 ∨ bitI g j = 1) ∧ ((bitI g j : ℤ) : F) = g.toList.getD j 0 := by
  unfold bitI
  refine ⟨?_, by simp⟩
  unfold GatesDef.is_bool at h
  rcases mul_eq_zero.mp h with h | h
  · right
    have : g.toList.getD j 0 = 1 := by linear_combination -h
    rw [this, ZMod.val_one]; norm_num
  · left
    rw [h, ZMod.val_zero]; norm_num

theorem recover_ofFn {d : ℕ} (f : Fin d → F) :
    recover_binary_zmod' (List.Vector.ofFn f) = ∑ j : Fin d, 2 ^ j.val * f j := by
  induction d with
  | zero => simp [recover_binary_zmod']
  | succ d ih =>
    simp only [recover_binary_zmod']
    rw [List.Vector.head_ofFn, List.Vector.tail_ofFn, ih, Fin.sum_univ_succ, Finset.mul_sum]
    congr 1
    · simp
    · apply Finset.sum_congr rfl; intro j _; simp [Fin.val_succ, pow_succ]; ring

end ZolanaVE.P256
