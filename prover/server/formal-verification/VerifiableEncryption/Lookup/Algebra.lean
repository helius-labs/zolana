import Mathlib.Algebra.Polynomial.Roots
import Mathlib.Algebra.Polynomial.BigOperators
import Mathlib.Tactic

/-!
Algebraic part of a committed log-derivative lookup. `d` and `w` are fixed
before the challenge. Repeated poles must be grouped before using the
distinct-pole lemma; the grouped weight is a field-valued residue, not a
hint's assertion that it counted honestly.

The general denominator model also covers the production P-256 argument,
whose denominators depend polynomially on the same challenge used for column
separation. Nonzeroness for that specialization is a separate obligation.
-/

namespace ZolanaVE.Lookup

open Polynomial
open scoped BigOperators

variable {K : Type*} [Field K] {I : Type*} [DecidableEq I]

noncomputable def residual (s : Finset I) (d : I → K[X]) (w : I → K) : K[X] :=
  ∑ i ∈ s, C (w i) * ∏ j ∈ s.erase i, d j

/-- Actual division constraints, including unchecked table divisions. A table
pole with zero numerator leaves its quotient unconstrained. It is therefore
incorrect to silently rewrite every unchecked division as field division. -/
def Accepted (s : Finset I) (d : I → K[X]) (w : I → K) (x : K) : Prop :=
  ∃ q : I → K, (∀ i ∈ s, q i * (d i).eval x = w i) ∧ ∑ i ∈ s, q i = 0

def Pole (s : Finset I) (d : I → K[X]) (x : K) : Prop :=
  ∃ i ∈ s, (d i).eval x = 0

/-- Denominator clearing uses multiplication only, so even a zero denominator
does not invalidate this implication. Poles still need a separate failure
budget because they can erase the information in the residual. -/
theorem accepted_residual_zero (s : Finset I) (d : I → K[X]) (w : I → K)
    (x : K) (h : Accepted s d w x) : (residual s d w).eval x = 0 := by
  obtain ⟨q, hq, hs⟩ := h
  have hterm : ∀ i ∈ s,
      w i * (∏ j ∈ s.erase i, (d j).eval x) =
        q i * (∏ j ∈ s, (d j).eval x) := by
    intro i hi
    rw [← hq i hi, mul_assoc, Finset.mul_prod_erase s (fun j => (d j).eval x) hi]
  simp only [residual, eval_finset_sum, eval_mul, eval_C, eval_prod]
  calc
    (∑ i ∈ s, w i * ∏ j ∈ s.erase i, (d j).eval x) =
        ∑ i ∈ s, q i * ∏ j ∈ s, (d j).eval x := Finset.sum_congr rfl hterm
    _ = (∑ i ∈ s, q i) * (∏ j ∈ s, (d j).eval x) := (Finset.sum_mul _ _ _).symm
    _ = 0 := by rw [hs, zero_mul]

/-- General explicit degree bound: at most `(support size - 1) * D`. -/
theorem residual_degree_le (s : Finset I) (d : I → K[X]) (w : I → K)
    (D : ℕ) (hd : ∀ i ∈ s, (d i).natDegree ≤ D) :
    (residual s d w).natDegree ≤ (s.card - 1) * D := by
  apply natDegree_sum_le_of_forall_le
  intro i hi
  calc
    (C (w i) * ∏ j ∈ s.erase i, d j).natDegree ≤
        (C (w i)).natDegree + (∏ j ∈ s.erase i, d j).natDegree := natDegree_mul_le
    _ = (∏ j ∈ s.erase i, d j).natDegree := by simp
    _ ≤ ∑ j ∈ s.erase i, (d j).natDegree := natDegree_prod_le _ _
    _ ≤ ∑ _j ∈ s.erase i, D := Finset.sum_le_sum (fun j hj => hd j (Finset.mem_of_mem_erase hj))
    _ = (s.card - 1) * D := by simp [Finset.card_erase_of_mem hi]

/-- For distinct scalar poles, one nonzero grouped residue proves that the
residual is a nonzero polynomial. This is a derived algebraic fact. -/
theorem residual_ne_zero_of_distinct_poles (s : Finset I) (a : I → K) (w : I → K)
    (ha : Set.InjOn a (↑s : Set I)) (i : I) (hi : i ∈ s) (hw : w i ≠ 0) :
    residual s (fun j => X - C (a j)) w ≠ 0 := by
  have hprod : (∏ j ∈ s.erase i, (a i - a j)) ≠ 0 := by
    apply Finset.prod_ne_zero_iff.mpr
    intro j hj
    apply sub_ne_zero.mpr
    intro heq
    have hij := ha hi (Finset.mem_of_mem_erase hj) heq
    exact (Finset.ne_of_mem_erase hj) hij.symm
  have heval : (residual s (fun j => X - C (a j)) w).eval (a i) =
      w i * ∏ j ∈ s.erase i, (a i - a j) := by
    simp only [residual, eval_finset_sum, eval_mul, eval_C, eval_prod, eval_sub, eval_X]
    apply Finset.sum_eq_single i
    · intro j hj hji
      have hij : i ∈ s.erase j := Finset.mem_erase.mpr ⟨hji.symm, hi⟩
      have hz : (∏ k ∈ s.erase j, (a i - a k)) = 0 :=
        Finset.prod_eq_zero hij (sub_self (a i))
      rw [hz, mul_zero]
    · exact fun hn => (hn hi).elim
  intro hz
  have hn := mul_ne_zero hw hprod
  apply hn
  rw [← heval, hz, eval_zero]

end ZolanaVE.Lookup
