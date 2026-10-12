import Mathlib

/-!
Bounded-degree Kronecker substitution. Variables `j` are replaced by
`X^(B^j)`. The degree bound prevents carries between radix digits, so a
nonzero multivariate polynomial of total degree below `B` stays nonzero.
This is an algebraic statement; there is no challenge distribution premise.
-/

namespace ZolanaVE.Lookup

open scoped Polynomial BigOperators

def radixCode (B : ℕ) : {n : ℕ} → (Fin n → ℕ) → ℕ
  | 0, _ => 0
  | n + 1, d => d 0 + B * radixCode B (fun j : Fin n => d j.succ)

theorem radixCode_eq_sum (B : ℕ) {n : ℕ} (d : Fin n → ℕ) :
    radixCode B d = ∑ j : Fin n, B ^ j.val * d j := by
  induction n with
  | zero => simp [radixCode]
  | succ n ih =>
    rw [radixCode, ih, Fin.sum_univ_succ]
    simp only [Fin.val_zero, pow_zero, one_mul, Fin.val_succ, pow_succ]
    rw [Finset.mul_sum]
    congr 1
    apply Finset.sum_congr rfl
    intro j _
    ring

theorem radixCode_injective_on_digits (B : ℕ) {n : ℕ} (a b : Fin n → ℕ)
    (ha : ∀ j, a j < B) (hb : ∀ j, b j < B)
    (h : radixCode B a = radixCode B b) : a = b := by
  induction n with
  | zero => funext j; exact Fin.elim0 j
  | succ n ih =>
    have hB : 0 < B := lt_of_le_of_lt (Nat.zero_le _) (ha 0)
    have hhead : a 0 = b 0 := by
      have hm := congrArg (fun x => x % B) h
      simpa [radixCode, Nat.add_mod, Nat.mul_mod,
        Nat.mod_eq_of_lt (ha 0), Nat.mod_eq_of_lt (hb 0)] using hm
    have htail : radixCode B (fun j : Fin n => a j.succ) =
        radixCode B (fun j : Fin n => b j.succ) := by
      simp only [radixCode, hhead] at h
      exact Nat.eq_of_mul_eq_mul_left hB (Nat.add_left_cancel h)
    have ht := ih (fun j => a j.succ) (fun j => b j.succ)
      (fun j => ha j.succ) (fun j => hb j.succ) htail
    funext j
    refine Fin.cases hhead (fun k => congrFun ht k) j

variable {K : Type*} [Field K]

noncomputable def kronecker (B n : ℕ) : MvPolynomial (Fin n) K →+* K[X] :=
  MvPolynomial.eval₂Hom Polynomial.C (fun j => Polynomial.X ^ (B ^ j.val))

theorem kronecker_as_sum (B n : ℕ) (p : MvPolynomial (Fin n) K) :
    kronecker B n p = ∑ m ∈ p.support,
      Polynomial.C (p.coeff m) * Polynomial.X ^ radixCode B (fun j => m j) := by
  classical
  change p.eval₂ Polynomial.C (fun j => Polynomial.X ^ (B ^ j.val)) = _
  rw [MvPolynomial.eval₂_eq']
  apply Finset.sum_congr rfl
  intro m _
  rw [radixCode_eq_sum]
  simp only [← pow_mul, Finset.prod_pow_eq_pow_sum]

theorem kronecker_coeff_of_totalDegree_lt (B n : ℕ) (p : MvPolynomial (Fin n) K)
    (hdegree : p.totalDegree < B) (m : Fin n →₀ ℕ) (hm : m ∈ p.support) :
    (kronecker B n p).coeff (radixCode B (fun j => m j)) = p.coeff m := by
  classical
  have hdigit : ∀ a ∈ p.support, ∀ j, a j < B := by
    intro a ha j
    exact lt_of_le_of_lt ((MvPolynomial.monomial_le_degreeOf j ha).trans
      (MvPolynomial.degreeOf_le_totalDegree p j)) hdegree
  rw [kronecker_as_sum, Polynomial.finset_sum_coeff, Finset.sum_eq_single m]
  · simp [Polynomial.coeff_C_mul_X_pow]
  · intro a ha ham
    have hne : radixCode B (fun j => m j) ≠ radixCode B (fun j => a j) := by
      intro h
      have he := radixCode_injective_on_digits B (fun j => m j) (fun j => a j)
        (hdigit m hm) (hdigit a ha) h
      apply ham
      exact Finsupp.ext (fun j => (congrFun he j).symm)
    simp [Polynomial.coeff_C_mul_X_pow, hne]
  · exact fun h => (h hm).elim

theorem kronecker_ne_zero_of_totalDegree_lt (B n : ℕ) (p : MvPolynomial (Fin n) K)
    (hdegree : p.totalDegree < B) (hp : p ≠ 0) : kronecker B n p ≠ 0 := by
  classical
  obtain ⟨m, hm⟩ : ∃ m, m ∈ p.support := by
    apply Finset.nonempty_iff_ne_empty.mpr
    exact fun hs => hp (MvPolynomial.support_eq_empty.mp hs)
  intro h
  have hc := kronecker_coeff_of_totalDegree_lt B n p hdegree m hm
  rw [h, Polynomial.coeff_zero] at hc
  exact (MvPolynomial.mem_support_iff.mp hm) hc.symm

end ZolanaVE.Lookup
