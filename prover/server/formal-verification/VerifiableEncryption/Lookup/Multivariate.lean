import VerifiableEncryption.Lookup.Kronecker
import VerifiableEncryption.Lookup.Algebra

/-!
Reciprocal independence before column compression. Each distinct indexed
tuple has a distinct linear pole in the root variable. Substituting one pole
annihilates every residual summand except its own. Kronecker substitution
then preserves nonzeroness when the support size is below the radix.
-/

namespace ZolanaVE.Lookup

open scoped Polynomial BigOperators

variable {K : Type*} [Field K] {d : ℕ}

abbrev LookupTuple (K : Type*) (d : ℕ) := K × (Fin d → K)

noncomputable def tupleLinearForm (t : LookupTuple K d) : MvPolynomial (Fin d) K :=
  MvPolynomial.C t.1 + ∑ j : Fin d, MvPolynomial.C (t.2 j) * MvPolynomial.X j

theorem tupleLinearForm_coeff_zero (t : LookupTuple K d) :
    (tupleLinearForm t).coeff 0 = t.1 := by
  classical
  simp [tupleLinearForm, MvPolynomial.coeff_add, MvPolynomial.coeff_sum,
    MvPolynomial.coeff_C_mul, MvPolynomial.coeff_X']

theorem tupleLinearForm_coeff_column (t : LookupTuple K d) (j : Fin d) :
    (tupleLinearForm t).coeff (Finsupp.single j 1) = t.2 j := by
  classical
  have hs : ∀ i : Fin d, Finsupp.single i (1 : ℕ) = Finsupp.single j 1 ↔ i = j :=
    fun i => (Finsupp.single_left_injective Nat.one_ne_zero).eq_iff
  have hn : (0 : Fin d →₀ ℕ) ≠ Finsupp.single j 1 := by
    intro he
    have hj := congrArg (fun m : Fin d →₀ ℕ => m j) he
    simp at hj
  simp [tupleLinearForm, MvPolynomial.coeff_add, MvPolynomial.coeff_sum,
    MvPolynomial.coeff_C_mul, MvPolynomial.coeff_X', hs, hn, mul_ite]

theorem tupleLinearForm_injective : Function.Injective (tupleLinearForm (K := K) (d := d)) := by
  intro a b h
  apply Prod.ext
  · have hc := congrArg (fun p : MvPolynomial (Fin d) K => p.coeff 0) h
    simpa only [tupleLinearForm_coeff_zero] using hc
  · funext j
    have hc := congrArg (fun p : MvPolynomial (Fin d) K => p.coeff (Finsupp.single j 1)) h
    simpa only [tupleLinearForm_coeff_column] using hc

noncomputable def tupleDenominator (t : LookupTuple K d) : MvPolynomial (Fin (d + 1)) K :=
  MvPolynomial.X 0 - MvPolynomial.C t.1 -
    ∑ j : Fin d, MvPolynomial.C (t.2 j) * MvPolynomial.X j.succ

noncomputable def specializeTuple (a : LookupTuple K d) :
    MvPolynomial (Fin (d + 1)) K →+* MvPolynomial (Fin d) K :=
  MvPolynomial.eval₂Hom MvPolynomial.C
    (Fin.cases (tupleLinearForm a) (fun j => MvPolynomial.X j))

theorem specializeTuple_denominator (a b : LookupTuple K d) :
    specializeTuple a (tupleDenominator b) = tupleLinearForm a - tupleLinearForm b := by
  classical
  simp only [specializeTuple, tupleDenominator, map_sub, map_sum, map_mul,
    MvPolynomial.eval₂Hom_X', MvPolynomial.eval₂Hom_C, Fin.cases_zero, Fin.cases_succ,
    tupleLinearForm]
  ring

theorem tupleDenominator_totalDegree_le (t : LookupTuple K d) :
    (tupleDenominator t).totalDegree ≤ 1 := by
  classical
  unfold tupleDenominator
  apply le_trans (MvPolynomial.totalDegree_sub _ _) (max_le ?_ ?_)
  · apply le_trans (MvPolynomial.totalDegree_sub _ _) (max_le ?_ ?_)
    · simp
    · simp
  · apply MvPolynomial.totalDegree_finsetSum_le
    intro j _
    simpa only [MvPolynomial.totalDegree_C, MvPolynomial.totalDegree_X, zero_add] using
      MvPolynomial.totalDegree_mul (MvPolynomial.C (t.2 j)) (MvPolynomial.X j.succ)

variable [DecidableEq K]

noncomputable def tupleResidual (s : Finset (LookupTuple K d))
    (w : LookupTuple K d → K) : MvPolynomial (Fin (d + 1)) K :=
  ∑ a ∈ s, MvPolynomial.C (w a) * ∏ b ∈ s.erase a, tupleDenominator b

theorem tupleResidual_totalDegree_le (s : Finset (LookupTuple K d))
    (w : LookupTuple K d → K) : (tupleResidual s w).totalDegree ≤ s.card - 1 := by
  classical
  apply MvPolynomial.totalDegree_finsetSum_le
  intro a ha
  calc
    (MvPolynomial.C (w a) * ∏ b ∈ s.erase a, tupleDenominator b).totalDegree ≤
        (MvPolynomial.C (w a)).totalDegree +
          (∏ b ∈ s.erase a, tupleDenominator b).totalDegree := MvPolynomial.totalDegree_mul _ _
    _ = (∏ b ∈ s.erase a, tupleDenominator b).totalDegree := by simp
    _ ≤ ∑ b ∈ s.erase a, (tupleDenominator b).totalDegree :=
      MvPolynomial.totalDegree_finset_prod _ _
    _ ≤ ∑ _b ∈ s.erase a, 1 :=
      Finset.sum_le_sum (fun b _ => tupleDenominator_totalDegree_le b)
    _ = s.card - 1 := by simp [Finset.card_erase_of_mem ha]

theorem tupleResidual_ne_zero (s : Finset (LookupTuple K d)) (w : LookupTuple K d → K)
    (a : LookupTuple K d) (ha : a ∈ s) (hw : w a ≠ 0) : tupleResidual s w ≠ 0 := by
  classical
  have hp : (∏ b ∈ s.erase a, (tupleLinearForm a - tupleLinearForm b)) ≠ 0 := by
    apply Finset.prod_ne_zero_iff.mpr
    intro b hb
    apply sub_ne_zero.mpr
    intro he
    have hab := tupleLinearForm_injective he
    exact (Finset.ne_of_mem_erase hb) hab.symm
  have hc : (MvPolynomial.C (w a) : MvPolynomial (Fin d) K) ≠ 0 := by
    simpa using hw
  have heval : specializeTuple a (tupleResidual s w) =
      MvPolynomial.C (w a) * ∏ b ∈ s.erase a, (tupleLinearForm a - tupleLinearForm b) := by
    simp only [tupleResidual, map_sum, map_mul, map_prod,
      specializeTuple, MvPolynomial.eval₂Hom_C]
    change (∑ b ∈ s, MvPolynomial.C (w b) *
      ∏ c ∈ s.erase b, specializeTuple a (tupleDenominator c)) = _
    simp only [specializeTuple_denominator]
    apply Finset.sum_eq_single a
    · intro b hb hba
      have hab : a ∈ s.erase b := Finset.mem_erase.mpr ⟨hba.symm, ha⟩
      have hz : (∏ c ∈ s.erase b, (tupleLinearForm a - tupleLinearForm c)) = 0 :=
        Finset.prod_eq_zero hab (sub_self _)
      rw [hz, mul_zero]
    · exact fun h => (h ha).elim
  intro hz
  apply mul_ne_zero hc hp
  rw [← heval, hz, map_zero]

/-- The actual separated one-variable denominator family. For radix 256 and
twelve columns this is the custom P-256 row denominator; for one column and
radix `2^20` it is the tagged range denominator. -/
noncomputable def separatedDenominator (B : ℕ) (t : LookupTuple K d) : K[X] :=
  Polynomial.X - Polynomial.C t.1 -
    ∑ j : Fin d, Polynomial.C (t.2 j) * Polynomial.X ^ (B ^ (j.val + 1))

theorem kronecker_tupleDenominator (B : ℕ) (t : LookupTuple K d) :
    kronecker B (d + 1) (tupleDenominator t) = separatedDenominator B t := by
  classical
  simp [kronecker, tupleDenominator, separatedDenominator,
    MvPolynomial.eval₂Hom_X', MvPolynomial.eval₂Hom_C]

theorem kronecker_tupleResidual (B : ℕ) (s : Finset (LookupTuple K d))
    (w : LookupTuple K d → K) :
    kronecker B (d + 1) (tupleResidual s w) = residual s (separatedDenominator B) w := by
  classical
  simp only [tupleResidual, residual, map_sum, map_mul, map_prod,
    kronecker_tupleDenominator]
  simp [kronecker, MvPolynomial.eval₂Hom_C]

/-- A nonzero grouped residue remains nonzero for the *actual* radix-separated
argument. The support cap rules out exponent carries. No desired lookup
correctness or invalid-query residual conclusion is assumed. -/
theorem separatedResidual_ne_zero (B : ℕ) (s : Finset (LookupTuple K d))
    (w : LookupTuple K d → K) (hsize : s.card < B)
    (a : LookupTuple K d) (ha : a ∈ s) (hw : w a ≠ 0) :
    residual s (separatedDenominator B) w ≠ 0 := by
  rw [← kronecker_tupleResidual]
  exact kronecker_ne_zero_of_totalDegree_lt B (d + 1) (tupleResidual s w)
    (lt_of_le_of_lt (tupleResidual_totalDegree_le s w)
      (lt_of_le_of_lt (Nat.sub_le _ _) hsize))
    (tupleResidual_ne_zero s w a ha hw)

end ZolanaVE.Lookup
