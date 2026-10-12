import VerifiableEncryption.Lookup.GroupedSoundness
import VerifiableEncryption.Lookup.MiMC

/-!
The actual AES coefficient graph. Nonzeroness of the two-variable residual is
proved algebraically. Evaluation on the public MiMC graph is a separate
security obligation: graph membership is computable, and the two coordinates
must never be advertised as independent uniform samples.
-/

namespace ZolanaVE.Lookup

open scoped Polynomial BigOperators

variable [Fact (Nat.Prime Order)] {n m : ℕ}

noncomputable def aesDenominatorPolynomial (keccak : MiMC.Hash256)
    (t : LookupTuple F 1) : F[X] :=
  Polynomial.X - Polynomial.C t.1 - Polynomial.C (t.2 0) * MiMC.coefficientPolynomial keccak

noncomputable def aesGraph (keccak : MiMC.Hash256) : MvPolynomial (Fin 2) F →+* F[X] :=
  MvPolynomial.eval₂Hom Polynomial.C
    (Fin.cases Polynomial.X (fun _ : Fin 1 => MiMC.coefficientPolynomial keccak))

theorem aesGraph_tupleDenominator (keccak : MiMC.Hash256) (t : LookupTuple F 1) :
    aesGraph keccak (tupleDenominator t) = aesDenominatorPolynomial keccak t := by
  have hs : Fin.cases Polynomial.X
      (fun _ : Fin 1 => MiMC.coefficientPolynomial keccak) (1 : Fin 2) =
        MiMC.coefficientPolynomial keccak := rfl
  simp [aesGraph, tupleDenominator, aesDenominatorPolynomial,
    MvPolynomial.eval₂Hom_X', MvPolynomial.eval₂Hom_C, hs]

theorem aesDenominatorPolynomial_eval (keccak : MiMC.Hash256)
    (t : LookupTuple F 1) (x : F) :
    (aesDenominatorPolynomial keccak t).eval x = MiMC.denominator keccak t.1 (t.2 0) x := by
  simp only [aesDenominatorPolynomial, Polynomial.eval_sub, Polynomial.eval_X,
    Polynomial.eval_C, Polynomial.eval_mul, MiMC.coefficientPolynomial_eval,
    MiMC.denominator]
  ring

theorem aesGraph_tupleResidual (keccak : MiMC.Hash256) (b : TupleBatch F 1 n m) :
    aesGraph keccak (tupleResidual b.support b.residue) =
      residual b.support (aesDenominatorPolynomial keccak) b.residue := by
  simp only [tupleResidual, residual, map_sum, map_mul, map_prod, aesGraph_tupleDenominator]
  simp [aesGraph, MvPolynomial.eval₂Hom_C]

theorem aesGraph_eval (keccak : MiMC.Hash256) (p : MvPolynomial (Fin 2) F) (x : F) :
    (aesGraph keccak p).eval x =
      MvPolynomial.eval (Fin.cases x (fun _ : Fin 1 => MiMC.coefficient keccak x)) p := by
  have hh : (Polynomial.evalRingHom x).comp (aesGraph keccak) =
      MvPolynomial.eval (Fin.cases x (fun _ : Fin 1 => MiMC.coefficient keccak x)) := by
    apply MvPolynomial.ringHom_ext
    · intro value
      simp [aesGraph]
    · intro i
      refine Fin.cases ?_ (fun j => ?_) i
      · simp [aesGraph]
      · simp [aesGraph, MiMC.coefficientPolynomial_eval, Fin.cases_succ]
  exact RingHom.congr_fun hh p

noncomputable def aesBatch (keccak : MiMC.Hash256) (b : TupleBatch F 1 n m) : Batch F n m where
  table := fun i => aesDenominatorPolynomial keccak (b.table i)
  query := fun j => aesDenominatorPolynomial keccak (b.query j)
  multiplicity := b.multiplicity

theorem invalid_aes_multivariate_residual_ne_zero (b : TupleBatch F 1 n m)
    (hchar : m < Order) (j : Fin m) (hout : ∀ i, b.table i ≠ b.query j) :
    tupleResidual b.support b.residue ≠ 0 := by
  have hw : b.residue (b.query j) ≠ 0 := by
    rw [b.residue_outside_table _ hout]
    exact negative_count_ne_zero _ (b.queryCount_pos j)
      (lt_of_le_of_lt (b.queryCount_le _) hchar)
  exact tupleResidual_ne_zero b.support b.residue (b.query j) (b.query_mem_support j) hw

/-- Acceptance of the raw AES quotient constraints forces a zero on the
*actual* MiMC graph, regardless of table poles. No graph-root bound is assumed
or proved by this deterministic lemma. -/
theorem aes_accepted_graph_zero (keccak : MiMC.Hash256) (b : TupleBatch F 1 n m) (x : F)
    (h : Accepted Finset.univ (aesBatch keccak b).denominator (aesBatch keccak b).weight x) :
    (aesGraph keccak (tupleResidual b.support b.residue)).eval x = 0 := by
  have hd : (aesBatch keccak b).denominator = fun i => aesDenominatorPolynomial keccak (b.key i) := by
    funext i
    cases i <;> rfl
  rw [hd] at h
  have hg := accepted_grouped Finset.univ b.key (aesDenominatorPolynomial keccak) b.weight x h
  rw [aesGraph_tupleResidual]
  exact accepted_residual_zero b.support (aesDenominatorPolynomial keccak) b.residue x hg

def aesGraphZero (keccak : MiMC.Hash256) (b : TupleBatch F 1 n m) (r : ℕ) (root : F) : Prop :=
  tupleResidual b.support b.residue ≠ 0 ∧
    (aesGraph keccak (tupleResidual b.support b.residue)).eval (root ^ r) = 0

/-- An explicitly named security premise on graph zeros. It says nothing
about independent samples. In an adversarial experiment it must be justified
for the chosen snapshots, oracle queries and commitment/grinding resources,
not merely for an unrelated fresh polynomial.
-/
def MiMCGraphBound (keccak : MiMC.Hash256) (b : TupleBatch F 1 n m)
    (r : ℕ) (μ : Distribution F) (ε : ℚ) : Prop :=
  eventMass μ (aesGraphZero keccak b r) ≤ ε

theorem invalid_aes_acceptance_mass_le (keccak : MiMC.Hash256) (b : TupleBatch F 1 n m)
    (hchar : m < Order) (j : Fin m) (hout : ∀ i, b.table i ≠ b.query j)
    (r : ℕ) (μ : Distribution F) (ε : ℚ)
    (hgraph : MiMCGraphBound keccak b r μ ε) :
    eventMass μ (fun root => Accepted Finset.univ
      (aesBatch keccak b).denominator (aesBatch keccak b).weight (root ^ r)) ≤ ε := by
  classical
  have hn := invalid_aes_multivariate_residual_ne_zero b hchar j hout
  apply le_trans ?_ hgraph
  apply Finset.sum_le_sum_of_subset_of_nonneg
  · intro root hr
    obtain ⟨_, ha⟩ := Finset.mem_filter.mp hr
    exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, hn, aes_accepted_graph_zero keccak b _ ha⟩
  · intro root _ _
    exact μ.nonneg root

end ZolanaVE.Lookup
