import VerifiableEncryption.Lookup.ProductionAlgebra

/-!
Witness existence for the actual log-derivative quotient constraints is
separate from adversarial lookup soundness and from Go hint correctness.
For honest indexed queries, multiplicities count the selected table rows and
quotients are explicit sums of query inverses. Query denominators must be
nonzero. Unused table rows may have a zero denominator: their count and
constructed quotient are both zero, satisfying the unchecked division gate.
-/

namespace ZolanaVE.Lookup

open Polynomial
open scoped BigOperators

namespace Completeness

variable {K : Type*} [Field K] {n m : ℕ}

def selectedCount (selection : Fin m → Fin n) (i : Fin n) : ℕ :=
  (Finset.univ.filter (fun j => selection j = i)).card

/-- All table/query values and counts are fixed before the challenge. Counts
are mathematical witnesses, not a claim that the production count hint is
implemented correctly. -/
noncomputable def honestBatch (table : Fin n → K[X]) (selection : Fin m → Fin n) :
    Batch K n m where
  table := table
  query := fun j => table (selection j)
  multiplicity := fun i => (selectedCount selection i : K)

noncomputable def selectedQuotients (b : Batch K n m)
    (selection : Fin m → Fin n) (x : K) : Sum (Fin n) (Fin m) → K :=
  Sum.elim
    (fun i => ∑ j ∈ Finset.univ.filter (fun j => selection j = i),
      ((b.query j).eval x)⁻¹)
    (fun j => -((b.query j).eval x)⁻¹)

/-- Construct all raw quotient witnesses from true indexed selections. The
only denominator premise concerns the query inverses actually constrained
by production; no unchecked 0/0 division is silently assumed invertible. -/
theorem selected_batch_complete (b : Batch K n m) (selection : Fin m → Fin n)
    (hquery : ∀ j, b.query j = b.table (selection j))
    (hcount : ∀ i, b.multiplicity i = (selectedCount selection i : K))
    (x : K) (hden : ∀ j, (b.query j).eval x ≠ 0) :
    Accepted Finset.univ b.denominator b.weight x := by
  classical
  refine ⟨selectedQuotients b selection x, ?_, ?_⟩
  · intro entry _
    cases entry with
    | inl i =>
      change (∑ j ∈ Finset.univ.filter (fun j => selection j = i),
        ((b.query j).eval x)⁻¹) * (b.table i).eval x = b.multiplicity i
      rw [Finset.sum_mul, hcount i]
      calc
        (∑ j ∈ Finset.univ.filter (fun j => selection j = i),
            ((b.query j).eval x)⁻¹ * (b.table i).eval x) =
            ∑ _j ∈ Finset.univ.filter (fun j => selection j = i), (1 : K) := by
          apply Finset.sum_congr rfl
          intro j hj
          have hi := (Finset.mem_filter.mp hj).2
          have he := congrArg (fun p : K[X] => p.eval x) (hquery j)
          rw [hi] at he
          change (b.query j).eval x = (b.table i).eval x at he
          rw [← he, inv_mul_cancel₀ (hden j)]
        _ = (selectedCount selection i : K) := by simp [selectedCount]
    | inr j =>
      change -((b.query j).eval x)⁻¹ * (b.query j).eval x = -1
      rw [neg_mul, inv_mul_cancel₀ (hden j)]
  · change (∑ i : Sum (Fin n) (Fin m), selectedQuotients b selection x i) = 0
    simp only [Fintype.sum_sum_type, selectedQuotients, Sum.elim_inl, Sum.elim_inr]
    rw [Finset.sum_fiberwise, Finset.sum_neg_distrib, add_neg_cancel]

theorem honest_batch_complete (table : Fin n → K[X]) (selection : Fin m → Fin n)
    (x : K) (hden : ∀ j, (table (selection j)).eval x ≠ 0) :
    Accepted Finset.univ (honestBatch table selection).denominator
      (honestBatch table selection).weight x :=
  selected_batch_complete (honestBatch table selection) selection (fun _ => rfl)
    (fun _ => rfl) x hden

theorem selected_batch_failure_is_query_pole (b : Batch K n m)
    (selection : Fin m → Fin n)
    (hquery : ∀ j, b.query j = b.table (selection j))
    (hcount : ∀ i, b.multiplicity i = (selectedCount selection i : K))
    (x : K) (hfail : ¬ Accepted Finset.univ b.denominator b.weight x) :
    Pole Finset.univ b.query x := by
  classical
  by_contra hp
  apply hfail
  apply selected_batch_complete b selection hquery hcount x
  intro j hz
  exact hp ⟨j, Finset.mem_univ _, hz⟩

/-- When the total degree of the query-pole polynomial is below the field
size, a good numerical challenge exists. Connecting it to the committed
production transcript is a separate completeness/security obligation. -/
theorem selected_batch_good_challenge_exists [Fintype K] [DecidableEq K]
    (b : Batch K n m) (selection : Fin m → Fin n)
    (hquery : ∀ j, b.query j = b.table (selection j))
    (hcount : ∀ i, b.multiplicity i = (selectedCount selection i : K))
    (D : ℕ) (hdegree : ∀ j, (b.query j).natDegree ≤ D)
    (hnonzero : ∀ j, b.query j ≠ 0) (hsize : m * D < Fintype.card K) :
    ∃ x : K, Accepted Finset.univ b.denominator b.weight x := by
  classical
  let p : K[X] := ∏ j : Fin m, b.query j
  have hp : p ≠ 0 := Finset.prod_ne_zero_iff.mpr (fun j _ => hnonzero j)
  have hd : p.natDegree ≤ m * D := by
    calc
      p.natDegree ≤ ∑ j : Fin m, (b.query j).natDegree := natDegree_prod_le _ _
      _ ≤ ∑ _j : Fin m, D := Finset.sum_le_sum (fun j _ => hdegree j)
      _ = m * D := by simp
  by_contra h
  push_neg at h
  apply hp
  apply eq_zero_of_natDegree_lt_card_of_eval_eq_zero' p Finset.univ
  · intro x _
    obtain ⟨j, _, hj⟩ := selected_batch_failure_is_query_pole b selection hquery hcount x (h x)
    simp only [p, eval_prod]
    exact Finset.prod_eq_zero (Finset.mem_univ j) hj
  · simpa only [Finset.card_univ] using lt_of_le_of_lt hd hsize

/-- Honest quotient witness failure has only the explicit query-pole budget.
This statement concerns existence, not the behavior of production hints. -/
theorem selected_batch_failure_mass_callback_le [Fintype K] [DecidableEq K]
    (b : Batch K n m) (selection : Fin m → Fin n)
    (hquery : ∀ j, b.query j = b.table (selection j))
    (hcount : ∀ i, b.multiplicity i = (selectedCount selection i : K))
    (D : ℕ) (hdegree : ∀ j, (b.query j).natDegree ≤ D)
    (hnonzero : ∀ j, b.query j ≠ 0)
    (μ : Distribution K) (cap : ℚ) (hcap : 0 ≤ cap)
    (hpoint : ∀ x, μ.mass x ≤ cap) (r : ℕ) (hr : 0 < r) :
    eventMass (μ.pushforward (fun x => x ^ r))
      (fun x => ¬ Accepted Finset.univ b.denominator b.weight x) ≤
      ((m * D : ℕ) : ℚ) * ((r : ℚ) * cap) := by
  classical
  let p : K[X] := ∏ j : Fin m, b.query j
  have hp : p ≠ 0 := Finset.prod_ne_zero_iff.mpr (fun j _ => hnonzero j)
  have hd : p.natDegree ≤ m * D := by
    calc
      p.natDegree ≤ ∑ j : Fin m, (b.query j).natDegree := natDegree_prod_le _ _
      _ ≤ ∑ _j : Fin m, D := Finset.sum_le_sum (fun j _ => hdegree j)
      _ = m * D := by simp
  have he : ∀ x, ¬ Accepted Finset.univ b.denominator b.weight x → p.eval x = 0 := by
    intro x hx
    obtain ⟨j, _, hj⟩ := selected_batch_failure_is_query_pole b selection hquery hcount x hx
    simp only [p, eval_prod]
    exact Finset.prod_eq_zero (Finset.mem_univ j) hj
  have hb := eventMass_le_degree_mul_cap (μ.pushforward (fun x => x ^ r))
    ((r : ℚ) * cap) (mul_nonneg (Nat.cast_nonneg r) hcap)
    (fun y => power_pushforward_mass_le μ cap hcap hpoint r hr y) p hp
    (fun x => ¬ Accepted Finset.univ b.denominator b.weight x) he
  exact le_trans hb (mul_le_mul_of_nonneg_right (by exact_mod_cast hd)
    (mul_nonneg (Nat.cast_nonneg r) hcap))

end Completeness

end ZolanaVE.Lookup
