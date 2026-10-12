import VerifiableEncryption.Lookup.Challenge
import VerifiableEncryption.Circuit.Prelude
import VerifiableEncryption.ParameterCertificates.BN254

/-!
Source-aligned models, not a proof that extracted opaque predicates enforce
these constraints. Gnark v0.16.4 and the custom VE arguments both commit
queries and multiplicities before deriving their callback challenge. Rows
are also committed when variable. Quotients are chosen after the challenge.

`Batch` separates that boundary in its data: a fixed batch gives denominator
polynomials and weights; `Accepted` then quantifies post-challenge quotients.
There is deliberately no theorem producing `LookupAssumptions` from a
single satisfying witness. Cryptographic binding/extraction, challenge
distribution and the missing opaque-predicate trace bridge remain external.
-/

namespace ZolanaVE.Lookup

open Polynomial
open scoped BigOperators

variable {K : Type*} [Field K]

/-- All entries and counts are fixed before the callback challenge. The
counting hint is untrusted: multiplicities are arbitrary field elements. -/
structure Batch (K : Type*) [Field K] (n m : ℕ) where
  table : Fin n → K[X]
  query : Fin m → K[X]
  multiplicity : Fin n → K

namespace Batch

variable {n m : ℕ}

noncomputable def denominator (b : Batch K n m) : Sum (Fin n) (Fin m) → K[X] :=
  Sum.elim b.table b.query

def weight (b : Batch K n m) : Sum (Fin n) (Fin m) → K :=
  Sum.elim b.multiplicity (fun _ => -1)

/-- For query inverses, a zero denominator is impossible: its numerator is
`-1`. Table denominators may vanish when their arbitrary multiplicity is zero.
This statement checks constraints, never the hint implementation. -/
theorem query_denominator_ne_zero (b : Batch K n m) (x : K)
    (h : Accepted Finset.univ b.denominator b.weight x) (j : Fin m) :
    (b.query j).eval x ≠ 0 := by
  obtain ⟨q, hq, _⟩ := h
  have he := hq (Sum.inr j) (Finset.mem_univ _)
  change q (Sum.inr j) * (b.query j).eval x = -1 at he
  intro hz
  rw [hz, mul_zero] at he
  exact neg_ne_zero.mpr one_ne_zero he.symm

end Batch

/-- Custom emfield/rangecheck.go denominator. Tags are widths, the main table
uses tag zero, and tag separation is twenty successive squarings. -/
noncomputable def rangeDenominator (tag : ℕ) (value : K) : K[X] :=
  X - C (tag : K) * X ^ (2 ^ 20) - C value

theorem rangeDenominator_eval (tag : ℕ) (value x : K) :
    (rangeDenominator tag value).eval x = x - (tag : K) * x ^ (2 ^ 20) - value := by
  simp [rangeDenominator]

/-- Custom emcurve/lookup.go denominator: twelve payload columns plus the
index, with successive radix-256 powers, all from one callback challenge.
This is not an independent random-linear-combination experiment. -/
noncomputable def rowDenominator (index : K) (row : Fin 12 → K) : K[X] :=
  X - C index - ∑ j : Fin 12, C (row j) * X ^ (256 ^ (j.val + 1))

theorem rowDenominator_eval (index : K) (row : Fin 12 → K) (x : K) :
    (rowDenominator index row).eval x =
      x - index - ∑ j : Fin 12, row j * x ^ (256 ^ (j.val + 1)) := by
  simp [rowDenominator, eval_finset_sum]

theorem rangeDenominator_degree_le (tag : ℕ) (value : K) :
    (rangeDenominator tag value).natDegree ≤ 2 ^ 20 := by
  unfold rangeDenominator
  apply le_trans (natDegree_sub_le _ _) (max_le ?_ ?_)
  · apply le_trans (natDegree_sub_le _ _) (max_le ?_ ?_)
    · norm_num
    · exact natDegree_C_mul_X_pow_le _ _
  · simp

theorem rangeDenominator_coeff_one (tag : ℕ) (value : K) :
    (rangeDenominator tag value).coeff 1 = 1 := by
  norm_num [rangeDenominator, coeff_sub, coeff_C_mul_X_pow, coeff_C]

theorem rangeDenominator_coeff_zero (tag : ℕ) (value : K) :
    (rangeDenominator tag value).coeff 0 = -value := by
  norm_num [rangeDenominator, coeff_sub, coeff_C_mul_X_pow, coeff_C]

theorem rangeDenominator_coeff_tag (tag : ℕ) (value : K) :
    (rangeDenominator tag value).coeff (2 ^ 20) = -(tag : K) := by
  norm_num [rangeDenominator, coeff_sub, coeff_C_mul_X_pow, coeff_C, coeff_X]

theorem rangeDenominator_ne_zero (tag : ℕ) (value : K) :
    rangeDenominator tag value ≠ 0 := by
  intro h
  have hc := congrArg (fun p : K[X] => p.coeff 1) h
  simp only [rangeDenominator_coeff_one, coeff_zero] at hc
  exact one_ne_zero hc

theorem rangeDenominator_eq_iff (tag₁ tag₂ : ℕ) (value₁ value₂ : K) :
    rangeDenominator tag₁ value₁ = rangeDenominator tag₂ value₂ ↔
      (tag₁ : K) = (tag₂ : K) ∧ value₁ = value₂ := by
  constructor
  · intro h
    have ht := congrArg (fun p : K[X] => p.coeff (2 ^ 20)) h
    have hv := congrArg (fun p : K[X] => p.coeff 0) h
    exact ⟨by simpa only [rangeDenominator_coeff_tag, neg_inj] using ht,
      by simpa only [rangeDenominator_coeff_zero, neg_inj] using hv⟩
  · rintro ⟨ht, hv⟩
    simp only [rangeDenominator, ht, hv]

theorem row_exponent_gt_one (j : Fin 12) : 1 < 256 ^ (j.val + 1) := by
  have h : (256 : ℕ) ^ 1 ≤ 256 ^ (j.val + 1) :=
    pow_le_pow_right' (by norm_num) (by omega)
  norm_num only [pow_one] at h
  omega

theorem row_exponent_le (j : Fin 12) : 256 ^ (j.val + 1) ≤ 256 ^ 12 :=
  pow_le_pow_right' (by norm_num) (by have := j.isLt; omega)

theorem row_exponent_injective :
    Function.Injective (fun j : Fin 12 => (256 : ℕ) ^ (j.val + 1)) := by
  intro i j h
  have he := (Nat.pow_right_injective (by norm_num : 2 ≤ (256 : ℕ))) h
  apply Fin.ext
  omega

theorem rowDenominator_degree_le (index : K) (row : Fin 12 → K) :
    (rowDenominator index row).natDegree ≤ 256 ^ 12 := by
  unfold rowDenominator
  apply le_trans (natDegree_sub_le _ _) (max_le ?_ ?_)
  · apply le_trans (natDegree_sub_le _ _) (max_le ?_ ?_)
    · norm_num
    · simp
  · apply natDegree_sum_le_of_forall_le
    intro j _
    exact le_trans (natDegree_C_mul_X_pow_le _ _) (row_exponent_le j)

theorem rowDenominator_coeff_zero (index : K) (row : Fin 12 → K) :
    (rowDenominator index row).coeff 0 = -index := by
  have hne : ∀ j : Fin 12, 0 ≠ 256 ^ (j.val + 1) :=
    fun j => ne_of_lt (lt_trans Nat.zero_lt_one (row_exponent_gt_one j))
  simp [rowDenominator, coeff_sub, finset_sum_coeff, coeff_C_mul_X_pow, hne]

theorem rowDenominator_coeff_one (index : K) (row : Fin 12 → K) :
    (rowDenominator index row).coeff 1 = 1 := by
  have hne : ∀ j : Fin 12, 1 ≠ 256 ^ (j.val + 1) :=
    fun j => ne_of_lt (row_exponent_gt_one j)
  simp [rowDenominator, coeff_sub, finset_sum_coeff, coeff_C_mul_X_pow, hne]

theorem rowDenominator_coeff_column (index : K) (row : Fin 12 → K) (i : Fin 12) :
    (rowDenominator index row).coeff (256 ^ (i.val + 1)) = -(row i) := by
  have hsum : (∑ j : Fin 12, C (row j) * X ^ (256 ^ (j.val + 1))).coeff
      (256 ^ (i.val + 1)) = row i := by
    rw [finset_sum_coeff, Finset.sum_eq_single i]
    · simp [coeff_C_mul_X_pow]
    · intro j _ hji
      have hne : 256 ^ (i.val + 1) ≠ 256 ^ (j.val + 1) := by
        intro he
        exact hji (row_exponent_injective he).symm
      simp [coeff_C_mul_X_pow, hne]
    · exact fun hi => (hi (Finset.mem_univ i)).elim
  have hne_one : 1 ≠ 256 ^ (i.val + 1) := ne_of_lt (row_exponent_gt_one i)
  have hne_zero : 256 ^ (i.val + 1) ≠ 0 :=
    ne_of_gt (lt_trans Nat.zero_lt_one (row_exponent_gt_one i))
  simp [rowDenominator, coeff_sub, hsum, coeff_X, coeff_C, hne_one, hne_zero]

theorem rowDenominator_ne_zero (index : K) (row : Fin 12 → K) :
    rowDenominator index row ≠ 0 := by
  intro h
  have hc := congrArg (fun p : K[X] => p.coeff 1) h
  simp only [rowDenominator_coeff_one, coeff_zero] at hc
  exact one_ne_zero hc

/-- Polynomial equality binds the index and every column. This does not say
that distinct rows cannot collide at a particular challenge evaluation. -/
theorem rowDenominator_eq_iff (index₁ index₂ : K) (row₁ row₂ : Fin 12 → K) :
    rowDenominator index₁ row₁ = rowDenominator index₂ row₂ ↔
      index₁ = index₂ ∧ row₁ = row₂ := by
  constructor
  · intro h
    have hi := congrArg (fun p : K[X] => p.coeff 0) h
    refine ⟨by simpa only [rowDenominator_coeff_zero, neg_inj] using hi, ?_⟩
    funext j
    have hj := congrArg (fun p : K[X] => p.coeff (256 ^ (j.val + 1))) h
    simpa only [rowDenominator_coeff_column, neg_inj] using hj
  · rintro ⟨rfl, rfl⟩
    rfl

/-- Gnark's two-column AES table uses `(index,value)` and coefficient
`MiMC(2,challenge)`. This model takes the concrete coefficient function as an
argument; it does not replace it with an independent random variable. -/
def aesDenominator (coefficient : K → K) (index value challenge : K) : K :=
  challenge - (index + coefficient challenge * value)

/-- Callback `r` is numbered from one in multicommit/nativecommit.go. The
callback challenge is the corresponding power of the common root commitment.
Even an ideal uniform root does not give uniform independent callback values.
-/
def callbackChallenge (r : ℕ) (root : K) : K := root ^ r

section CallbackBounds

variable [Fintype K] [DecidableEq K] {I : Type*} [DecidableEq I]

/-- Concrete tagged-range pole budget for a callback power of a root with an
explicit point-mass cap. Tags and values are fixed before the root is sampled.
-/
theorem range_pole_mass_callback_le (s : Finset I) (tag : I → ℕ) (value : I → K)
    (μ : Distribution K) (cap : ℚ) (hcap : 0 ≤ cap)
    (hpoint : ∀ x, μ.mass x ≤ cap) (r : ℕ) (hr : 0 < r) :
    eventMass (μ.pushforward (fun x => x ^ r))
      (Pole s (fun i => rangeDenominator (tag i) (value i))) ≤
      ((s.card * 2 ^ 20 : ℕ) : ℚ) * ((r : ℚ) * cap) := by
  exact pole_mass_le s (fun i => rangeDenominator (tag i) (value i))
    (μ.pushforward (fun x => x ^ r)) ((r : ℚ) * cap)
    (mul_nonneg (Nat.cast_nonneg r) hcap)
    (fun y => power_pushforward_mass_le μ cap hcap hpoint r hr y) (2 ^ 20)
    (fun i _ => rangeDenominator_degree_le (tag i) (value i))
    (fun i _ => rangeDenominator_ne_zero (tag i) (value i))

theorem row_pole_mass_callback_le (s : Finset I) (index : I → K)
    (row : I → Fin 12 → K) (μ : Distribution K) (cap : ℚ) (hcap : 0 ≤ cap)
    (hpoint : ∀ x, μ.mass x ≤ cap) (r : ℕ) (hr : 0 < r) :
    eventMass (μ.pushforward (fun x => x ^ r))
      (Pole s (fun i => rowDenominator (index i) (row i))) ≤
      ((s.card * 256 ^ 12 : ℕ) : ℚ) * ((r : ℚ) * cap) := by
  exact pole_mass_le s (fun i => rowDenominator (index i) (row i))
    (μ.pushforward (fun x => x ^ r)) ((r : ℚ) * cap)
    (mul_nonneg (Nat.cast_nonneg r) hcap)
    (fun y => power_pushforward_mass_le μ cap hcap hpoint r hr y) (256 ^ 12)
    (fun i _ => rowDenominator_degree_le (index i) (row i))
    (fun i _ => rowDenominator_ne_zero (index i) (row i))

theorem uniform_range_pole_mass_callback_le (s : Finset I) (tag : I → ℕ)
    (value : I → K) (r : ℕ) (hr : 0 < r) :
    eventMass ((uniformDistribution (K := K)).pushforward (fun x => x ^ r))
      (Pole s (fun i => rangeDenominator (tag i) (value i))) ≤
      (((s.card * 2 ^ 20 : ℕ) : ℚ) * (r : ℚ)) / Fintype.card K := by
  simpa only [div_eq_mul_inv, one_mul, mul_assoc] using
    range_pole_mass_callback_le s tag value (uniformDistribution (K := K))
      (1 / (Fintype.card K : ℚ)) (by positivity) (fun _ => le_rfl) r hr

theorem uniform_row_pole_mass_callback_le (s : Finset I) (index : I → K)
    (row : I → Fin 12 → K) (r : ℕ) (hr : 0 < r) :
    eventMass ((uniformDistribution (K := K)).pushforward (fun x => x ^ r))
      (Pole s (fun i => rowDenominator (index i) (row i))) ≤
      (((s.card * 256 ^ 12 : ℕ) : ℚ) * (r : ℚ)) / Fintype.card K := by
  simpa only [div_eq_mul_inv, one_mul, mul_assoc] using
    row_pole_mass_callback_le s index row (uniformDistribution (K := K))
      (1 / (Fintype.card K : ℚ)) (by positivity) (fun _ => le_rfl) r hr

theorem range_evaluation_collision_mass_callback_le (tag₁ tag₂ : ℕ)
    (value₁ value₂ : K) (hne : (tag₁ : K) ≠ (tag₂ : K) ∨ value₁ ≠ value₂)
    (μ : Distribution K) (cap : ℚ) (hcap : 0 ≤ cap)
    (hpoint : ∀ x, μ.mass x ≤ cap) (r : ℕ) (hr : 0 < r) :
    eventMass (μ.pushforward (fun x => x ^ r))
      (fun x => (rangeDenominator tag₁ value₁).eval x = (rangeDenominator tag₂ value₂).eval x) ≤
      (2 ^ 20 : ℚ) * ((r : ℚ) * cap) := by
  have hpoly : rangeDenominator tag₁ value₁ - rangeDenominator tag₂ value₂ ≠ 0 := by
    apply sub_ne_zero.mpr
    intro h
    obtain ⟨ht, hv⟩ := (rangeDenominator_eq_iff tag₁ tag₂ value₁ value₂).mp h
    rcases hne with hn | hn
    · exact hn ht
    · exact hn hv
  have hdeg : (rangeDenominator tag₁ value₁ - rangeDenominator tag₂ value₂).natDegree ≤
      2 ^ 20 :=
    le_trans (natDegree_sub_le _ _) (max_le
      (rangeDenominator_degree_le tag₁ value₁) (rangeDenominator_degree_le tag₂ value₂))
  have hb := eventMass_le_degree_mul_cap (μ.pushforward (fun x => x ^ r))
    ((r : ℚ) * cap) (mul_nonneg (Nat.cast_nonneg r) hcap)
    (fun y => power_pushforward_mass_le μ cap hcap hpoint r hr y)
    (rangeDenominator tag₁ value₁ - rangeDenominator tag₂ value₂) hpoly
    (fun x => (rangeDenominator tag₁ value₁).eval x = (rangeDenominator tag₂ value₂).eval x)
    (fun x hx => by simp only [eval_sub, hx, sub_self])
  apply le_trans hb
  have hdegree : ((rangeDenominator tag₁ value₁ - rangeDenominator tag₂ value₂).natDegree : ℚ) ≤
      (2 ^ 20 : ℚ) := by exact_mod_cast hdeg
  exact mul_le_mul_of_nonneg_right hdegree (mul_nonneg (Nat.cast_nonneg r) hcap)

/-- Index or payload differences can disappear at an individual challenge,
but the equality event is bounded by the degree of a *derived nonzero*
difference polynomial. This is distinct from log-derivative residual soundness.
-/
theorem row_evaluation_collision_mass_callback_le (index₁ index₂ : K)
    (row₁ row₂ : Fin 12 → K) (hne : index₁ ≠ index₂ ∨ row₁ ≠ row₂)
    (μ : Distribution K) (cap : ℚ) (hcap : 0 ≤ cap)
    (hpoint : ∀ x, μ.mass x ≤ cap) (r : ℕ) (hr : 0 < r) :
    eventMass (μ.pushforward (fun x => x ^ r))
      (fun x => (rowDenominator index₁ row₁).eval x = (rowDenominator index₂ row₂).eval x) ≤
      (256 ^ 12 : ℚ) * ((r : ℚ) * cap) := by
  have hpoly : rowDenominator index₁ row₁ - rowDenominator index₂ row₂ ≠ 0 := by
    apply sub_ne_zero.mpr
    intro h
    obtain ⟨hi, hrow⟩ := (rowDenominator_eq_iff index₁ index₂ row₁ row₂).mp h
    rcases hne with hn | hn
    · exact hn hi
    · exact hn hrow
  have hdeg : (rowDenominator index₁ row₁ - rowDenominator index₂ row₂).natDegree ≤
      256 ^ 12 :=
    le_trans (natDegree_sub_le _ _) (max_le
      (rowDenominator_degree_le index₁ row₁) (rowDenominator_degree_le index₂ row₂))
  have hb := eventMass_le_degree_mul_cap (μ.pushforward (fun x => x ^ r))
    ((r : ℚ) * cap) (mul_nonneg (Nat.cast_nonneg r) hcap)
    (fun y => power_pushforward_mass_le μ cap hcap hpoint r hr y)
    (rowDenominator index₁ row₁ - rowDenominator index₂ row₂) hpoly
    (fun x => (rowDenominator index₁ row₁).eval x = (rowDenominator index₂ row₂).eval x)
    (fun x hx => by simp only [eval_sub, hx, sub_self])
  apply le_trans hb
  have hdegree : ((rowDenominator index₁ row₁ - rowDenominator index₂ row₂).natDegree : ℚ) ≤
      (256 ^ 12 : ℚ) := by exact_mod_cast hdeg
  exact mul_le_mul_of_nonneg_right hdegree (mul_nonneg (Nat.cast_nonneg r) hcap)

end CallbackBounds

end ZolanaVE.Lookup
