import VerifiableEncryption.Lookup.Algebra

/-!
A finite challenge experiment after fixing committed rows, queries and
multiplicities. A bound on each point mass is an explicit distribution
hypothesis. No assertion here treats a Fiat--Shamir hash or powers of a root
commitment as independent uniform field elements.

All probabilities are rational finite sums. `Distribution` records positivity
and normalization, so a point-mass bound cannot conceal an unnormalized
measure. Cryptographic extraction/binding and distribution claims are outside
the polynomial theorems.
-/

namespace ZolanaVE.Lookup

open Polynomial
open scoped BigOperators

variable {K : Type*} [Field K] [Fintype K] [DecidableEq K]

structure Distribution (K : Type*) [Fintype K] where
  mass : K → ℚ
  nonneg : ∀ x, 0 ≤ mass x
  normalized : ∑ x, mass x = 1

noncomputable def eventMass (μ : Distribution K) (e : K → Prop) : ℚ := by
  classical
  exact ∑ x ∈ Finset.univ.filter e, μ.mass x

namespace Distribution

/-- Ordinary image distribution. Its mass at `y` is the sum of all original
point masses in the fiber `f ⁻¹ {y}`. This records correlations neither as
fresh randomness nor as an independence assumption. -/
noncomputable def pushforward {A B : Type*} [Fintype A] [Fintype B]
    [DecidableEq B] (μ : Distribution A) (f : A → B) : Distribution B where
  mass := fun y => ∑ x ∈ Finset.univ.filter (fun x => f x = y), μ.mass x
  nonneg := fun _ => Finset.sum_nonneg (fun x _ => μ.nonneg x)
  normalized := (Finset.sum_fiberwise Finset.univ f μ.mass).trans μ.normalized

end Distribution

theorem pushforward_mass_eq_eventMass (μ : Distribution K) (f : K → K) (y : K) :
    (μ.pushforward f).mass y = eventMass μ (fun x => f x = y) := by
  classical
  unfold Distribution.pushforward eventMass
  apply Finset.sum_congr
  · ext x; simp
  · intro x hx; rfl

theorem pushforward_eventMass_eq (μ : Distribution K) (f : K → K) (event : K → Prop) :
    eventMass (μ.pushforward f) event = eventMass μ (fun x => event (f x)) := by
  classical
  simp only [eventMass, Distribution.pushforward]
  rw [Finset.sum_fiberwise_eq_sum_filter]
  simp

noncomputable def uniformDistribution : Distribution K where
  mass := fun _ => 1 / (Fintype.card K : ℚ)
  nonneg := fun _ => by positivity
  normalized := by
    simp [div_eq_mul_inv, Fintype.card_ne_zero]

theorem root_card_le (p : K[X]) (hp : p ≠ 0) :
    (Finset.univ.filter (fun x => p.eval x = 0)).card ≤ p.natDegree := by
  by_contra h
  apply hp
  exact eq_zero_of_natDegree_lt_card_of_eval_eq_zero' p _
    (fun x hx => (Finset.mem_filter.mp hx).2) (Nat.lt_of_not_ge h)

/-- Any event contained in the roots of a fixed nonzero polynomial has mass
at most `degree * cap`. In particular, uniform challenges have cap `1/|K|`.
Fixing the polynomial before sampling is essential. -/
theorem eventMass_le_degree_mul_cap (μ : Distribution K) (cap : ℚ)
    (hcap : 0 ≤ cap) (hpoint : ∀ x, μ.mass x ≤ cap)
    (p : K[X]) (hp : p ≠ 0) (e : K → Prop) [DecidablePred e]
    (he : ∀ x, e x → p.eval x = 0) :
    eventMass μ e ≤ (p.natDegree : ℚ) * cap := by
  classical
  have hcard : (Finset.univ.filter e).card ≤ p.natDegree := by
    apply le_trans (Finset.card_le_card ?_) (root_card_le p hp)
    intro x hx
    exact Finset.mem_filter.mpr ⟨Finset.mem_univ x, he x (Finset.mem_filter.mp hx).2⟩
  calc
    eventMass μ e ≤ ∑ _x ∈ Finset.univ.filter e, cap := by
      unfold eventMass
      refine le_trans (le_of_eq ?_)
        (Finset.sum_le_sum (s := Finset.univ.filter e) (fun x _ => hpoint x))
      apply Finset.sum_congr
      · ext x; simp
      · intro x hx; rfl
    _ = ((Finset.univ.filter e).card : ℚ) * cap := by simp
    _ ≤ (p.natDegree : ℚ) * cap :=
      mul_le_mul_of_nonneg_right (by exact_mod_cast hcard) hcap

theorem uniform_eventMass_le (p : K[X]) (hp : p ≠ 0)
    (e : K → Prop) [DecidablePred e] (he : ∀ x, e x → p.eval x = 0) :
    eventMass uniformDistribution e ≤ (p.natDegree : ℚ) / Fintype.card K := by
  simpa [div_eq_mul_inv] using eventMass_le_degree_mul_cap
    (uniformDistribution (K := K)) (1 / (Fintype.card K : ℚ))
    (by positivity) (fun _ => le_rfl) p hp e he

/-- If the root commitment has point-mass cap `cap`, callback power `r ≥ 1`
has point-mass cap `r * cap`. This is a pushforward bound, not a claim that
different callback powers are independent or uniformly distributed. -/
theorem power_pushforward_mass_le (μ : Distribution K) (cap : ℚ)
    (hcap : 0 ≤ cap) (hpoint : ∀ x, μ.mass x ≤ cap)
    (r : ℕ) (hr : 0 < r) (y : K) :
    (μ.pushforward (fun x => x ^ r)).mass y ≤ (r : ℚ) * cap := by
  rw [pushforward_mass_eq_eventMass]
  have hroots : ∀ x : K, x ^ r = y → ((X : K[X]) ^ r - C y).eval x = 0 := by
    intro x hx
    simp [hx]
  simpa only [natDegree_X_pow_sub_C] using eventMass_le_degree_mul_cap μ cap
    hcap hpoint ((X : K[X]) ^ r - C y) (X_pow_sub_C_ne_zero hr y)
    (fun x => x ^ r = y) hroots

theorem uniform_power_pushforward_mass_le (r : ℕ) (hr : 0 < r) (y : K) :
    ((uniformDistribution (K := K)).pushforward (fun x => x ^ r)).mass y ≤
      (r : ℚ) / Fintype.card K := by
  simpa [div_eq_mul_inv] using power_pushforward_mass_le
    (uniformDistribution (K := K)) (1 / (Fintype.card K : ℚ))
    (by positivity) (fun _ => le_rfl) r hr y

variable {I : Type*} [DecidableEq I]

/-- False acceptance for a fixed nonzero residual. Multiplicities `w` are
arbitrary committed field elements; honesty of a counting hint is unused. -/
theorem accepted_mass_le (s : Finset I) (d : I → K[X]) (w : I → K)
    (μ : Distribution K) (cap : ℚ) (hcap : 0 ≤ cap)
    (hpoint : ∀ x, μ.mass x ≤ cap) (D : ℕ)
    (hd : ∀ i ∈ s, (d i).natDegree ≤ D)
    (hn : residual s d w ≠ 0) :
    eventMass μ (Accepted s d w) ≤ (((s.card - 1) * D : ℕ) : ℚ) * cap := by
  classical
  apply le_trans (eventMass_le_degree_mul_cap μ cap hcap hpoint
    (residual s d w) hn (Accepted s d w) (fun x h => accepted_residual_zero s d w x h))
  exact mul_le_mul_of_nonneg_right
    (by exact_mod_cast residual_degree_le s d w D hd) hcap

/-- Pole probability is bounded separately, never conditioned away for free. -/
theorem pole_mass_le (s : Finset I) (d : I → K[X])
    (μ : Distribution K) (cap : ℚ) (hcap : 0 ≤ cap)
    (hpoint : ∀ x, μ.mass x ≤ cap) (D : ℕ)
    (hd : ∀ i ∈ s, (d i).natDegree ≤ D)
    (hn : ∀ i ∈ s, d i ≠ 0) :
    eventMass μ (Pole s d) ≤ ((s.card * D : ℕ) : ℚ) * cap := by
  classical
  have hpoly : (∏ i ∈ s, d i) ≠ 0 := Finset.prod_ne_zero_iff.mpr hn
  have hdeg : (∏ i ∈ s, d i).natDegree ≤ s.card * D := by
    calc
      (∏ i ∈ s, d i).natDegree ≤ ∑ i ∈ s, (d i).natDegree := natDegree_prod_le _ _
      _ ≤ ∑ _i ∈ s, D := Finset.sum_le_sum hd
      _ = s.card * D := by simp
  have hroots : ∀ x, Pole s d x → (∏ i ∈ s, d i).eval x = 0 := by
    intro x hx
    obtain ⟨i, hi, hz⟩ := hx
    simp only [eval_prod]
    exact Finset.prod_eq_zero hi hz
  exact le_trans (eventMass_le_degree_mul_cap μ cap hcap hpoint
    (∏ i ∈ s, d i) hpoly (Pole s d) hroots)
    (mul_le_mul_of_nonneg_right (by exact_mod_cast hdeg) hcap)

end ZolanaVE.Lookup
