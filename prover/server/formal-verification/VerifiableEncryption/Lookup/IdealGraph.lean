import VerifiableEncryption.Lookup.ExecutionSemantics

/-!
Finite algebra for a frozen nonzero bivariate polynomial evaluated on an ideal
lazy-sampled permutation graph. Cached inputs and identically-zero slices get
their own budgets. Fresh permutation outputs are uniform only over unused
outputs, not independent uniform field elements.

This does not prove that the actual public fixed-key MiMC permutation admits
a small replacement advantage. Any such premise must concern frozen graph
tests in the actual adversarial/resource model, with all local public MiMC
computations accounted for; it is not ordinary secret-key PRF security.
-/

namespace ZolanaVE.Lookup

open Polynomial
open scoped BigOperators

variable {K : Type*} [Field K] [Fintype K] [DecidableEq K]

noncomputable def graphSlice (p : Polynomial K[X]) (x : K) : K[X] :=
  p.map (Polynomial.evalRingHom x)

theorem zero_slice_leading_zero (p : Polynomial K[X]) (x : K)
    (h : graphSlice p x = 0) : (p.coeff p.natDegree).eval x = 0 := by
  have hc := congrArg (fun q : K[X] => q.coeff p.natDegree) h
  simpa only [graphSlice, Polynomial.coeff_map, Polynomial.coeff_zero] using hc

theorem graphSlice_degree_le (p : Polynomial K[X]) (x : K) :
    (graphSlice p x).natDegree ≤ p.natDegree := natDegree_map_le

theorem eventMass_le_one (μ : Distribution K) (event : K → Prop) : eventMass μ event ≤ 1 := by
  classical
  calc
    eventMass μ event ≤ ∑ x, μ.mass x := Finset.sum_le_sum_of_subset_of_nonneg
      (Finset.filter_subset _ _) (fun x _ _ => μ.nonneg x)
    _ = 1 := μ.normalized

theorem eventMass_nonneg (μ : Distribution K) (event : K → Prop) : 0 ≤ eventMass μ event := by
  classical
  exact Finset.sum_nonneg (fun x _ => μ.nonneg x)

theorem shift_pushforward_mass (μ : Distribution K) (shift y : K) :
    (μ.pushforward (fun x => x + shift)).mass y = μ.mass (y - shift) := by
  rw [pushforward_mass_eq_eventMass]
  have he : (fun x : K => x + shift = y) = (fun x => x = y - shift) := by
    funext x
    exact propext eq_sub_iff_add_eq.symm
  rw [he]
  classical
  calc
    eventMass μ (fun x => x = y - shift) = ∑ x ∈ ({y - shift} : Finset K), μ.mass x := by
      unfold eventMass
      apply Finset.sum_congr
      · ext x; simp
      · intro x hx; rfl
    _ = μ.mass (y - shift) := by simp

theorem graph_fresh_slice_mass_le (p : Polynomial K[X]) (D : ℕ) (x shift : K)
    (hp : graphSlice p x ≠ 0) (hdegree : p.natDegree ≤ D)
    (μ : Distribution K) (cap : ℚ) (hcap : 0 ≤ cap) (hpoint : ∀ y, μ.mass y ≤ cap) :
    eventMass μ (fun y => (graphSlice p x).eval (y + shift) = 0) ≤ (D : ℚ) * cap := by
  have hb := eventMass_le_degree_mul_cap (μ.pushforward (fun y => y + shift)) cap hcap
    (fun y => by rw [shift_pushforward_mass]; exact hpoint _)
    (graphSlice p x) hp (fun y => (graphSlice p x).eval y = 0) (fun _ h => h)
  rw [pushforward_eventMass_eq] at hb
  exact le_trans hb (mul_le_mul_of_nonneg_right
    (by exact_mod_cast (graphSlice_degree_le p x).trans hdegree) hcap)

theorem cached_input_mass_le (cache : Finset K) (q : ℕ) (hcache : cache.card ≤ q)
    (μ : Distribution K) (cap : ℚ) (hcap : 0 ≤ cap) (hpoint : ∀ x, μ.mass x ≤ cap) :
    eventMass μ (fun x => x ∈ cache) ≤ (q : ℚ) * cap := by
  classical
  have hc : (Finset.univ.filter (fun x => x ∈ cache)).card ≤ q := by
    exact le_trans (Finset.card_le_card (fun x hx => (Finset.mem_filter.mp hx).2)) hcache
  calc
    eventMass μ (fun x => x ∈ cache) ≤ ∑ _x ∈ Finset.univ.filter (fun x => x ∈ cache), cap := by
      unfold eventMass
      refine le_trans (le_of_eq ?_)
        (Finset.sum_le_sum (s := Finset.univ.filter (fun x => x ∈ cache)) (fun x _ => hpoint x))
      apply Finset.sum_congr
      · ext x; simp
      · intro x hx; rfl
    _ = ((Finset.univ.filter (fun x => x ∈ cache)).card : ℚ) * cap := by simp
    _ ≤ (q : ℚ) * cap := mul_le_mul_of_nonneg_right (by exact_mod_cast hc) hcap

theorem zero_slice_mass_le (p : Polynomial K[X]) (hp : p ≠ 0) (D : ℕ)
    (hcoeff : ∀ i, (p.coeff i).natDegree ≤ D)
    (μ : Distribution K) (cap : ℚ) (hcap : 0 ≤ cap) (hpoint : ∀ x, μ.mass x ≤ cap) :
    eventMass μ (fun x => graphSlice p x = 0) ≤ (D : ℚ) * cap := by
  have hlead : p.coeff p.natDegree ≠ 0 := by
    rw [coeff_natDegree]
    exact leadingCoeff_ne_zero.mpr hp
  have hb := eventMass_le_degree_mul_cap μ cap hcap hpoint (p.coeff p.natDegree) hlead
    (fun x => graphSlice p x = 0) (fun x hx => zero_slice_leading_zero p x hx)
  exact le_trans hb (mul_le_mul_of_nonneg_right (by exact_mod_cast hcoeff p.natDegree) hcap)

noncomputable def unitDistribution : Distribution Unit where
  mass := fun _ => 1
  nonneg := fun _ => by norm_num
  normalized := by simp

/-- Ideal conditional permutation response: after at most `q` distinct cached
inputs, each fresh response has point mass at most `1/(|K|-q)`. The actual
uniform-unused-output construction below supplies this premise.
-/
theorem ideal_graph_mass_le (p : Polynomial K[X]) (hp : p ≠ 0) (D : ℕ)
    (hdegree : p.natDegree ≤ D) (hcoeff : ∀ i, (p.coeff i).natDegree ≤ D)
    (cache : Finset K) (q : ℕ) (hcache : cache.card ≤ q) (hq : q < Fintype.card K)
    (root : Distribution K) (δ : ℚ) (hδ : 0 ≤ δ) (hroot : ∀ x, root.mass x ≤ δ)
    (response : K → Distribution K)
    (hfresh : ∀ x, x ∉ cache → ∀ y,
      (response x).mass y ≤ 1 / ((Fintype.card K - q : ℕ) : ℚ)) (offset : K) :
    finiteProbability (stagedLaw root response (fun _ _ => unitDistribution))
      (fun ω => (graphSlice p ω.1).eval (ω.2.1 + (ω.1 + offset)) = 0) ≤
      ((q + D : ℕ) : ℚ) * δ + (D : ℚ) / ((Fintype.card K - q : ℕ) : ℚ) := by
  classical
  let η : ℚ := 1 / ((Fintype.card K - q : ℕ) : ℚ)
  have hden : 0 < ((Fintype.card K - q : ℕ) : ℚ) := by
    exact_mod_cast Nat.sub_pos_of_lt hq
  have hη : 0 ≤ η := le_of_lt (div_pos (by norm_num) hden)
  let event := fun x y => (graphSlice p x).eval (y + (x + offset)) = 0
  have hconditional : ∀ x,
      root.mass x * eventMass (response x) (event x) ≤
        (if x ∈ cache then root.mass x else 0) +
        (if graphSlice p x = 0 then root.mass x else 0) + root.mass x * ((D : ℚ) * η) := by
    intro x
    have hm := root.nonneg x
    have hterm : 0 ≤ root.mass x * ((D : ℚ) * η) := by positivity
    have hunit := mul_le_mul_of_nonneg_left (eventMass_le_one (response x) (event x)) hm
    by_cases hc : x ∈ cache
    · by_cases hz : graphSlice p x = 0
      · simp only [if_pos hc, if_pos hz]
        linarith
      · simp only [if_pos hc, if_neg hz, add_zero]
        linarith
    · by_cases hz : graphSlice p x = 0
      · simp only [if_neg hc, if_pos hz, zero_add]
        linarith
      · simp only [if_neg hc, if_neg hz, zero_add]
        exact mul_le_mul_of_nonneg_left
          (graph_fresh_slice_mass_le p D x (x + offset) hz hdegree (response x) η hη (hfresh x hc)) hm
  have htotal : finiteProbability (stagedLaw root response (fun _ _ => unitDistribution))
      (fun ω => event ω.1 ω.2.1) ≤
      eventMass root (fun x => x ∈ cache) + eventMass root (fun x => graphSlice p x = 0) +
        (D : ℚ) * η := by
    rw [staged_event_probability_eq]
    calc
      (∑ x, root.mass x * finiteProbability (response x) (event x)) ≤
          ∑ x, ((if x ∈ cache then root.mass x else 0) +
            (if graphSlice p x = 0 then root.mass x else 0) + root.mass x * ((D : ℚ) * η)) :=
        Finset.sum_le_sum (fun x _ => hconditional x)
      _ = _ := by
        simp only [eventMass, Finset.sum_filter, Finset.sum_add_distrib,
          ← Finset.sum_mul, root.normalized, one_mul]
        apply congrArg₂ (fun a b : ℚ => a + b + (D : ℚ) * η)
        · apply Finset.sum_congr rfl
          intro x hx
          split_ifs <;> rfl
        · apply Finset.sum_congr rfl
          intro x hx
          split_ifs <;> rfl
  have hcached := cached_input_mass_le cache q hcache root δ hδ hroot
  have hexception := zero_slice_mass_le p hp D hcoeff root δ hδ hroot
  have harith : ((q + D : ℕ) : ℚ) * δ + (D : ℚ) / ((Fintype.card K - q : ℕ) : ℚ) =
      (q : ℚ) * δ + (D : ℚ) * δ + (D : ℚ) * η := by
    simp only [η, Nat.cast_add, div_eq_mul_inv, one_mul]
    ring
  rw [harith]
  exact le_trans htotal (by linarith)

noncomputable def pointDistribution (point : K) : Distribution K where
  mass := fun x => if x = point then 1 else 0
  nonneg := fun x => by dsimp only; split_ifs <;> norm_num
  normalized := by simp

noncomputable def uniformOn (s : Finset K) (hs : s.Nonempty) : Distribution K where
  mass := fun x => if x ∈ s then 1 / (s.card : ℚ) else 0
  nonneg := fun x => by dsimp only; split_ifs <;> positivity
  normalized := by
    rw [← Finset.sum_filter]
    have he : Finset.univ.filter (fun x : K => x ∈ s) = s := by ext x; simp
    rw [he]
    have hc : s.card ≠ 0 := Nat.ne_of_gt (Finset.card_pos.mpr hs)
    simp [hc]

theorem uniformOn_point_le (s : Finset K) (hs : s.Nonempty) (x : K) :
    (uniformOn s hs).mass x ≤ 1 / (s.card : ℚ) := by
  by_cases h : x ∈ s
  · simp [uniformOn, h]
  · simp only [uniformOn, if_neg h]
    positivity

/-- A genuine cached partial permutation: distinct queried inputs have
distinct returned outputs. The response law at a fresh point samples uniformly
from unused outputs, exactly the lazy-sampling ideal-permutation rule.
-/
structure PermutationPrefix (K : Type*) [Fintype K] [DecidableEq K] where
  cache : Finset K
  output : K → K
  injective : Set.InjOn output (↑cache : Set K)
  not_full : cache.card < Fintype.card K

def PermutationPrefix.unused (permPrefix : PermutationPrefix K) : Finset K :=
  Finset.univ \ permPrefix.cache.image permPrefix.output

theorem PermutationPrefix.unused_card (permPrefix : PermutationPrefix K) :
    permPrefix.unused.card = Fintype.card K - permPrefix.cache.card := by
  rw [PermutationPrefix.unused, Finset.card_sdiff (Finset.subset_univ _),
    Finset.card_image_of_injOn permPrefix.injective, Finset.card_univ]

theorem PermutationPrefix.unused_nonempty (permPrefix : PermutationPrefix K) : permPrefix.unused.Nonempty := by
  apply Finset.card_pos.mp
  rw [permPrefix.unused_card]
  exact Nat.sub_pos_of_lt permPrefix.not_full

noncomputable def PermutationPrefix.response (permPrefix : PermutationPrefix K) (x : K) : Distribution K :=
  if x ∈ permPrefix.cache then pointDistribution (permPrefix.output x) else
    uniformOn permPrefix.unused permPrefix.unused_nonempty

theorem PermutationPrefix.fresh_point_cap (permPrefix : PermutationPrefix K)
    (q : ℕ) (hq : q < Fintype.card K) (hcache : permPrefix.cache.card ≤ q)
    (x : K) (hx : x ∉ permPrefix.cache) (y : K) :
    (permPrefix.response x).mass y ≤ 1 / ((Fintype.card K - q : ℕ) : ℚ) := by
  rw [PermutationPrefix.response, if_neg hx]
  apply le_trans (uniformOn_point_le _ _ y)
  apply one_div_le_one_div_of_le
  · exact_mod_cast Nat.sub_pos_of_lt hq
  · rw [permPrefix.unused_card]
    exact_mod_cast Nat.sub_le_sub_left hcache (Fintype.card K)

theorem ideal_permutation_graph_mass_le (permPrefix : PermutationPrefix K)
    (p : Polynomial K[X]) (hp : p ≠ 0) (D : ℕ)
    (hdegree : p.natDegree ≤ D) (hcoeff : ∀ i, (p.coeff i).natDegree ≤ D)
    (q : ℕ) (hcache : permPrefix.cache.card ≤ q) (hq : q < Fintype.card K)
    (root : Distribution K) (δ : ℚ) (hδ : 0 ≤ δ) (hroot : ∀ x, root.mass x ≤ δ) (offset : K) :
    finiteProbability (stagedLaw root permPrefix.response (fun _ _ => unitDistribution))
      (fun ω => (graphSlice p ω.1).eval (ω.2.1 + (ω.1 + offset)) = 0) ≤
      ((q + D : ℕ) : ℚ) * δ + (D : ℚ) / ((Fintype.card K - q : ℕ) : ℚ) :=
  ideal_graph_mass_le p hp D hdegree hcoeff permPrefix.cache q hcache hq root δ hδ hroot
    permPrefix.response (fun x hx y => permPrefix.fresh_point_cap q hq hcache x hx y) offset

noncomputable def oneVariableEquiv : MvPolynomial (Fin 1) K ≃+* K[X] :=
  (MvPolynomial.finSuccEquiv K 0).toRingEquiv.trans
    (Polynomial.mapEquiv (MvPolynomial.isEmptyRingEquiv (R := K) (σ := Fin 0)))

theorem oneVariableEquiv_degree (p : MvPolynomial (Fin 1) K) :
    (oneVariableEquiv p).natDegree = p.degreeOf 0 := by
  change ((MvPolynomial.finSuccEquiv K 0 p).map
    (MvPolynomial.isEmptyRingEquiv (R := K) (σ := Fin 0)).toRingHom).natDegree = _
  rw [natDegree_map_eq_of_injective
    (f := (MvPolynomial.isEmptyRingEquiv (R := K) (σ := Fin 0)).toRingHom)
    (MvPolynomial.isEmptyRingEquiv (R := K) (σ := Fin 0)).injective,
    MvPolynomial.natDegree_finSuccEquiv]

@[simp] theorem oneVariableEquiv_C (value : K) :
    oneVariableEquiv (MvPolynomial.C value) = Polynomial.C value := by
  simp [oneVariableEquiv, MvPolynomial.finSuccEquiv_apply,
    MvPolynomial.isEmptyRingEquiv, MvPolynomial.isEmptyAlgEquiv]

@[simp] theorem oneVariableEquiv_X :
    oneVariableEquiv (MvPolynomial.X (0 : Fin 1) : MvPolynomial (Fin 1) K) =
      (Polynomial.X : K[X]) := by
  simp [oneVariableEquiv, MvPolynomial.finSuccEquiv_X_zero]

/-- Outer variable is the permutation response/coefficient coordinate; inner
variable is the root. This ring equivalence preserves nonzeroness exactly.
-/
noncomputable def bivariateView : MvPolynomial (Fin 2) K ≃+* Polynomial K[X] :=
  (MvPolynomial.renameEquiv K (Equiv.swap (0 : Fin 2) 1)).toRingEquiv.trans
    ((MvPolynomial.finSuccEquiv K 1).toRingEquiv.trans (Polynomial.mapEquiv oneVariableEquiv))

theorem bivariateView_degree_le (p : MvPolynomial (Fin 2) K) :
    (bivariateView p).natDegree ≤ p.totalDegree := by
  change ((MvPolynomial.finSuccEquiv K 1 (MvPolynomial.rename (Equiv.swap (0 : Fin 2) 1) p)).map
    oneVariableEquiv.toRingHom).natDegree ≤ _
  rw [natDegree_map_eq_of_injective oneVariableEquiv.injective, MvPolynomial.natDegree_finSuccEquiv]
  exact (MvPolynomial.degreeOf_le_totalDegree _ _).trans (MvPolynomial.totalDegree_rename_le _ _)

theorem bivariateView_coefficient_degree_le (p : MvPolynomial (Fin 2) K) (i : ℕ) :
    ((bivariateView p).coeff i).natDegree ≤ p.totalDegree := by
  change (((MvPolynomial.finSuccEquiv K 1 (MvPolynomial.rename (Equiv.swap (0 : Fin 2) 1) p)).map
    oneVariableEquiv.toRingHom).coeff i).natDegree ≤ _
  rw [coeff_map]
  change (oneVariableEquiv ((MvPolynomial.finSuccEquiv K 1
    (MvPolynomial.rename (Equiv.swap (0 : Fin 2) 1) p)).coeff i)).natDegree ≤ _
  rw [oneVariableEquiv_degree]
  exact (MvPolynomial.degreeOf_coeff_finSuccEquiv _ (0 : Fin 1) i).trans
    ((MvPolynomial.degreeOf_le_totalDegree _ _).trans (MvPolynomial.totalDegree_rename_le _ _))

@[simp] theorem bivariateView_C (value : K) :
    bivariateView (MvPolynomial.C value) = Polynomial.C (Polynomial.C value) := by
  simp [bivariateView, MvPolynomial.renameEquiv_apply, MvPolynomial.finSuccEquiv_apply]

@[simp] theorem bivariateView_X_zero : bivariateView (MvPolynomial.X (0 : Fin 2)) =
    Polynomial.C (Polynomial.X : K[X]) := by
  have hs : Fin.cases (Polynomial.X : Polynomial (MvPolynomial (Fin 1) K))
      (fun k => Polynomial.C (MvPolynomial.X k)) (1 : Fin 2) =
        Polynomial.C (MvPolynomial.X (0 : Fin 1)) := rfl
  simp [bivariateView, MvPolynomial.renameEquiv_apply, MvPolynomial.finSuccEquiv_apply, hs]

@[simp] theorem bivariateView_X_one : bivariateView (MvPolynomial.X (1 : Fin 2)) =
    (Polynomial.X : Polynomial K[X]) := by
  simp [bivariateView, MvPolynomial.renameEquiv_apply, MvPolynomial.finSuccEquiv_apply]

theorem bivariateView_eval (p : MvPolynomial (Fin 2) K) (x y : K) :
    (graphSlice (bivariateView p) x).eval y =
      MvPolynomial.eval (Fin.cases x (fun _ : Fin 1 => y)) p := by
  have hh : (Polynomial.evalRingHom y).comp
      ((Polynomial.mapRingHom (Polynomial.evalRingHom x)).comp bivariateView.toRingHom) =
      MvPolynomial.eval (Fin.cases x (fun _ : Fin 1 => y)) := by
    apply MvPolynomial.ringHom_ext
    · intro value
      simp
    · intro i
      have hy : Fin.cases x (fun _ : Fin 1 => y) (1 : Fin 2) = y := rfl
      fin_cases i <;> simp [hy]
  exact RingHom.congr_fun hh p

theorem ideal_multivariate_permutation_graph_mass_le (permPrefix : PermutationPrefix K)
    (p : MvPolynomial (Fin 2) K) (hp : p ≠ 0) (D : ℕ) (hdegree : p.totalDegree ≤ D)
    (q : ℕ) (hcache : permPrefix.cache.card ≤ q) (hq : q < Fintype.card K)
    (root : Distribution K) (δ : ℚ) (hδ : 0 ≤ δ) (hroot : ∀ x, root.mass x ≤ δ) (offset : K) :
    finiteProbability (stagedLaw root permPrefix.response (fun _ _ => unitDistribution))
      (fun ω => MvPolynomial.eval (Fin.cases ω.1 (fun _ : Fin 1 => ω.2.1 + (ω.1 + offset))) p = 0) ≤
      ((q + D : ℕ) : ℚ) * δ + (D : ℚ) / ((Fintype.card K - q : ℕ) : ℚ) := by
  have hn : bivariateView p ≠ 0 := by
    intro h
    apply hp
    apply bivariateView.injective
    rw [h, map_zero]
  have hb := ideal_permutation_graph_mass_le permPrefix (bivariateView p) hn D
    ((bivariateView_degree_le p).trans hdegree)
    (fun i => (bivariateView_coefficient_degree_le p i).trans hdegree)
    q hcache hq root δ hδ hroot offset
  simpa only [bivariateView_eval] using hb

section NativeMiMC

variable [Fact (Nat.Prime Order)] {n m : ℕ}

/-- Explicit, unproved replacement advantage for this frozen graph test in
the actual public-MiMC adversarial model. This compares the same low-degree
graph-zero observable, not arbitrary distinguishers of public code and not
an independent-uniform pair. A caller must justify the advantage for its
full permPrefix queries, local computations and commitment-grinding strategy.
-/
def FrozenMiMCGraphReplacementBound (keccak : MiMC.Hash256) (p : MvPolynomial (Fin 2) F)
    (root : Distribution F) (permPrefix : PermutationPrefix F) (εreplace : ℚ) : Prop :=
  let offset := 2 * MiMC.compress (MiMC.constants keccak) 0 2
  eventMass root (fun x => (aesGraph keccak p).eval x = 0) ≤
    finiteProbability (stagedLaw root permPrefix.response (fun _ _ => unitDistribution))
      (fun ω => MvPolynomial.eval
        (Fin.cases ω.1 (fun _ : Fin 1 => ω.2.1 + (ω.1 + offset))) p = 0) + εreplace

theorem actual_mimc_graph_mass_le_of_replacement (keccak : MiMC.Hash256)
    (p : MvPolynomial (Fin 2) F) (hp : p ≠ 0) (D : ℕ) (hdegree : p.totalDegree ≤ D)
    (root : Distribution F) (δ : ℚ) (hδ : 0 ≤ δ) (hroot : ∀ x, root.mass x ≤ δ)
    (permPrefix : PermutationPrefix F) (q : ℕ) (hcache : permPrefix.cache.card ≤ q)
    (hq : q < Fintype.card F) (εreplace : ℚ)
    (hreplace : FrozenMiMCGraphReplacementBound keccak p root permPrefix εreplace) :
    eventMass root (fun x => (aesGraph keccak p).eval x = 0) ≤
      ((q + D : ℕ) : ℚ) * δ + (D : ℚ) / ((Fintype.card F - q : ℕ) : ℚ) + εreplace := by
  have hideal := ideal_multivariate_permutation_graph_mass_le permPrefix p hp D hdegree
    q hcache hq root δ hδ hroot (2 * MiMC.compress (MiMC.constants keccak) 0 2)
  exact le_trans hreplace (add_le_add_right hideal εreplace)

/-- The actual affine public-permutation graph agrees with the coefficient
used by source gates. Bijectivity is proved in MiMC.lean; ideal replacement
security remains the explicitly separate premise above.
-/
theorem actual_mimc_graph_coordinate (keccak : MiMC.Hash256) (p : MvPolynomial (Fin 2) F) (x : F) :
    (aesGraph keccak p).eval x =
      MvPolynomial.eval (Fin.cases x (fun _ : Fin 1 =>
        MiMC.permutation (MiMC.constants keccak) (MiMC.compress (MiMC.constants keccak) 0 2) x +
          (x + 2 * MiMC.compress (MiMC.constants keccak) 0 2))) p := by
  exact (aesGraph_eval keccak p x).trans
    (congrArg (fun coefficient : F =>
      MvPolynomial.eval (Fin.cases x (fun _ : Fin 1 => coefficient)) p)
      ((MiMC.coefficient_permutation_graph keccak x).trans (add_assoc _ _ _)))

theorem invalid_aes_actual_graph_mass_le_of_replacement (keccak : MiMC.Hash256)
    (b : TupleBatch F 1 n m) (hchar : m < Order) (j : Fin m)
    (hout : ∀ i, b.table i ≠ b.query j)
    (root : Distribution F) (δ : ℚ) (hδ : 0 ≤ δ) (hroot : ∀ x, root.mass x ≤ δ)
    (permPrefix : PermutationPrefix F) (q : ℕ) (hcache : permPrefix.cache.card ≤ q)
    (hq : q < Fintype.card F) (εreplace : ℚ)
    (hreplace : FrozenMiMCGraphReplacementBound keccak (tupleResidual b.support b.residue)
      root permPrefix εreplace) :
    eventMass root (fun x => (aesGraph keccak (tupleResidual b.support b.residue)).eval x = 0) ≤
      ((q + (n + m - 1) : ℕ) : ℚ) * δ +
        ((n + m - 1 : ℕ) : ℚ) / ((Fintype.card F - q : ℕ) : ℚ) + εreplace := by
  apply actual_mimc_graph_mass_le_of_replacement keccak (tupleResidual b.support b.residue)
    (invalid_aes_multivariate_residual_ne_zero b hchar j hout) (n + m - 1) ?_
    root δ hδ hroot permPrefix q hcache hq εreplace hreplace
  exact (tupleResidual_totalDegree_le b.support b.residue).trans
    (Nat.sub_le_sub_right b.support_card_le 1)

end NativeMiMC

end ZolanaVE.Lookup
