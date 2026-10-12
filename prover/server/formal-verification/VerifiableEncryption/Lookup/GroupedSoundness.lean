import VerifiableEncryption.Lookup.Multivariate
import VerifiableEncryption.Lookup.Production

/-!
Grouping the raw committed tuple batch is sound even at poles: quotients for
equal tuples are added, using multiplication only. An invalid query has a
nonzero grouped residue when its occurrence count is below the characteristic.
Together with the source radix cap this derives nonzero residuals, rather
than assuming the desired invalid-query implication.
-/

namespace ZolanaVE.Lookup

open scoped Polynomial BigOperators

variable {K : Type*} [Field K] {I A : Type*} [DecidableEq I] [DecidableEq A]

noncomputable def groupedWeight (s : Finset I) (key : I → A) (w : I → K) (a : A) : K :=
  ∑ i ∈ s.filter (fun i => key i = a), w i

theorem accepted_grouped (s : Finset I) (key : I → A) (d : A → K[X])
    (w : I → K) (x : K) (h : Accepted s (fun i => d (key i)) w x) :
    Accepted (s.image key) d (groupedWeight s key w) x := by
  obtain ⟨q, hq, hs⟩ := h
  refine ⟨fun a => ∑ i ∈ s.filter (fun i => key i = a), q i, ?_, ?_⟩
  · intro a _
    rw [Finset.sum_mul]
    apply Finset.sum_congr rfl
    intro i hi
    obtain ⟨his, hkey⟩ := Finset.mem_filter.mp hi
    rw [← hkey]
    exact hq i his
  · exact (Finset.sum_fiberwise_of_maps_to
      (fun i hi => Finset.mem_image_of_mem key hi) q).trans hs

variable {d n m : ℕ}

structure TupleBatch (K : Type*) (d n m : ℕ) where
  table : Fin n → LookupTuple K d
  query : Fin m → LookupTuple K d
  multiplicity : Fin n → K

namespace TupleBatch

variable [DecidableEq K]

def key (b : TupleBatch K d n m) : Sum (Fin n) (Fin m) → LookupTuple K d :=
  Sum.elim b.table b.query

def weight (b : TupleBatch K d n m) : Sum (Fin n) (Fin m) → K :=
  Sum.elim b.multiplicity (fun _ => -1)

noncomputable def support (b : TupleBatch K d n m) : Finset (LookupTuple K d) :=
  Finset.univ.image b.key

noncomputable def residue (b : TupleBatch K d n m) : LookupTuple K d → K :=
  groupedWeight Finset.univ b.key b.weight

noncomputable def queryCount (b : TupleBatch K d n m) (a : LookupTuple K d) : ℕ :=
  (Finset.univ.filter (fun j => b.query j = a)).card

noncomputable def asBatch (B : ℕ) (b : TupleBatch K d n m) : Batch K n m where
  table := fun i => separatedDenominator B (b.table i)
  query := fun j => separatedDenominator B (b.query j)
  multiplicity := b.multiplicity

theorem support_card_le (b : TupleBatch K d n m) : b.support.card ≤ n + m := by
  simpa [support] using Finset.card_image_le (s := (Finset.univ : Finset (Sum (Fin n) (Fin m))))
    (f := b.key)

theorem query_mem_support (b : TupleBatch K d n m) (j : Fin m) : b.query j ∈ b.support :=
  Finset.mem_image.mpr ⟨Sum.inr j, Finset.mem_univ _, rfl⟩

theorem queryCount_pos (b : TupleBatch K d n m) (j : Fin m) : 0 < b.queryCount (b.query j) := by
  apply Finset.card_pos.mpr
  exact ⟨j, Finset.mem_filter.mpr ⟨Finset.mem_univ _, rfl⟩⟩

theorem queryCount_le (b : TupleBatch K d n m) (a : LookupTuple K d) : b.queryCount a ≤ m := by
  exact le_trans (Finset.card_filter_le _ _) (by simp)

theorem residue_outside_table (b : TupleBatch K d n m) (a : LookupTuple K d)
    (hout : ∀ i, b.table i ≠ a) : b.residue a = -(b.queryCount a : K) := by
  classical
  simp only [residue, groupedWeight, Finset.sum_filter, Fintype.sum_sum_type,
    key, weight, Sum.elim_inl, Sum.elim_inr]
  simp only [hout, if_false, Finset.sum_const_zero, zero_add]
  rw [← Finset.sum_filter]
  simp [queryCount]

/-- Refinement of raw table divisions/query inverses into the distinct-tuple
residual model. No denominator nonzero premise is needed for grouping. -/
theorem accepted_residual_zero (B : ℕ) (b : TupleBatch K d n m) (x : K)
    (h : Accepted Finset.univ (b.asBatch B).denominator (b.asBatch B).weight x) :
    (residual b.support (separatedDenominator B) b.residue).eval x = 0 := by
  have hd : (b.asBatch B).denominator = fun i => separatedDenominator B (b.key i) := by
    funext i
    cases i <;> rfl
  rw [hd] at h
  have hg := accepted_grouped Finset.univ b.key (separatedDenominator B) b.weight x h
  exact ZolanaVE.Lookup.accepted_residual_zero b.support (separatedDenominator B) b.residue x hg

end TupleBatch

section Native

variable [Fact (Nat.Prime Order)]

/-- Actual radix residual nonzeroness for an invalid indexed query. Counts
are arbitrary committed field elements; only true query occurrence counts are
used at the invalid tuple. The caps are exactly the source separation cap and
the native-characteristic cap. -/
theorem invalid_tuple_residual_ne_zero (B : ℕ) (b : TupleBatch F d n m)
    (hsize : n + m < B) (hchar : m < Order) (j : Fin m)
    (hout : ∀ i, b.table i ≠ b.query j) :
    residual b.support (separatedDenominator B) b.residue ≠ 0 := by
  have hw : b.residue (b.query j) ≠ 0 := by
    rw [b.residue_outside_table _ hout]
    exact negative_count_ne_zero _ (b.queryCount_pos j)
      (lt_of_le_of_lt (b.queryCount_le _) hchar)
  exact separatedResidual_ne_zero B b.support b.residue
    (lt_of_le_of_lt b.support_card_le hsize) (b.query j) (b.query_mem_support j) hw

theorem separated_row_eq (t : LookupTuple F 12) :
    separatedDenominator 256 t = rowDenominator t.1 t.2 := rfl

theorem separated_range_eq (t : LookupTuple F 1) :
    separatedDenominator (2 ^ 20) t = rangeDenominator (t.2 0).val t.1 := by
  simp [separatedDenominator, rangeDenominator, ZMod.natCast_zmod_val]
  ring

/-- Production's sixteen indexed twelve-column ladder rows, queried with
untrusted returned payloads and arbitrary hinted multiplicities. -/
def rowTupleBatch (rows : List.Vector (List.Vector F 12) 16)
    (indices : Fin m → F) (outputs : Fin m → List.Vector F 12)
    (counts : Fin 16 → F) : TupleBatch F 12 16 m where
  table := fun i => ((i.val : F), fun j => (rows.get i).get j)
  query := fun i => (indices i, fun j => (outputs i).get j)
  multiplicity := counts

theorem rowTupleBatch_invalid_query (rows : List.Vector (List.Vector F 12) 16)
    (indices : Fin m → F) (outputs : Fin m → List.Vector F 12) (counts : Fin 16 → F)
    (j : Fin m) (hwrong : (indices j, outputs j) ∉ indexedTable rows.get) :
    ∀ i, (rowTupleBatch rows indices outputs counts).table i ≠
      (rowTupleBatch rows indices outputs counts).query j := by
  intro i he
  have hindex : (i.val : F) = indices j := congrArg Prod.fst he
  have hcols : (fun k => (rows.get i).get k) = (fun k => (outputs j).get k) :=
    congrArg Prod.snd he
  have hout : rows.get i = outputs j := List.Vector.ext (fun k => congrFun hcols k)
  apply hwrong
  exact Finset.mem_image.mpr ⟨i, Finset.mem_univ _, Prod.ext hindex hout⟩

/-- The paired sparse narrow-range checks prevent native-field wraparound:
both the original and scaled value lie in the main eleven-bit table. -/
theorem sparse_range_bound (width : ℕ) (hwidth : width ≤ 11) (value : F)
    (hv : value.val < 2 ^ 11)
    (hs : (value * ((2 ^ (11 - width) : ℕ) : F)).val < 2 ^ 11) : value.val < 2 ^ width := by
  have hscale : (2 : ℕ) ^ (11 - width) ≤ 2 ^ 11 :=
    pow_le_pow_right' (by norm_num) (Nat.sub_le _ _)
  have hpos : 0 < (2 : ℕ) ^ (11 - width) := by positivity
  have hprod : value.val * 2 ^ (11 - width) < Order := by
    have hlt : value.val * 2 ^ (11 - width) < 2 ^ 11 * 2 ^ 11 :=
      lt_of_lt_of_le (Nat.mul_lt_mul_of_pos_right hv hpos)
        (Nat.mul_le_mul_left (2 ^ 11) hscale)
    have ho : 2 ^ 11 * 2 ^ 11 < Order := by unfold Order; norm_num
    exact lt_trans hlt ho
  have hcast : ((2 ^ (11 - width) : ℕ) : F).val = 2 ^ (11 - width) := by
    apply ZMod.val_cast_of_lt
    have ho : 2 ^ 11 < Order := by unfold Order; norm_num
    exact lt_of_le_of_lt hscale ho
  rw [ZMod.val_mul, hcast, Nat.mod_eq_of_lt hprod] at hs
  have hpow : (2 : ℕ) ^ 11 = 2 ^ width * 2 ^ (11 - width) := by
    have he : width + (11 - width) = 11 := by omega
    rw [← pow_add, he]
  rw [hpow] at hs
  exact Nat.lt_of_mul_lt_mul_right hs

theorem invalid_range_residual_ne_zero (b : TupleBatch F 1 n m)
    (hsize : n + m < 2 ^ 20) (j : Fin m) (hout : ∀ i, b.table i ≠ b.query j) :
    residual b.support (separatedDenominator (2 ^ 20)) b.residue ≠ 0 := by
  apply invalid_tuple_residual_ne_zero (2 ^ 20) b hsize ?_ j hout
  have horder : 2 ^ 20 < Order := by unfold Order; norm_num
  omega

theorem invalid_row_residual_ne_zero (b : TupleBatch F 12 n m)
    (hsize : n + m < 256) (j : Fin m) (hout : ∀ i, b.table i ≠ b.query j) :
    residual b.support (separatedDenominator 256) b.residue ≠ 0 := by
  apply invalid_tuple_residual_ne_zero 256 b hsize ?_ j hout
  have horder : 256 < Order := by unfold Order; norm_num
  omega

/-- Whole raw-batch false acceptance bound, including poles. The nonzero
residual is derived from an actual invalid tuple, arbitrary table counts,
query multiplicities, and radix/characteristic caps. -/
theorem invalid_tuple_acceptance_mass_callback_le (B D : ℕ) (b : TupleBatch F d n m)
    (hsize : n + m < B) (hchar : m < Order) (j : Fin m)
    (hout : ∀ i, b.table i ≠ b.query j)
    (hdegree : ∀ t ∈ b.support, (separatedDenominator B t).natDegree ≤ D)
    (μ : Distribution F) (cap : ℚ) (hcap : 0 ≤ cap)
    (hpoint : ∀ x, μ.mass x ≤ cap) (r : ℕ) (hr : 0 < r) :
    eventMass (μ.pushforward (fun x => x ^ r))
      (Accepted Finset.univ (b.asBatch B).denominator (b.asBatch B).weight) ≤
      (((n + m - 1) * D : ℕ) : ℚ) * ((r : ℚ) * cap) := by
  classical
  have hn := invalid_tuple_residual_ne_zero B b hsize hchar j hout
  have hd : (residual b.support (separatedDenominator B) b.residue).natDegree ≤
      (n + m - 1) * D := by
    exact le_trans (residual_degree_le b.support (separatedDenominator B) b.residue D hdegree)
      (Nat.mul_le_mul_right D (Nat.sub_le_sub_right b.support_card_le 1))
  have hb := eventMass_le_degree_mul_cap (μ.pushforward (fun x => x ^ r))
    ((r : ℚ) * cap) (mul_nonneg (Nat.cast_nonneg r) hcap)
    (fun y => power_pushforward_mass_le μ cap hcap hpoint r hr y)
    (residual b.support (separatedDenominator B) b.residue) hn
    (Accepted Finset.univ (b.asBatch B).denominator (b.asBatch B).weight)
    (fun x h => b.accepted_residual_zero B x h)
  exact le_trans hb (mul_le_mul_of_nonneg_right (by exact_mod_cast hd)
    (mul_nonneg (Nat.cast_nonneg r) hcap))

theorem invalid_range_acceptance_mass_callback_le (b : TupleBatch F 1 n m)
    (hsize : n + m < 2 ^ 20) (j : Fin m) (hout : ∀ i, b.table i ≠ b.query j)
    (μ : Distribution F) (cap : ℚ) (hcap : 0 ≤ cap)
    (hpoint : ∀ x, μ.mass x ≤ cap) (r : ℕ) (hr : 0 < r) :
    eventMass (μ.pushforward (fun x => x ^ r))
      (Accepted Finset.univ (b.asBatch (2 ^ 20)).denominator (b.asBatch (2 ^ 20)).weight) ≤
      (((n + m - 1) * 2 ^ 20 : ℕ) : ℚ) * ((r : ℚ) * cap) := by
  have horder : 2 ^ 20 < Order := by unfold Order; norm_num
  apply invalid_tuple_acceptance_mass_callback_le (2 ^ 20) (2 ^ 20) b hsize (by omega)
    j hout ?_ μ cap hcap hpoint r hr
  intro t _
  rw [separated_range_eq]
  exact rangeDenominator_degree_le _ _

theorem invalid_row_acceptance_mass_callback_le (b : TupleBatch F 12 n m)
    (hsize : n + m < 256) (j : Fin m) (hout : ∀ i, b.table i ≠ b.query j)
    (μ : Distribution F) (cap : ℚ) (hcap : 0 ≤ cap)
    (hpoint : ∀ x, μ.mass x ≤ cap) (r : ℕ) (hr : 0 < r) :
    eventMass (μ.pushforward (fun x => x ^ r))
      (Accepted Finset.univ (b.asBatch 256).denominator (b.asBatch 256).weight) ≤
      (((n + m - 1) * 256 ^ 12 : ℕ) : ℚ) * ((r : ℚ) * cap) := by
  have horder : 256 < Order := by unfold Order; norm_num
  apply invalid_tuple_acceptance_mass_callback_le 256 (256 ^ 12) b hsize (by omega)
    j hout ?_ μ cap hcap hpoint r hr
  intro t _
  rw [separated_row_eq]
  exact rowDenominator_degree_le _ _

/-- The production-sized ladder table specialization: any returned index/row
outside the actual indexed table makes the committed raw batch accept only
within the explicit algebraic callback budget. -/
theorem invalid_rowLookup_acceptance_mass_callback_le
    (rows : List.Vector (List.Vector F 12) 16) (indices : Fin m → F)
    (outputs : Fin m → List.Vector F 12) (counts : Fin 16 → F)
    (hsize : 16 + m < 256) (j : Fin m)
    (hwrong : (indices j, outputs j) ∉ indexedTable rows.get)
    (μ : Distribution F) (cap : ℚ) (hcap : 0 ≤ cap)
    (hpoint : ∀ x, μ.mass x ≤ cap) (r : ℕ) (hr : 0 < r) :
    let b := rowTupleBatch rows indices outputs counts
    eventMass (μ.pushforward (fun x => x ^ r))
      (Accepted Finset.univ (b.asBatch 256).denominator (b.asBatch 256).weight) ≤
      (((16 + m - 1) * 256 ^ 12 : ℕ) : ℚ) * ((r : ℚ) * cap) :=
  invalid_row_acceptance_mass_callback_le (rowTupleBatch rows indices outputs counts)
    hsize j (rowTupleBatch_invalid_query rows indices outputs counts j hwrong)
    μ cap hcap hpoint r hr

theorem invalid_range_uniform_acceptance_mass_callback_le (b : TupleBatch F 1 n m)
    (hsize : n + m < 2 ^ 20) (hbad : ∃ j : Fin m, ∀ i, b.table i ≠ b.query j)
    (r : ℕ) (hr : 0 < r) :
    eventMass ((uniformDistribution (K := F)).pushforward (fun x => x ^ r))
      (Accepted Finset.univ (b.asBatch (2 ^ 20)).denominator (b.asBatch (2 ^ 20)).weight) ≤
      ((((n + m - 1) * 2 ^ 20 : ℕ) : ℚ) * (r : ℚ)) / Fintype.card F := by
  obtain ⟨j, hj⟩ := hbad
  simpa only [div_eq_mul_inv, one_mul, mul_assoc] using
    invalid_range_acceptance_mass_callback_le b hsize j hj (uniformDistribution (K := F))
      (1 / (Fintype.card F : ℚ)) (by positivity) (fun _ => le_rfl) r hr

theorem invalid_row_uniform_acceptance_mass_callback_le (b : TupleBatch F 12 n m)
    (hsize : n + m < 256) (hbad : ∃ j : Fin m, ∀ i, b.table i ≠ b.query j)
    (r : ℕ) (hr : 0 < r) :
    eventMass ((uniformDistribution (K := F)).pushforward (fun x => x ^ r))
      (Accepted Finset.univ (b.asBatch 256).denominator (b.asBatch 256).weight) ≤
      ((((n + m - 1) * 256 ^ 12 : ℕ) : ℚ) * (r : ℚ)) / Fintype.card F := by
  obtain ⟨j, hj⟩ := hbad
  simpa only [div_eq_mul_inv, one_mul, mul_assoc] using
    invalid_row_acceptance_mass_callback_le b hsize j hj (uniformDistribution (K := F))
      (1 / (Fintype.card F : ℚ)) (by positivity) (fun _ => le_rfl) r hr

end Native

end ZolanaVE.Lookup
