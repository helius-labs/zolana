import VerifiableEncryption.Lookup.SourcePrograms
import VerifiableEncryption.Lookup.Completeness

/-!
Honest row selections construct the emitted row program whenever their query
denominators are nonzero. Lifting that program into the actual opaque
RowLookup predicate needs an explicitly trusted backend construction/refinement
boundary. Neither numerical challenge existence nor a pole probability alone
establishes the universal primitive RowComplete contract.
-/

namespace ZolanaVE.Lookup

open Polynomial
open scoped BigOperators

variable {K : Type*} [Field K] {n m : ℕ}

theorem rawGateTrace_of_accepted (b : Batch K n m) (x : K)
    (h : Accepted Finset.univ b.denominator b.weight x) : Nonempty (RawGateTrace b x) := by
  obtain ⟨q, hq, hs⟩ := h
  refine ⟨⟨(fun i => q (Sum.inl i)), (fun j => -q (Sum.inr j)), ?_, ?_, ?_⟩⟩
  · intro i
    exact hq (Sum.inl i) (Finset.mem_univ _)
  · intro j
    have he := hq (Sum.inr j) (Finset.mem_univ _)
    change q (Sum.inr j) * (b.query j).eval x = -1 at he
    rw [neg_mul, he, neg_neg]
  · have he : (∑ i, q (Sum.inl i)) + (∑ j, q (Sum.inr j)) = 0 := by
      simpa only [Fintype.sum_sum_type] using hs
    rw [Finset.sum_neg_distrib]
    exact eq_neg_of_add_eq_zero_left he

variable [Fact (Nat.Prime Order)]

theorem sourceRowCallback_of_certificate (b : TupleBatch F 12 n m) (callback : F)
    (trace : RawGateTrace (b.asBatch 256) callback) :
    (sourceRowCallback b callback).Satisfies := by
  rw [sourceRowCallback, sourceColumnWeights_satisfies]
  exact nativeLookupCallback_of_certificate (b.asBatch 256) callback _ _
    (fun i => rowDenominatorExpression_value callback (b.table i))
    (fun j => rowDenominatorExpression_value callback (b.query j)) trace

def honestRowBatch (rows : List.Vector (List.Vector F 12) 16) (selection : Fin m → Fin 16) :
    TupleBatch F 12 16 m :=
  rowTupleBatch rows (fun j => (selection j).val) (fun j => rows.get (selection j))
    (fun i => (Completeness.selectedCount selection i : F))

theorem honestRowBatch_query (rows : List.Vector (List.Vector F 12) 16)
    (selection : Fin m → Fin 16) (j : Fin m) :
    ((honestRowBatch rows selection).asBatch 256).query j =
      ((honestRowBatch rows selection).asBatch 256).table (selection j) := rfl

theorem honest_row_program (rows : List.Vector (List.Vector F 12) 16)
    (selection : Fin m → Fin 16) (callback : F)
    (hden : ∀ j, (((honestRowBatch rows selection).asBatch 256).query j).eval callback ≠ 0) :
    (sourceRowCallback (honestRowBatch rows selection) callback).Satisfies := by
  have ha := Completeness.selected_batch_complete
    ((honestRowBatch rows selection).asBatch 256) selection
    (honestRowBatch_query rows selection) (fun _ => rfl) callback hden
  obtain ⟨trace⟩ := rawGateTrace_of_accepted _ _ ha
  exact sourceRowCallback_of_certificate _ _ trace

/-- A numerical callback exists under the explicit query-degree capacity.
It is not claimed to equal the configured commitment hash callback. -/
theorem honest_row_numerical_challenge_exists
    (rows : List.Vector (List.Vector F 12) 16) (selection : Fin m → Fin 16)
    (hsize : m * 256 ^ 12 < Fintype.card F) :
    ∃ callback, (sourceRowCallback (honestRowBatch rows selection) callback).Satisfies := by
  obtain ⟨callback, ha⟩ := Completeness.selected_batch_good_challenge_exists
    ((honestRowBatch rows selection).asBatch 256) selection
    (honestRowBatch_query rows selection) (fun _ => rfl) (256 ^ 12)
    (fun j => by
      change (separatedDenominator 256 ((honestRowBatch rows selection).query j)).natDegree ≤ _
      rw [separated_row_eq]; exact rowDenominator_degree_le _ _)
    (fun j => by
      change separatedDenominator 256 ((honestRowBatch rows selection).query j) ≠ 0
      rw [separated_row_eq]; exact rowDenominator_ne_zero _ _) hsize
  obtain ⟨trace⟩ := rawGateTrace_of_accepted _ _ ha
  exact ⟨callback, sourceRowCallback_of_certificate _ _ trace⟩

/-- Honest witness failure is contained in the query-pole event; unused
table rows may have zero denominators and zero unchecked quotients. -/
theorem honest_row_failure_mass_callback_le
    (rows : List.Vector (List.Vector F 12) 16) (selection : Fin m → Fin 16)
    (μ : Distribution F) (cap : ℚ) (hcap : 0 ≤ cap) (hpoint : ∀ x, μ.mass x ≤ cap)
    (r : ℕ) (hr : 0 < r) :
    eventMass (μ.pushforward (fun x => x ^ r))
      (fun callback => ¬ (sourceRowCallback (honestRowBatch rows selection) callback).Satisfies) ≤
      ((m * 256 ^ 12 : ℕ) : ℚ) * ((r : ℚ) * cap) := by
  classical
  let b := (honestRowBatch rows selection).asBatch 256
  have hb := Completeness.selected_batch_failure_mass_callback_le b selection
    (honestRowBatch_query rows selection) (fun _ => rfl) (256 ^ 12)
    (fun j => by
      change (separatedDenominator 256 ((honestRowBatch rows selection).query j)).natDegree ≤ _
      rw [separated_row_eq]; exact rowDenominator_degree_le _ _)
    (fun j => by
      change separatedDenominator 256 ((honestRowBatch rows selection).query j) ≠ 0
      rw [separated_row_eq]; exact rowDenominator_ne_zero _ _)
    μ cap hcap hpoint r hr
  have hm := finiteProbability_mono (μ.pushforward (fun x => x ^ r))
    (fun callback => ¬ (sourceRowCallback (honestRowBatch rows selection) callback).Satisfies)
    (fun callback => ¬ Accepted Finset.univ b.denominator b.weight callback) (by
      intro callback hfail ha
      obtain ⟨trace⟩ := rawGateTrace_of_accepted b callback ha
      exact hfail (sourceRowCallback_of_certificate _ _ trace))
  exact le_trans hm hb

/-- Completeness of backend lowering for one source program invocation.
`compatible` must certify the actual committed inputs, challenge/transcript,
wire assignment and source/backend interpretation. Outputs are arbitrary;
no lookup membership or FullScalarMulChecked premise is present. This
construction boundary is not proved from the extractor's opaque predicates. -/
structure RowBackendCompleteness where
  compatible : {queries : ℕ} → List.Vector (List.Vector F 12) 16 →
    (Fin queries → F) → (Fin queries → List.Vector F 12) → (Fin 16 → F) → F → Prop
  realize : ∀ {queries : ℕ} (rows : List.Vector (List.Vector F 12) 16)
    (indices : Fin queries → F) (outputs : Fin queries → List.Vector F 12) (counts : Fin 16 → F)
    (callback : F), compatible rows indices outputs counts callback →
    (sourceRowCallback (rowTupleBatch rows indices outputs counts) callback).Satisfies →
    ∀ (slot : Fin queries) (k : List.Vector F 12 → Prop), k (outputs slot) →
      RowLookup_12_16 rows (indices slot) k

/-- An actual opaque call proof is obtained only after supplying the trusted
per-invocation backend construction certificate and a good actual callback. -/
theorem honest_rowCall_of_backend (backend : RowBackendCompleteness)
    (rows : List.Vector (List.Vector F 12) 16) (i : Fin 16) (callback : F)
    (hcompatible : backend.compatible rows (fun _ : Fin 1 => (i.val : F))
      (fun _ => rows.get i) (fun j => (Completeness.selectedCount (fun _ : Fin 1 => i) j : F)) callback)
    (hden : (((honestRowBatch rows (fun _ : Fin 1 => i)).asBatch 256).query 0).eval callback ≠ 0)
    (k : List.Vector F 12 → Prop) (hk : k (rows.get i)) : RowLookup_12_16 rows (i.val : F) k := by
  have hp := honest_row_program rows (fun _ : Fin 1 => i) callback (fun j => by
    have hj : j = 0 := Subsingleton.elim _ _
    simpa only [hj] using hden)
  exact backend.realize rows (fun _ : Fin 1 => (i.val : F)) (fun _ => rows.get i)
    (fun j => (Completeness.selectedCount (fun _ : Fin 1 => i) j : F)) callback hcompatible hp 0 k hk


/-- The construction experiment includes backend compatibility failure as well
as lookup poles. A good numerical callback alone does not remove that term. -/
theorem honest_row_construction_failure_mass_le (backend : RowBackendCompleteness)
    (rows : List.Vector (List.Vector F 12) 16) (i : Fin 16)
    (k : List.Vector F 12 → Prop) (hk : k (rows.get i))
    (μ : Distribution F) (cap : ℚ) (hcap : 0 ≤ cap) (hpoint : ∀ x, μ.mass x ≤ cap)
    (r : ℕ) (hr : 0 < r) (εbackend : ℚ)
    (hbackend : eventMass (μ.pushforward (fun x => x ^ r))
      (fun callback => ¬ backend.compatible rows (fun _ : Fin 1 => (i.val : F))
        (fun _ => rows.get i)
        (fun j => (Completeness.selectedCount (fun _ : Fin 1 => i) j : F)) callback) ≤ εbackend) :
    eventMass (μ.pushforward (fun x => x ^ r))
      (fun callback => ¬ (backend.compatible rows (fun _ : Fin 1 => (i.val : F))
        (fun _ => rows.get i)
        (fun j => (Completeness.selectedCount (fun _ : Fin 1 => i) j : F)) callback ∧
        (sourceRowCallback (honestRowBatch rows (fun _ : Fin 1 => i)) callback).Satisfies ∧
        RowLookup_12_16 rows (i.val : F) k)) ≤
      εbackend + ((256 ^ 12 : ℕ) : ℚ) * ((r : ℚ) * cap) := by
  classical
  let ν := μ.pushforward (fun x => x ^ r)
  let compatible := fun callback => backend.compatible rows (fun _ : Fin 1 => (i.val : F))
    (fun _ => rows.get i)
    (fun j => (Completeness.selectedCount (fun _ : Fin 1 => i) j : F)) callback
  let program := fun callback =>
    (sourceRowCallback (honestRowBatch rows (fun _ : Fin 1 => i)) callback).Satisfies
  have hm := finiteProbability_mono ν
    (fun callback => ¬ (compatible callback ∧ program callback ∧ RowLookup_12_16 rows (i.val : F) k))
    (fun callback => ¬ compatible callback ∨ ¬ program callback) (by
      intro callback hf
      by_cases hc : compatible callback
      · right
        intro hp
        have hcall := backend.realize rows (fun _ : Fin 1 => (i.val : F))
          (fun _ => rows.get i)
          (fun j => (Completeness.selectedCount (fun _ : Fin 1 => i) j : F)) callback hc hp 0 k hk
        exact hf ⟨hc, hp, hcall⟩
      · exact Or.inl hc)
  have hpole := honest_row_failure_mass_callback_le rows (fun _ : Fin 1 => i) μ cap hcap hpoint r hr
  have hu := finiteProbability_or_le ν (fun callback => ¬ compatible callback)
    (fun callback => ¬ program callback)
  exact le_trans hm (le_trans hu (add_le_add hbackend (by simpa only [one_mul] using hpole)))

end ZolanaVE.Lookup
