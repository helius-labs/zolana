import VerifiableEncryption.Lookup.ProductionAlgebra
import VerifiableEncryption.Aes.Lookups

/-! Native membership consequences retain the actual AES/curve specification
imports. ProductionAlgebra reexports the same generic batch, denominator and
probability declarations through this module. -/

namespace ZolanaVE.Lookup

open Polynomial
open scoped BigOperators

section NativeMembership

variable [Fact (Nat.Prime Order)]

/-- Below the native characteristic, equality of tagged denominator
polynomials binds the natural width tag as well as the field value. -/
theorem native_rangeDenominator_eq_iff (tag₁ tag₂ : ℕ) (value₁ value₂ : F)
    (h₁ : tag₁ < Order) (h₂ : tag₂ < Order) :
    rangeDenominator tag₁ value₁ = rangeDenominator tag₂ value₂ ↔
      tag₁ = tag₂ ∧ value₁ = value₂ := by
  constructor
  · intro h
    obtain ⟨ht, hv⟩ := (rangeDenominator_eq_iff tag₁ tag₂ value₁ value₂).mp h
    have htag := congrArg ZMod.val ht
    rw [ZMod.val_cast_of_lt h₁, ZMod.val_cast_of_lt h₂] at htag
    exact ⟨htag, hv⟩
  · rintro ⟨rfl, rfl⟩
    rfl

/-- The *uncompressed* indexed table. Payload equality alone is insufficient:
distinct indices may carry identical values. -/
noncomputable def indexedTable {n : ℕ} {V : Type*} [DecidableEq V]
    (table : Fin n → V) : Finset (F × V) :=
  Finset.univ.image (fun i => ((i.val : F), table i))

theorem indexedTable_member {n : ℕ} {V : Type*} [DecidableEq V]
    (table : Fin n → V) (index : F) (value : V)
    (h : (index, value) ∈ indexedTable table) :
    ∃ i : Fin n, index = (i.val : F) ∧ value = table i := by
  obtain ⟨i, _, hi⟩ := Finset.mem_image.mp h
  exact ⟨i, (congrArg Prod.fst hi).symm, (congrArg Prod.snd hi).symm⟩

/-- Membership in the true indexed table gives a canonical in-range index,
using `n ≤ Order` to exclude field reduction of a table index. -/
theorem indexedTable_member_semantics {n : ℕ} {V : Type*} [DecidableEq V]
    (table : Fin n → V) (hn : n ≤ Order) (index : F) (value : V)
    (h : (index, value) ∈ indexedTable table) :
    index.val < n ∧ value = table ⟨index.val, by
      obtain ⟨i, hi, _⟩ := indexedTable_member table index value h
      rw [hi, ZMod.val_cast_of_lt (lt_of_lt_of_le i.isLt hn)]
      exact i.isLt⟩ := by
  obtain ⟨i, hi, hv⟩ := indexedTable_member table index value h
  have hval : index.val = i.val := by
    rw [hi, ZMod.val_cast_of_lt (lt_of_lt_of_le i.isLt hn)]
  refine ⟨by rw [hval]; exact i.isLt, ?_⟩
  exact hv.trans (congrArg table (Fin.ext hval.symm))

/-- A nonzero number of repeated invalid queries cannot disappear modulo the
native characteristic when the entire query count is below `Order`. -/
theorem negative_count_ne_zero (count : ℕ) (hc : 0 < count) (hp : count < Order) :
    -(count : F) ≠ 0 := by
  apply neg_ne_zero.mpr
  intro hz
  have hv := congrArg ZMod.val hz
  rw [ZMod.val_cast_of_lt hp, ZMod.val_zero] at hv
  omega

/-- Explicit AES table graphs connect true indexed membership to the existing
semantic relations. They do not assert that an opaque extracted lookup gives
membership: that missing production/extraction bridge is kept visible. -/
noncomputable def spreadTable : Finset (F × F) :=
  indexedTable (fun i : Fin 256 => ((AesTables.spreadBytes.getD i.val 0 : ℕ) : F))

noncomputable def substitutionTable : Finset (F × F) :=
  indexedTable (fun i : Fin 1280 => ((Aes.substitutionAt i.val : ℕ) : F))

noncomputable def chunkTable : Finset (F × F) :=
  indexedTable (fun i : Fin 1296 => ((AesTables.chunkParity.getD i.val 0 : ℕ) : F))

theorem spread_member_semantics (index value : F) (h : (index, value) ∈ spreadTable) :
    Aes.spreadRel index value := by
  exact indexedTable_member_semantics _ (by unfold Order; norm_num) index value h

theorem substitution_member_semantics (index value : F)
    (h : (index, value) ∈ substitutionTable) : Aes.substRel index value := by
  exact indexedTable_member_semantics _ (by unfold Order; norm_num) index value h

theorem chunk_member_semantics (index value : F) (h : (index, value) ∈ chunkTable) :
    Aes.chunkRel index value := by
  exact indexedTable_member_semantics _ (by unfold Order; norm_num) index value h

/-- Indexed membership preserves all twelve payload columns and the
continuation. A proof of payload membership without index binding would not
establish this conclusion. -/
theorem row_member_semantics (rows : List.Vector (List.Vector F 12) 16)
    (index : F) (value : List.Vector F 12) (k : List.Vector F 12 → Prop)
    (h : (index, value) ∈ indexedTable rows.get) (hk : k value) :
    ∃ i : Fin 16, index = (i.val : F) ∧ k (rows.get i) := by
  obtain ⟨i, hi, hv⟩ := indexedTable_member rows.get index value h
  exact ⟨i, hi, hv ▸ hk⟩

noncomputable def scalarRangeTable (width : ℕ) : Finset F :=
  (Finset.range (2 ^ width)).image (fun v : ℕ => (v : F))

theorem scalarRange_member_semantics (width : ℕ) (value : F)
    (hwidth : 2 ^ width ≤ Order) (h : value ∈ scalarRangeTable width) :
    value.val < 2 ^ width := by
  obtain ⟨v, hv, heq⟩ := Finset.mem_image.mp h
  have hlt : v < 2 ^ width := Finset.mem_range.mp hv
  rw [← heq, ZMod.val_cast_of_lt (lt_of_lt_of_le hlt hwidth)]
  exact hlt

/-- Residues after grouping equal scalar poles. The left multiplicities stay
arbitrary; repeated right queries contribute their actual list occurrence
count. Grouping avoids the zero polynomial caused by keeping repeated poles
as separate denominator factors. -/
noncomputable def scalarResidue {n : ℕ} (table : Fin n → F)
    (multiplicity : Fin n → F) (queries : List F) (a : F) : F :=
  (∑ i : Fin n, if table i = a then multiplicity i else 0) - (queries.count a : F)

/-- An out-of-table scalar queried a positive number of times gives a nonzero
residual, irrespective of the claimed table multiplicities. The characteristic
bound is indispensable: `Order` repeats would have zero residue. -/
theorem scalar_invalid_residual_ne_zero {n : ℕ} (table : Fin n → F)
    (multiplicity : Fin n → F) (queries : List F) (s : Finset F) (a : F)
    (ha : a ∈ s) (hout : ∀ i, table i ≠ a)
    (hcount : 0 < queries.count a) (hchar : queries.count a < Order) :
    residual s (fun b => X - C b) (scalarResidue table multiplicity queries) ≠ 0 := by
  have hw : scalarResidue table multiplicity queries a = -(queries.count a : F) := by
    simp [scalarResidue, hout]
  apply residual_ne_zero_of_distinct_poles s id _
    (fun _ _ _ _ h => h) a ha
  rw [hw]
  exact negative_count_ne_zero _ hcount hchar

end NativeMembership

end ZolanaVE.Lookup
