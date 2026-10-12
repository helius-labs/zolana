import VerifiableEncryption.Lookup.SourcePrograms
import VerifiableEncryption.Field.Layout

/-!
Lookup semantics for one satisfying emitted source program, on its good
algebra/graph event. Table metadata is independently fixed by source table
construction. Local opaque-call anchors record the actual query slot, hint
output and continuation proof; they never assume the desired table output.
The opaque extracted predicate alone cannot supply a deferred program proof
or its anchor, so that extraction boundary is explicit and per execution.
-/

namespace ZolanaVE.Lookup

open scoped Polynomial BigOperators

variable [Fact (Nat.Prime Order)] {n m : ℕ}

def radixFailure (B : ℕ) {d : ℕ} (b : TupleBatch F d n m) (challenge : F) : Prop :=
  residual b.support (separatedDenominator B) b.residue ≠ 0 ∧
    (residual b.support (separatedDenominator B) b.residue).eval challenge = 0

def aesFailure (keccak : MiMC.Hash256) (b : TupleBatch F 1 n m) (challenge : F) : Prop :=
  tupleResidual b.support b.residue ≠ 0 ∧
    (aesGraph keccak (tupleResidual b.support b.residue)).eval challenge = 0

theorem sourceRow_queries_correct (b : TupleBatch F 12 n m) (challenge : F)
    (hsize : n + m < 256) (hprogram : (sourceRowCallback b challenge).Satisfies)
    (hgood : ¬ radixFailure 256 b challenge) : ∀ j, ∃ i, b.table i = b.query j := by
  classical
  obtain ⟨trace⟩ := sourceRowCallback_certificate b challenge hprogram
  intro j
  by_contra h
  push_neg at h
  exact hgood ⟨invalid_row_residual_ne_zero b hsize j h,
    b.accepted_residual_zero 256 challenge trace.accepted⟩

theorem sourceRange_queries_correct (hasTags : Bool) (b : TupleBatch F 1 n m) (challenge : F)
    (hsize : n + m < 2 ^ 20) (hmetadata : hasTags = false → ∀ t ∈ b.support, t.2 0 = 0)
    (hprogram : (sourceRangeCallbackWithTags hasTags b challenge).Satisfies)
    (hgood : ¬ radixFailure (2 ^ 20) b challenge) : ∀ j, ∃ i, b.table i = b.query j := by
  classical
  obtain ⟨trace⟩ := sourceRangeCallbackWithTags_certificate hasTags b challenge hmetadata hprogram
  intro j
  by_contra h
  push_neg at h
  exact hgood ⟨invalid_range_residual_ne_zero b hsize j h,
    b.accepted_residual_zero (2 ^ 20) challenge trace.accepted⟩

theorem sourceAes_queries_correct (keccak : MiMC.Hash256) (b : TupleBatch F 1 n m)
    (challenge : F) (hchar : m < Order)
    (hprogram : (sourceAesCallback keccak b challenge).Satisfies)
    (hgood : ¬ (tupleResidual b.support b.residue ≠ 0 ∧
      (aesGraph keccak (tupleResidual b.support b.residue)).eval challenge = 0)) :
    ∀ j, ∃ i, b.table i = b.query j := by
  classical
  obtain ⟨trace⟩ := sourceAesCallback_certificate keccak b challenge hprogram
  intro j
  by_contra h
  push_neg at h
  exact hgood ⟨invalid_aes_multivariate_residual_ne_zero b hchar j h,
    aes_accepted_graph_zero keccak b challenge trace.accepted⟩

/-- Exact local row-call anchor. Its continuation is at the untrusted returned
row, not at the specified table row. `extracted` retains the actual opaque
predicate from the surrounding extracted circuit execution.
-/
structure RowCallAnchor (rows : List.Vector (List.Vector F 12) 16)
    (indices : Fin m → F) (outputs : Fin m → List.Vector F 12)
    (index : F) (k : List.Vector F 12 → Prop) where
  slot : Fin m
  index_agrees : indices slot = index
  continuation : k (outputs slot)
  extracted : RowLookup_12_16 rows index k

theorem anchored_RowLookup_sound (rows : List.Vector (List.Vector F 12) 16)
    (indices : Fin m → F) (outputs : Fin m → List.Vector F 12) (counts : Fin 16 → F)
    (index : F) (k : List.Vector F 12 → Prop) (anchor : RowCallAnchor rows indices outputs index k)
    (challenge : F) (hsize : 16 + m < 256)
    (hprogram : (sourceRowCallback (rowTupleBatch rows indices outputs counts) challenge).Satisfies)
    (hgood : ¬ radixFailure 256 (rowTupleBatch rows indices outputs counts) challenge) :
    ∃ i : Fin 16, index = (i.val : F) ∧ k (rows.get i) := by
  obtain ⟨i, hi⟩ := sourceRow_queries_correct _ challenge hsize hprogram hgood anchor.slot
  have hindex : (i.val : F) = indices anchor.slot := congrArg Prod.fst hi
  have hrow : rows.get i = outputs anchor.slot :=
    List.Vector.ext (fun j => congrFun (congrArg Prod.snd hi) j)
  exact ⟨i, anchor.index_agrees.symm.trans hindex.symm, hrow.symm ▸ anchor.continuation⟩

/-- Table construction metadata: each emitted table row states its source
range width and value bound. This is a property of fixed table constants,
not a premise asserting that queried values satisfy their requested checks.
-/
def rangeTableMetadata (b : TupleBatch F 1 n m) : Prop :=
  ∀ i, ((b.table i).2 0 = 0 ∧ (b.table i).1.val < 2 ^ 11) ∨
    ∃ width : ℕ, 2 ≤ width ∧ width < 11 ∧ (b.table i).2 0 = (width : F) ∧
      (b.table i).1.val < 2 ^ width

def mainRangeRow (i : Fin (2 ^ 11)) : LookupTuple F 1 := ((i.val : F), fun _ => 0)

def taggedRangeRow (width : ℕ) (i : Fin (2 ^ width)) : LookupTuple F 1 :=
  ((i.val : F), fun _ => (width : F))

theorem mainRangeRow_metadata (i : Fin (2 ^ 11)) :
    (mainRangeRow i).2 0 = 0 ∧ (mainRangeRow i).1.val < 2 ^ 11 := by
  have ho : 2 ^ 11 < Order := by unfold Order; norm_num
  exact ⟨rfl, by simpa only [mainRangeRow, ZMod.val_cast_of_lt (lt_trans i.isLt ho)] using i.isLt⟩

theorem taggedRangeRow_metadata (width : ℕ) (hlo : 2 ≤ width) (hhi : width < 11)
    (i : Fin (2 ^ width)) :
    2 ≤ width ∧ width < 11 ∧ (taggedRangeRow width i).2 0 = (width : F) ∧
      (taggedRangeRow width i).1.val < 2 ^ width := by
  have hp : (2 : ℕ) ^ width ≤ 2 ^ 11 := pow_le_pow_right' (by norm_num) hhi.le
  have ho : 2 ^ 11 < Order := by unfold Order; norm_num
  refine ⟨hlo, hhi, rfl, ?_⟩
  have hi : i.val < Order := lt_trans i.isLt (lt_of_le_of_lt hp ho)
  change ((i.val : F).val) < 2 ^ width
  rw [ZMod.val_cast_of_lt hi]
  exact i.isLt

theorem RangeBuilderGrouping.table_metadata {b : TupleBatch F 1 n m}
    (grouping : RangeBuilderGrouping b) : rangeTableMetadata b := by
  intro i
  have hi : b.table i ∈ List.ofFn b.table := (List.mem_ofFn _ _).mpr ⟨i, rfl⟩
  rw [grouping.table_agrees] at hi
  rcases List.mem_append.mp hi with hmain | htag
  · obtain ⟨row, he⟩ := (List.mem_ofFn _ _).mp hmain
    left
    rw [← he]
    exact mainRangeRow_metadata row
  · obtain ⟨bucket, hb, hrow⟩ := List.mem_flatMap.mp htag
    obtain ⟨row, he⟩ := (List.mem_ofFn _ _).mp hrow
    obtain ⟨hlo, hhi⟩ := grouping.widths bucket hb
    right
    refine ⟨bucket.width, ?_⟩
    rw [← he]
    exact taggedRangeRow_metadata bucket.width hlo hhi row

def nativeBooleanProgram (value : F) : NativeProgram F :=
  .add value (-1) (fun predecessor => .mul predecessor value (fun product =>
    .assertEqual product 0 .finish))

theorem nativeBooleanProgram_equation (value : F) (h : (nativeBooleanProgram value).Satisfies) :
    (value - 1) * value = 0 := by
  simpa [nativeBooleanProgram, NativeProgram.Satisfies, sub_eq_add_neg] using h

theorem sourceRange_main_member (b : TupleBatch F 1 n m) (hmeta : rangeTableMetadata b)
    (j : Fin m) (htag : (b.query j).2 0 = 0) (hm : ∃ i, b.table i = b.query j) :
    (b.query j).1.val < 2 ^ 11 := by
  obtain ⟨i, hi⟩ := hm
  rcases hmeta i with ⟨_, hv⟩ | ⟨width, hlo, hhi, ht, hv⟩
  · simpa only [hi] using hv
  · have hc : (width : F) = 0 := by rw [← ht, hi, htag]
    have hwidth : width < Order := by unfold Order; omega
    have hz := congrArg ZMod.val hc
    rw [ZMod.val_cast_of_lt hwidth, ZMod.val_zero] at hz
    omega

theorem sourceRange_tagged_member (b : TupleBatch F 1 n m) (hmeta : rangeTableMetadata b)
    (j : Fin m) (width : ℕ) (hlo : 2 ≤ width) (hhi : width < 11)
    (htag : (b.query j).2 0 = (width : F)) (hm : ∃ i, b.table i = b.query j) :
    (b.query j).1.val < 2 ^ width := by
  obtain ⟨i, hi⟩ := hm
  have hwOrder : width < Order := by unfold Order; omega
  rcases hmeta i with ⟨ht, hv⟩ | ⟨actual, haLo, haHi, ht, hv⟩
  · have hz : (width : F) = 0 := by rw [← htag, ← hi, ht]
    have hc := congrArg ZMod.val hz
    rw [ZMod.val_cast_of_lt hwOrder, ZMod.val_zero] at hc
    omega
  · have haOrder : actual < Order := by unfold Order; omega
    have he : (actual : F) = (width : F) := by rw [← ht, hi, htag]
    have hc := congrArg ZMod.val he
    rw [ZMod.val_cast_of_lt haOrder, ZMod.val_cast_of_lt hwOrder] at hc
    simpa only [hi, hc] using hv

/-- Dense versus sparse local source plans, including the two recorded main
queries of the sparse scaled check. The slots are emitted-query anchors.
-/
inductive SmallRangeAnchor (b : TupleBatch F 1 n m) (width : ℕ) (value : F) : Prop where
  | zero (hw : width = 0) (hv : value = 0)
  | boolean (hw : width = 1) (hv : (value - 1) * value = 0)
  | main (hw : width = 11) (slot : Fin m) (hvalue : (b.query slot).1 = value)
      (htag : (b.query slot).2 0 = 0)
  | dense (hlo : 2 ≤ width) (hhi : width < 11) (slot : Fin m)
      (hvalue : (b.query slot).1 = value) (htag : (b.query slot).2 0 = (width : F))
  | sparse (hlo : 2 ≤ width) (hhi : width < 11) (slot scaledSlot : Fin m)
      (hvalue : (b.query slot).1 = value) (htag : (b.query slot).2 0 = 0)
      (hscaled : (b.query scaledSlot).1 = value * ((2 ^ (11 - width) : ℕ) : F))
      (hscaledTag : (b.query scaledSlot).2 0 = 0)

theorem SmallRangeAnchor.bound {b : TupleBatch F 1 n m} {width : ℕ} {value : F}
    (anchor : SmallRangeAnchor b width value) (hmeta : rangeTableMetadata b)
    (hm : ∀ j, ∃ i, b.table i = b.query j) : value.val < 2 ^ width := by
  cases anchor with
  | zero hw hv => simp [hw, hv]
  | boolean hw hv =>
    rw [hw]
    apply Field.is_bool_val
    change (1 - value) * value = 0
    linear_combination -hv
  | main hw slot hvalue htag =>
    simpa only [hw, hvalue] using sourceRange_main_member b hmeta slot htag (hm slot)
  | dense hlo hhi slot hvalue htag =>
    simpa only [hvalue] using sourceRange_tagged_member b hmeta slot width hlo hhi htag (hm slot)
  | sparse hlo hhi slot scaledSlot hvalue htag hscaled hscaledTag =>
    apply sparse_range_bound width hhi.le value
    · simpa only [hvalue] using sourceRange_main_member b hmeta slot htag (hm slot)
    · simpa only [hscaled] using sourceRange_main_member b hmeta scaledSlot hscaledTag (hm scaledSlot)

def RangeCheckAnchor (b : TupleBatch F 1 n m) (width : ℕ) (value : F) : Prop :=
  if width ≤ 11 then SmallRangeAnchor b width value else
    ∃ pieces : List F, Field.ComposeOk (SmallRangeAnchor b) 11 width pieces ∧
      value = Field.composeValue 11 pieces

theorem RangeCheckAnchor.bound {b : TupleBatch F 1 n m} {width : ℕ} {value : F}
    (anchor : RangeCheckAnchor b width value) (hwidth : width ≤ 253)
    (hmeta : rangeTableMetadata b) (hm : ∀ j, ∃ i, b.table i = b.query j) :
    value.val < 2 ^ width := by
  unfold RangeCheckAnchor at anchor
  split_ifs at anchor with hsmall
  · exact anchor.bound hmeta hm
  · obtain ⟨pieces, hp, rfl⟩ := anchor
    apply Field.compose_val_lt (rc := SmallRangeAnchor b) ?_ (by norm_num) (by norm_num) hwidth hp
    intro bits v _ ha
    exact ha.bound hmeta hm

theorem RangeCheckAnchor.bound_all {b : TupleBatch F 1 n m} {width : ℕ} {value : F}
    (anchor : RangeCheckAnchor b width value) (hmeta : rangeTableMetadata b)
    (hm : ∀ j, ∃ i, b.table i = b.query j) : value.val < 2 ^ width := by
  by_cases hsmall : width ≤ 253
  · exact anchor.bound hsmall hmeta hm
  · have hlarge : 254 ≤ width := by omega
    have horder : Order < 2 ^ 254 := by unfold Order; norm_num
    have hpow : (2 : ℕ) ^ 254 ≤ 2 ^ width := pow_le_pow_right' (by norm_num) hlarge
    exact lt_trans (ZMod.val_lt value) (lt_of_lt_of_le horder hpow)

/-- The library's extracted range layout, including small opaque range checks,
is retained at the selected call. The anchor supplies its source control-flow plan, decomposition/recomposition
constraints and query-slot associations. Membership is derived on the source
callback's good event and then composed through the complete width check.
-/
structure RangeCallAnchor (b : TupleBatch F 1 n m) (width : ℕ) (value : F) : Prop where
  emitted : RangeCheckAnchor b width value
  extracted : Field.LookupCheck RangeCheck 11 width value

theorem anchored_RangeCheck_sound (hasTags : Bool) (b : TupleBatch F 1 n m) (width : ℕ)
    (value challenge : F) (anchor : RangeCallAnchor b width value) (hwidth : width ≤ 253)
    (hsize : n + m < 2 ^ 20) (hmeta : rangeTableMetadata b)
    (htagmeta : hasTags = false → ∀ t ∈ b.support, t.2 0 = 0)
    (hprogram : (sourceRangeCallbackWithTags hasTags b challenge).Satisfies)
    (hgood : ¬ radixFailure (2 ^ 20) b challenge) : value.val < 2 ^ width :=
  anchor.emitted.bound hwidth hmeta
    (sourceRange_queries_correct hasTags b challenge hsize htagmeta hprogram hgood)

theorem anchored_RangeCheck_sound_all (hasTags : Bool) (b : TupleBatch F 1 n m) (width : ℕ)
    (value challenge : F) (anchor : RangeCallAnchor b width value)
    (hsize : n + m < 2 ^ 20) (hmeta : rangeTableMetadata b)
    (htagmeta : hasTags = false → ∀ t ∈ b.support, t.2 0 = 0)
    (hprogram : (sourceRangeCallbackWithTags hasTags b challenge).Satisfies)
    (hgood : ¬ radixFailure (2 ^ 20) b challenge) : value.val < 2 ^ width :=
  anchor.emitted.bound_all hmeta
    (sourceRange_queries_correct hasTags b challenge hsize htagmeta hprogram hgood)

structure AesCallAnchor (lookup : F → (F → Prop) → Prop) (indices values : Fin m → F)
    (index : F) (k : F → Prop) where
  slot : Fin m
  index_agrees : indices slot = index
  continuation : k (values slot)
  extracted : lookup index k

theorem anchored_AesLookup_member (lookup : F → (F → Prop) → Prop)
    (table : Fin n → F) (indices values : Fin m → F) (counts : Fin n → F)
    (index : F) (k : F → Prop) (anchor : AesCallAnchor lookup indices values index k)
    (keccak : MiMC.Hash256) (challenge : F) (hchar : m < Order)
    (hprogram : (sourceAesCallback keccak (indexedAesTupleBatch table indices values counts) challenge).Satisfies)
    (hgood : ¬ aesFailure keccak (indexedAesTupleBatch table indices values counts) challenge) :
    (index, values anchor.slot) ∈ indexedTable table := by
  have hm := indexedAesTupleBatch_member table indices values counts anchor.slot
    (sourceAes_queries_correct keccak _ challenge hchar hprogram hgood anchor.slot)
  simpa only [anchor.index_agrees] using hm

theorem anchored_SpreadByteLookup_sound (indices values : Fin m → F) (counts : Fin 256 → F)
    (index : F) (k : F → Prop) (anchor : AesCallAnchor SpreadByteLookup indices values index k)
    (keccak : MiMC.Hash256) (challenge : F) (hchar : m < Order)
    (hprogram : (sourceAesCallback keccak
      (indexedAesTupleBatch (fun i : Fin 256 => ((AesTables.spreadBytes.getD i.val 0 : ℕ) : F))
        indices values counts) challenge).Satisfies)
    (hgood : ¬ aesFailure keccak
      (indexedAesTupleBatch (fun i : Fin 256 => ((AesTables.spreadBytes.getD i.val 0 : ℕ) : F))
        indices values counts) challenge) :
    index.val < 256 ∧ k ((AesTables.spreadBytes.getD index.val 0 : ℕ) : F) := by
  apply spread_recorded_continuation index (values anchor.slot) k ?_ anchor.continuation
  exact anchored_AesLookup_member SpreadByteLookup _ indices values counts index k anchor
    keccak challenge hchar hprogram hgood

theorem anchored_SubstitutionLookup_sound (indices values : Fin m → F) (counts : Fin 1280 → F)
    (index : F) (k : F → Prop) (anchor : AesCallAnchor SubstitutionLookup indices values index k)
    (keccak : MiMC.Hash256) (challenge : F) (hchar : m < Order)
    (hprogram : (sourceAesCallback keccak
      (indexedAesTupleBatch (fun i : Fin 1280 => ((Aes.substitutionAt i.val : ℕ) : F))
        indices values counts) challenge).Satisfies)
    (hgood : ¬ aesFailure keccak
      (indexedAesTupleBatch (fun i : Fin 1280 => ((Aes.substitutionAt i.val : ℕ) : F))
        indices values counts) challenge) :
    index.val < 1280 ∧ k ((Aes.substitutionAt index.val : ℕ) : F) := by
  apply substitution_recorded_continuation index (values anchor.slot) k ?_ anchor.continuation
  exact anchored_AesLookup_member SubstitutionLookup _ indices values counts index k anchor
    keccak challenge hchar hprogram hgood

theorem anchored_ChunkParityLookup_sound (indices values : Fin m → F) (counts : Fin 1296 → F)
    (index : F) (k : F → Prop) (anchor : AesCallAnchor ChunkParityLookup indices values index k)
    (keccak : MiMC.Hash256) (challenge : F) (hchar : m < Order)
    (hprogram : (sourceAesCallback keccak
      (indexedAesTupleBatch (fun i : Fin 1296 => ((AesTables.chunkParity.getD i.val 0 : ℕ) : F))
        indices values counts) challenge).Satisfies)
    (hgood : ¬ aesFailure keccak
      (indexedAesTupleBatch (fun i : Fin 1296 => ((AesTables.chunkParity.getD i.val 0 : ℕ) : F))
        indices values counts) challenge) :
    index.val < 1296 ∧ k ((AesTables.chunkParity.getD index.val 0 : ℕ) : F) := by
  apply chunk_recorded_continuation index (values anchor.slot) k ?_ anchor.continuation
  exact anchored_AesLookup_member ChunkParityLookup _ indices values counts index k anchor
    keccak challenge hchar hprogram hgood

/-- The backend boundary now supplies an interpretation of the emitted
native gate program. Producing the raw quotient certificate is proved from
that program, rather than included in the backend hypothesis. The same
binding/source/actual-graph failure budgets remain explicit.
-/
theorem aesExperiment_source_failure_budget {PreCoins PostCoins : Type*}
    [Fintype PreCoins] [Fintype PostCoins] (keccak : MiMC.Hash256) (rootHash : List MiMC.Byte → F)
    (strategy : AesStrategy (PreCoins := PreCoins) (PostCoins := PostCoins) n m)
    (r : ℕ) (hchar : m < Order) (μ : Distribution (AesSample PreCoins PostCoins))
    (budget : OracleBudget) (bindingFailure realizationFailure : AesSample PreCoins PostCoins → Prop)
    (hadmissible : aesExperimentAdmissible keccak rootHash strategy r μ budget)
    (hbinding : ∀ ω, ¬ bindingFailure ω →
      (opened strategy ω).opened = (committed strategy ω).snapshot)
    (hsource : ∀ ω, ¬ realizationFailure ω → (opened strategy ω).accepted = true →
      (sourceAesCallback keccak (opened strategy ω).opened (ω.2.1 ^ r)).Satisfies)
    (εbind εreal εgraph : ℚ)
    (hbindProbability : finiteProbability μ bindingFailure ≤ εbind)
    (hrealProbability : finiteProbability μ realizationFailure ≤ εreal)
    (hgraph : AdversarialMiMCGraphBound keccak rootHash strategy r μ budget εgraph) :
    finiteProbability μ (aesExecutionBad strategy) ≤ εbind + εreal + εgraph :=
  aesExperiment_failure_budget keccak rootHash strategy r hchar μ budget
    bindingFailure realizationFailure hadmissible hbinding
    (fun ω hr ha => sourceAesCallback_certificate keccak _ _ (hsource ω hr ha))
    εbind εreal εgraph hbindProbability hrealProbability hgraph

end ZolanaVE.Lookup
