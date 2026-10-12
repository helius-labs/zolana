import VerifiableEncryption.Lookup.NativeGates

/-!
Source-shaped programs for the actual custom row and tagged-range builders.
Shared challenge powers are emitted once by successive squarings. Each native
arithmetic result is constrained by `NativeProgram.Satisfies`; the proofs then
derive the exact denominator maps and the raw gate certificate. Commitment
binding, backend interpretation and opaque-call anchors remain separate.
-/

namespace ZolanaVE.Lookup

open scoped Polynomial BigOperators

variable [Fact (Nat.Prime Order)] {n m : ℕ}
variable {K : Type*} [Field K]

def squareRepeated : ℕ → K → (K → NativeProgram K) → NativeProgram K
  | 0, value, next => next value
  | count + 1, value, next => .mul value value (fun squared => squareRepeated count squared next)

theorem squareRepeated_satisfies (count : ℕ) (value : K) (next : K → NativeProgram K) :
    (squareRepeated count value next).Satisfies ↔ (next (value ^ (2 ^ count))).Satisfies := by
  induction count generalizing value with
  | zero => simp [squareRepeated]
  | succ count ih =>
    simp only [squareRepeated, NativeProgram.satisfies_mul, ih]
    have he : (value * value) ^ (2 ^ count) = value ^ (2 ^ (count + 1)) := by
      rw [← pow_two, ← pow_mul, Nat.pow_succ]
      congr 1
      omega
    rw [he]

def sourceColumnWeights : (d : ℕ) → K → ((Fin d → K) → NativeProgram K) → NativeProgram K
  | 0, _, next => next Fin.elim0
  | d + 1, alpha, next => squareRepeated 8 alpha (fun weight =>
      sourceColumnWeights d weight (fun tail => next (Fin.cases weight tail)))

theorem sourceColumnWeights_satisfies (d : ℕ) (alpha : K)
    (next : (Fin d → K) → NativeProgram K) :
    (sourceColumnWeights d alpha next).Satisfies ↔
      (next (fun j => alpha ^ (256 ^ (j.val + 1)))).Satisfies := by
  induction d generalizing alpha with
  | zero =>
    have he : (Fin.elim0 : Fin 0 → K) = (fun j => alpha ^ (256 ^ (j.val + 1))) := by
      funext j; exact Fin.elim0 j
    simp only [sourceColumnWeights, he]
  | succ d ih =>
    simp only [sourceColumnWeights, squareRepeated_satisfies, ih]
    norm_num only [show (2 : ℕ) ^ 8 = 256 by norm_num]
    have he : Fin.cases (alpha ^ 256)
        (fun j : Fin d => (alpha ^ 256) ^ (256 ^ (j.val + 1))) =
        (fun j => alpha ^ (256 ^ (j.val + 1))) := by
      funext j
      refine Fin.cases ?_ (fun i => ?_) j
      · simp
      · change (alpha ^ 256) ^ (256 ^ (i.val + 1)) = alpha ^ (256 ^ (i.val + 1 + 1))
        rw [← pow_mul, Nat.pow_succ]
        congr 1
        omega
    rw [he]

def rowEncodingExpression (weights : Fin 12 → K) (t : LookupTuple K 12) : NativeExpression K :=
  (List.ofFn (fun j => NativeExpression.mul (.input (weights j)) (.input (t.2 j)))).foldl
    NativeExpression.add (.input t.1)

theorem expression_fold_add_value (terms : List (NativeExpression K)) (initial : NativeExpression K) :
    (terms.foldl NativeExpression.add initial).value = initial.value + (terms.map NativeExpression.value).sum := by
  induction terms generalizing initial with
  | nil => simp
  | cons term terms ih =>
    simp only [List.foldl_cons, ih, NativeExpression.value, List.map_cons, List.sum_cons]
    ring

theorem rowEncodingExpression_value (weights : Fin 12 → K) (t : LookupTuple K 12) :
    (rowEncodingExpression weights t).value = t.1 + ∑ j, weights j * t.2 j := by
  rw [rowEncodingExpression, expression_fold_add_value, List.map_ofFn]
  simp only [NativeExpression.value, Function.comp_apply]
  rw [List.sum_ofFn]
  simp only [NativeExpression.value, Function.comp_apply]

def rowDenominatorExpression (challenge : K) (weights : Fin 12 → K)
    (t : LookupTuple K 12) : NativeExpression K :=
  .sub (.input challenge) (rowEncodingExpression weights t)

theorem rowDenominatorExpression_value (challenge : K) (t : LookupTuple K 12) :
    (rowDenominatorExpression challenge (fun j => challenge ^ (256 ^ (j.val + 1))) t).value =
      (separatedDenominator 256 t).eval challenge := by
  change _ = (rowDenominator t.1 t.2).eval challenge
  rw [rowDenominator_eval]
  simp only [rowDenominatorExpression, NativeExpression.value, rowEncodingExpression_value]
  have hs : (∑ j : Fin 12, challenge ^ (256 ^ (j.val + 1)) * t.2 j) =
      ∑ j : Fin 12, t.2 j * challenge ^ (256 ^ (j.val + 1)) :=
    Finset.sum_congr rfl (fun j _ => mul_comm _ _)
  rw [hs, sub_add_eq_sub_sub]

def sourceRowCallback (b : TupleBatch F 12 n m) (challenge : F) : NativeProgram F :=
  sourceColumnWeights 12 challenge (fun weights =>
    nativeLookupCallback b.multiplicity
      (fun i => rowDenominatorExpression challenge weights (b.table i))
      (fun j => rowDenominatorExpression challenge weights (b.query j)))

theorem sourceRowCallback_certificate (b : TupleBatch F 12 n m) (challenge : F)
    (h : (sourceRowCallback b challenge).Satisfies) :
    Nonempty (RawGateTrace (b.asBatch 256) challenge) := by
  rw [sourceRowCallback, sourceColumnWeights_satisfies] at h
  exact nativeLookupCallback_certificate (b.asBatch 256) challenge _ _
    (fun i => rowDenominatorExpression_value challenge (b.table i))
    (fun j => rowDenominatorExpression_value challenge (b.query j)) h

/-- Actual custom row `committedValues` order: table payloads, query indices,
query payloads, candidate counts. Table indices are compile-time constants.
-/
def rowCommittedInputs (b : TupleBatch F 12 n m) : List F :=
  (List.ofFn b.table).flatMap (fun t => List.ofFn t.2) ++
    (List.ofFn (fun j => (b.query j).1) ++
    ((List.ofFn b.query).flatMap (fun t => List.ofFn t.2) ++ List.ofFn b.multiplicity))

def RowBuilderMetadata (b : TupleBatch F 12 n m) : Prop :=
  ∀ i, (b.table i).1 = (i.val : F)

theorem rowTupleBatch_builder_metadata (rows : List.Vector (List.Vector F 12) 16)
    (indices : Fin m → F) (outputs : Fin m → List.Vector F 12) (counts : Fin 16 → F) :
    RowBuilderMetadata (rowTupleBatch rows indices outputs counts) := fun _ => rfl

theorem rowCommittedInputs_table_payload (b : TupleBatch F 12 n m) (i : Fin n) (j : Fin 12) :
    (b.table i).2 j ∈ rowCommittedInputs b := by
  simp only [rowCommittedInputs, List.mem_append]
  left
  exact List.mem_flatMap.mpr ⟨b.table i, (List.mem_ofFn _ _).mpr ⟨i, rfl⟩, (List.mem_ofFn _ _).mpr ⟨j, rfl⟩⟩

theorem rowCommittedInputs_query_index (b : TupleBatch F 12 n m) (j : Fin m) :
    (b.query j).1 ∈ rowCommittedInputs b := by
  simp only [rowCommittedInputs, List.mem_append]
  exact Or.inr (Or.inl ((List.mem_ofFn _ _).mpr ⟨j, rfl⟩))

theorem rowCommittedInputs_query_payload (b : TupleBatch F 12 n m) (j : Fin m) (k : Fin 12) :
    (b.query j).2 k ∈ rowCommittedInputs b := by
  simp only [rowCommittedInputs, List.mem_append]
  exact Or.inr (Or.inr (Or.inl (List.mem_flatMap.mpr
    ⟨b.query j, (List.mem_ofFn _ _).mpr ⟨j, rfl⟩, (List.mem_ofFn _ _).mpr ⟨k, rfl⟩⟩)))

theorem rowCommittedInputs_count (b : TupleBatch F 12 n m) (i : Fin n) :
    b.multiplicity i ∈ rowCommittedInputs b := by
  simp only [rowCommittedInputs, List.mem_append]
  exact Or.inr (Or.inr (Or.inr ((List.mem_ofFn _ _).mpr ⟨i, rfl⟩)))

def canonicalRowBatch (b : TupleBatch F 12 n m) : TupleBatch F 12 n m :=
  { b with table := fun i => ((i.val : F), (b.table i).2) }

theorem canonicalRowBatch_eq (b : TupleBatch F 12 n m) (metadata : RowBuilderMetadata b) :
    canonicalRowBatch b = b := by
  cases b with
  | mk table query multiplicity =>
    have he : (fun i : Fin n => ((i.val : F), (table i).2)) = table := by
      funext i
      exact Prod.ext (metadata i).symm rfl
    simp only [canonicalRowBatch, he]

def sourceRowBuild (b : TupleBatch F 12 n m) : NativeProgram F :=
  .commit (rowCommittedInputs b) (sourceRowCallback (canonicalRowBatch b))

theorem sourceRowBuild_realization (b : TupleBatch F 12 n m) (metadata : RowBuilderMetadata b)
    (h : (sourceRowBuild b).Satisfies) :
    ∃ challenge, Nonempty (RawGateTrace (b.asBatch 256) challenge) := by
  obtain ⟨challenge, hc⟩ := h
  rw [canonicalRowBatch_eq b metadata] at hc
  exact ⟨challenge, sourceRowCallback_certificate b challenge hc⟩

def rangeDenominatorExpression (challenge alpha : K) (t : LookupTuple K 1) : NativeExpression K :=
  .sub (.input challenge) (.add (.input t.1) (.mul (.input alpha) (.input (t.2 0))))

theorem rangeDenominatorExpression_value (challenge : K) (t : LookupTuple K 1) :
    (rangeDenominatorExpression challenge (challenge ^ (2 ^ 20)) t).value =
      (separatedDenominator (2 ^ 20) t).eval challenge := by
  simp only [separatedDenominator, Polynomial.eval_sub, Polynomial.eval_X,
    Polynomial.eval_C, Polynomial.eval_finset_sum, Polynomial.eval_mul, Polynomial.eval_pow,
    Fin.sum_univ_one, Fin.val_zero, zero_add, pow_one,
    rangeDenominatorExpression, NativeExpression.value]
  rw [mul_comm (challenge ^ (2 ^ 20)) (t.2 0), sub_add_eq_sub_sub]

theorem rangeDenominatorExpression_untagged_value (challenge : K) (t : LookupTuple K 1)
    (htag : t.2 0 = 0) :
    (rangeDenominatorExpression challenge challenge t).value =
      (separatedDenominator (2 ^ 20) t).eval challenge := by
  simp only [separatedDenominator, Polynomial.eval_sub, Polynomial.eval_X,
    Polynomial.eval_C, Polynomial.eval_finset_sum, Polynomial.eval_mul, Polynomial.eval_pow,
    Fin.sum_univ_one, Fin.val_zero, zero_add, pow_one,
    rangeDenominatorExpression, NativeExpression.value, htag, zero_mul, mul_zero,
    add_zero, sub_zero]

def sourceRangeCallback (b : TupleBatch F 1 n m) (challenge : F) : NativeProgram F :=
  squareRepeated 20 challenge (fun alpha =>
    nativeLookupCallback b.multiplicity
      (fun i => rangeDenominatorExpression challenge alpha (b.table i))
      (fun j => rangeDenominatorExpression challenge alpha (b.query j)))

theorem sourceRangeCallback_certificate (b : TupleBatch F 1 n m) (challenge : F)
    (h : (sourceRangeCallback b challenge).Satisfies) :
    Nonempty (RawGateTrace (b.asBatch (2 ^ 20)) challenge) := by
  rw [sourceRangeCallback, squareRepeated_satisfies] at h
  exact nativeLookupCallback_certificate (b.asBatch (2 ^ 20)) challenge _ _
    (fun i => rangeDenominatorExpression_value challenge (b.table i))
    (fun j => rangeDenominatorExpression_value challenge (b.query j)) h

/-- `rangecheck.go` omits the twenty squarings when it has no tagged buckets.
Then all tuple tags are compile-time zero; this metadata is separate from
lookup correctness and is used only to identify the emitted denominator.
-/
def sourceRangeCallbackWithTags (hasTags : Bool) (b : TupleBatch F 1 n m)
    (challenge : F) : NativeProgram F :=
  if hasTags then sourceRangeCallback b challenge else
    nativeLookupCallback b.multiplicity
      (fun i => rangeDenominatorExpression challenge challenge (b.table i))
      (fun j => rangeDenominatorExpression challenge challenge (b.query j))

theorem sourceRangeCallbackWithTags_certificate (hasTags : Bool) (b : TupleBatch F 1 n m)
    (challenge : F) (hmetadata : hasTags = false → ∀ t ∈ b.support, t.2 0 = 0)
    (h : (sourceRangeCallbackWithTags hasTags b challenge).Satisfies) :
    Nonempty (RawGateTrace (b.asBatch (2 ^ 20)) challenge) := by
  cases hasTags with
  | true => exact sourceRangeCallback_certificate b challenge h
  | false =>
    have he : ∀ t ∈ b.support,
        (rangeDenominatorExpression challenge challenge t).value =
          (separatedDenominator (2 ^ 20) t).eval challenge := by
      intro t ht
      exact rangeDenominatorExpression_untagged_value challenge t (hmetadata rfl t ht)
    apply nativeLookupCallback_certificate (b.asBatch (2 ^ 20)) challenge _ _ ?_ ?_ h
    · intro i
      exact he (b.table i) (Finset.mem_image.mpr ⟨Sum.inl i, Finset.mem_univ _, rfl⟩)
    · intro j
      exact he (b.query j) (b.query_mem_support j)

def rangeCommittedInputs (mainQueries mainCounts : List F)
    (tagged : List (List F × List F)) : List F :=
  mainQueries ++ (mainCounts ++ tagged.flatMap (fun bucket => bucket.1 ++ bucket.2))

structure RangeBucket where
  width : ℕ
  queries : List F
  counts : Fin (2 ^ width) → F

def RangeBucket.tableRows (bucket : RangeBucket) : List (LookupTuple F 1) :=
  List.ofFn (fun i : Fin (2 ^ bucket.width) => ((i.val : F), fun _ : Fin 1 => (bucket.width : F)))

def RangeBucket.queryRows (bucket : RangeBucket) : List (LookupTuple F 1) :=
  bucket.queries.map (fun value => (value, fun _ : Fin 1 => (bucket.width : F)))

/-- Exact grouping performed before the deferred custom range argument. Dense
tagged buckets occur in increasing width order. Table rows, query tuple tags
and candidate counts are tied to the same flattened batch, not independent
arbitrary commitment lists. The sparse preprocessing is anchored at its two
main-table query slots by `SmallRangeAnchor.sparse`.
-/
structure RangeBuilderGrouping (b : TupleBatch F 1 n m) where
  mainQueries : List F
  mainCounts : Fin (2 ^ 11) → F
  tagged : List RangeBucket
  widths : ∀ bucket ∈ tagged, 2 ≤ bucket.width ∧ bucket.width < 11
  dense : ∀ bucket ∈ tagged, 2 ^ bucket.width < bucket.queries.length
  ordered : tagged.Pairwise (fun a b => a.width < b.width)
  table_agrees : List.ofFn b.table =
    List.ofFn (fun i : Fin (2 ^ 11) => ((i.val : F), fun _ : Fin 1 => 0)) ++ tagged.flatMap RangeBucket.tableRows
  query_agrees : List.ofFn b.query =
    mainQueries.map (fun value => (value, fun _ : Fin 1 => 0)) ++ tagged.flatMap RangeBucket.queryRows
  counts_agree : List.ofFn b.multiplicity = List.ofFn mainCounts ++ tagged.flatMap (fun bucket => List.ofFn bucket.counts)

def RangeBuilderGrouping.committedInputs {b : TupleBatch F 1 n m} (grouping : RangeBuilderGrouping b) : List F :=
  rangeCommittedInputs grouping.mainQueries (List.ofFn grouping.mainCounts)
    (grouping.tagged.map (fun bucket => (bucket.queries, List.ofFn bucket.counts)))

theorem RangeBuilderGrouping.query_committed {b : TupleBatch F 1 n m}
    (grouping : RangeBuilderGrouping b) (j : Fin m) : (b.query j).1 ∈ grouping.committedInputs := by
  have hj : b.query j ∈ List.ofFn b.query := (List.mem_ofFn _ _).mpr ⟨j, rfl⟩
  rw [grouping.query_agrees] at hj
  simp only [RangeBuilderGrouping.committedInputs, rangeCommittedInputs, List.mem_append]
  rcases List.mem_append.mp hj with hmain | htag
  · obtain ⟨value, hv, he⟩ := List.mem_map.mp hmain
    have hvalue := congrArg Prod.fst he
    exact Or.inl (hvalue ▸ hv)
  · obtain ⟨bucket, hb, hrows⟩ := List.mem_flatMap.mp htag
    obtain ⟨value, hv, he⟩ := List.mem_map.mp hrows
    have hvalue := congrArg Prod.fst he
    apply Or.inr
    apply Or.inr
    apply List.mem_flatMap.mpr
    refine ⟨(bucket.queries, List.ofFn bucket.counts), List.mem_map.mpr ⟨bucket, hb, rfl⟩, ?_⟩
    exact List.mem_append_left _ (hvalue ▸ hv)

theorem RangeBuilderGrouping.count_committed {b : TupleBatch F 1 n m}
    (grouping : RangeBuilderGrouping b) (i : Fin n) : b.multiplicity i ∈ grouping.committedInputs := by
  have hi : b.multiplicity i ∈ List.ofFn b.multiplicity := (List.mem_ofFn _ _).mpr ⟨i, rfl⟩
  rw [grouping.counts_agree] at hi
  simp only [RangeBuilderGrouping.committedInputs, rangeCommittedInputs, List.mem_append]
  rcases List.mem_append.mp hi with hmain | htag
  · exact Or.inr (Or.inl hmain)
  · obtain ⟨bucket, hb, hc⟩ := List.mem_flatMap.mp htag
    apply Or.inr
    apply Or.inr
    exact List.mem_flatMap.mpr ⟨(bucket.queries, List.ofFn bucket.counts),
      List.mem_map.mpr ⟨bucket, hb, rfl⟩, List.mem_append_right _ hc⟩

theorem RangeBuilderGrouping.no_tags_metadata {b : TupleBatch F 1 n m}
    (grouping : RangeBuilderGrouping b) (h : (!grouping.tagged.isEmpty) = false) :
    ∀ t ∈ b.support, t.2 0 = 0 := by
  have hnil : grouping.tagged = [] := by
    cases he : grouping.tagged with
    | nil => rfl
    | cons bucket rest => simp [he] at h
  have ht : ∀ i, (b.table i).2 0 = 0 := by
    intro i
    have hi : b.table i ∈ List.ofFn b.table := (List.mem_ofFn _ _).mpr ⟨i, rfl⟩
    rw [grouping.table_agrees, hnil] at hi
    simp only [List.flatMap_nil, List.append_nil] at hi
    obtain ⟨row, he⟩ := (List.mem_ofFn _ _).mp hi
    exact (congrFun (congrArg Prod.snd he) 0).symm
  have hq : ∀ j, (b.query j).2 0 = 0 := by
    intro j
    have hj : b.query j ∈ List.ofFn b.query := (List.mem_ofFn _ _).mpr ⟨j, rfl⟩
    rw [grouping.query_agrees, hnil] at hj
    simp only [List.flatMap_nil, List.append_nil] at hj
    obtain ⟨value, _, he⟩ := List.mem_map.mp hj
    exact (congrFun (congrArg Prod.snd he) 0).symm
  intro t hmem
  obtain ⟨entry, _, he⟩ := Finset.mem_image.mp hmem
  rw [← he]
  cases entry with
  | inl i => exact ht i
  | inr j => exact hq j

def sourceRangeBuild (b : TupleBatch F 1 n m) (grouping : RangeBuilderGrouping b) : NativeProgram F :=
  .commit grouping.committedInputs (sourceRangeCallbackWithTags (!grouping.tagged.isEmpty) b)

theorem sourceRangeBuild_realization (b : TupleBatch F 1 n m) (grouping : RangeBuilderGrouping b)
    (h : (sourceRangeBuild b grouping).Satisfies) :
    ∃ challenge, Nonempty (RawGateTrace (b.asBatch (2 ^ 20)) challenge) := by
  obtain ⟨challenge, hc⟩ := h
  exact ⟨challenge, sourceRangeCallbackWithTags_certificate (!grouping.tagged.isEmpty) b challenge
    grouping.no_tags_metadata hc⟩

def pow5Program (value : F) (next : F → NativeProgram F) : NativeProgram F :=
  .mul value value (fun square => .mul square square (fun fourth => .mul fourth value next))

theorem pow5Program_satisfies (value : F) (next : F → NativeProgram F) :
    (pow5Program value next).Satisfies ↔ (next (value ^ 5)).Satisfies := by
  simp only [pow5Program, NativeProgram.satisfies_mul]
  have he : (value * value) * (value * value) * value = value ^ 5 := by ring
  rw [he]

def mimcRoundProgram (key constant state : F) (next : F → NativeProgram F) : NativeProgram F :=
  .add state key (fun first => .add first constant (fun sum => pow5Program sum next))

theorem mimcRoundProgram_satisfies (key constant state : F) (next : F → NativeProgram F) :
    (mimcRoundProgram key constant state next).Satisfies ↔
      (next (MiMC.round key constant state)).Satisfies := by
  simp [mimcRoundProgram, pow5Program_satisfies, MiMC.round]

def mimcPermutationProgram : List F → F → F → (F → NativeProgram F) → NativeProgram F
  | [], _, state, next => next state
  | constant :: rounds, key, state, next => mimcRoundProgram key constant state
      (fun out => mimcPermutationProgram rounds key out next)

theorem mimcPermutationProgram_satisfies (rounds : List F) (key message : F)
    (next : F → NativeProgram F) :
    (mimcPermutationProgram rounds key message next).Satisfies ↔
      (next (rounds.foldl (fun state constant => MiMC.round key constant state) message)).Satisfies := by
  induction rounds generalizing message with
  | nil => rfl
  | cons constant rounds ih =>
    simp only [mimcPermutationProgram, mimcRoundProgram_satisfies, ih, List.foldl_cons]

def mimcCompressProgram (params : Fin 110 → F) (state message : F)
    (next : F → NativeProgram F) : NativeProgram F :=
  mimcPermutationProgram (List.ofFn params) state message (fun out =>
    .add out state (fun encrypted => .add state encrypted (fun first => .add first message next)))

theorem mimcCompressProgram_satisfies (params : Fin 110 → F) (state message : F)
    (next : F → NativeProgram F) :
    (mimcCompressProgram params state message next).Satisfies ↔
      (next (MiMC.compress params state message)).Satisfies := by
  simp [mimcCompressProgram, mimcPermutationProgram_satisfies, MiMC.compress, MiMC.permutation]

def mimcCoefficientProgram (keccak : MiMC.Hash256) (challenge : F)
    (next : F → NativeProgram F) : NativeProgram F :=
  mimcCompressProgram (MiMC.constants keccak) 0 2 (fun state =>
    mimcCompressProgram (MiMC.constants keccak) state challenge next)

theorem mimcCoefficientProgram_satisfies (keccak : MiMC.Hash256) (challenge : F)
    (next : F → NativeProgram F) :
    (mimcCoefficientProgram keccak challenge next).Satisfies ↔
      (next (MiMC.coefficient keccak challenge)).Satisfies := by
  simp [mimcCoefficientProgram, mimcCompressProgram_satisfies, MiMC.coefficient, MiMC.hash2]

def aesDenominatorExpression (challenge coefficient : F) (t : LookupTuple F 1) : NativeExpression F :=
  .sub (.input challenge) (.add (.input t.1) (.mul (.input coefficient) (.input (t.2 0))))

theorem aesDenominatorExpression_value (keccak : MiMC.Hash256) (challenge : F)
    (t : LookupTuple F 1) :
    (aesDenominatorExpression challenge (MiMC.coefficient keccak challenge) t).value =
      (aesDenominatorPolynomial keccak t).eval challenge := by
  rw [aesDenominatorPolynomial_eval]
  rfl

def sourceAesCallback (keccak : MiMC.Hash256) (b : TupleBatch F 1 n m)
    (challenge : F) : NativeProgram F :=
  mimcCoefficientProgram keccak challenge (fun coefficient =>
    nativeLookupCallback b.multiplicity
      (fun i => aesDenominatorExpression challenge coefficient (b.table i))
      (fun j => aesDenominatorExpression challenge coefficient (b.query j)))

theorem sourceAesCallback_certificate (keccak : MiMC.Hash256) (b : TupleBatch F 1 n m)
    (challenge : F) (h : (sourceAesCallback keccak b challenge).Satisfies) :
    Nonempty (RawGateTrace (aesBatch keccak b) challenge) := by
  rw [sourceAesCallback, mimcCoefficientProgram_satisfies] at h
  exact nativeLookupCallback_certificate (aesBatch keccak b) challenge _ _
    (fun i => aesDenominatorExpression_value keccak challenge (b.table i))
    (fun j => aesDenominatorExpression_value keccak challenge (b.query j)) h

def sourceAesBuild (keccak : MiMC.Hash256) (stage : AesCommitStage n m) : NativeProgram F :=
  .commit (aesCommittedInputs stage) (sourceAesCallback keccak stage.snapshot)

theorem sourceAesBuild_realization (keccak : MiMC.Hash256) (stage : AesCommitStage n m)
    (h : (sourceAesBuild keccak stage).Satisfies) :
    ∃ challenge, Nonempty (RawGateTrace (aesBatch keccak stage.snapshot) challenge) := by
  obtain ⟨challenge, hc⟩ := h
  exact ⟨challenge, sourceAesCallback_certificate keccak stage.snapshot challenge hc⟩

end ZolanaVE.Lookup
