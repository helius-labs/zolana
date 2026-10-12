import VerifiableEncryption.Lookup.AesGraph

/-!
Per-execution realization and explicit failure budgets. A gate certificate
contains the production table division equations, positive query inverse
equations, and equality of sums. It contains no lookup-membership premise.
Opaque extracted predicates alone cannot produce this certificate: a prover
backend/extraction refinement must establish it for the observed execution,
up to its explicit realization failure probability.

The pre-challenge strategy takes only pre-challenge coins. Its frozen snapshot
is compared with the opened snapshot after the root challenge. Binding and
graph-evaluation assumptions are explicit experiment premises. Oracle records
include both commitment requests and publicly computable MiMC queries; no
comparison to an independent-alpha experiment is performed.
-/

namespace ZolanaVE.Lookup

open scoped Polynomial BigOperators

variable {K : Type*} [Field K] {n m : ℕ}

structure RawGateTrace (b : Batch K n m) (x : K) where
  tableQuotient : Fin n → K
  queryInverse : Fin m → K
  tableEquation : ∀ i, tableQuotient i * (b.table i).eval x = b.multiplicity i
  queryEquation : ∀ j, queryInverse j * (b.query j).eval x = 1
  sumEquation : ∑ i, tableQuotient i = ∑ j, queryInverse j

theorem RawGateTrace.accepted {b : Batch K n m} {x : K} (trace : RawGateTrace b x) :
    Accepted Finset.univ b.denominator b.weight x := by
  refine ⟨Sum.elim trace.tableQuotient (fun j => -trace.queryInverse j), ?_, ?_⟩
  · intro i _
    cases i with
    | inl i => exact trace.tableEquation i
    | inr j =>
      change -trace.queryInverse j * (b.query j).eval x = -1
      rw [neg_mul, trace.queryEquation j]
  · simp only [Fintype.sum_sum_type, Sum.elim_inl, Sum.elim_inr, Finset.sum_neg_distrib]
    rw [trace.sumEquation]
    exact add_neg_cancel _

section FiniteProbability

variable {Ω : Type*} [Fintype Ω]

noncomputable def finiteProbability (μ : Distribution Ω) (event : Ω → Prop) : ℚ := by
  classical
  exact ∑ ω ∈ Finset.univ.filter event, μ.mass ω

noncomputable def stagedLaw {A B C : Type*} [Fintype A] [Fintype B] [Fintype C]
    (pre : Distribution A) (challenge : A → Distribution B)
    (post : A → B → Distribution C) : Distribution (A × B × C) where
  mass := fun ω => pre.mass ω.1 * (challenge ω.1).mass ω.2.1 * (post ω.1 ω.2.1).mass ω.2.2
  nonneg := fun ω => mul_nonneg
    (mul_nonneg (pre.nonneg _) ((challenge _).nonneg _)) ((post _ _).nonneg _)
  normalized := by
    have hi : ∀ a b, (∑ c, pre.mass a * (challenge a).mass b * (post a b).mass c) =
        pre.mass a * (challenge a).mass b := by
      intro a b
      rw [← Finset.mul_sum, (post a b).normalized, mul_one]
    have hc : ∀ a, (∑ b, pre.mass a * (challenge a).mass b) = pre.mass a := by
      intro a
      rw [← Finset.mul_sum, (challenge a).normalized, mul_one]
    simpa only [Fintype.sum_prod_type, hi, hc] using pre.normalized

theorem staged_event_probability_eq {A B C : Type*} [Fintype A] [Fintype B] [Fintype C]
    (pre : Distribution A) (challenge : A → Distribution B)
    (post : A → B → Distribution C) (event : A → B → Prop) :
    finiteProbability (stagedLaw pre challenge post) (fun ω => event ω.1 ω.2.1) =
      ∑ a, pre.mass a * finiteProbability (challenge a) (event a) := by
  classical
  simp only [finiteProbability, stagedLaw, Finset.sum_filter, Fintype.sum_prod_type]
  apply Finset.sum_congr rfl
  intro a _
  rw [Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro b _
  by_cases h : event a b
  · simp only [if_pos h]
    rw [← Finset.mul_sum, (post a b).normalized, mul_one]
  · simp [h]

/-- Post-challenge behavior may depend on the challenge. A uniform bound for
each frozen pre-stage transfers to the joint experiment by a finite mixture.
-/
theorem staged_event_uniform_budget {A B C : Type*} [Fintype A] [Fintype B] [Fintype C]
    (pre : Distribution A) (challenge : A → Distribution B)
    (post : A → B → Distribution C) (event : A → B → Prop) (ε : ℚ)
    (hbudget : ∀ a, finiteProbability (challenge a) (event a) ≤ ε) :
    finiteProbability (stagedLaw pre challenge post) (fun ω => event ω.1 ω.2.1) ≤ ε := by
  rw [staged_event_probability_eq]
  calc
    (∑ a, pre.mass a * finiteProbability (challenge a) (event a)) ≤
        ∑ a, pre.mass a * ε := Finset.sum_le_sum
      (fun a _ => mul_le_mul_of_nonneg_left (hbudget a) (pre.nonneg a))
    _ = (∑ a, pre.mass a) * ε := (Finset.sum_mul _ _ _).symm
    _ = ε := by rw [pre.normalized, one_mul]

theorem finiteProbability_mono (μ : Distribution Ω) (a b : Ω → Prop)
    (hab : ∀ ω, a ω → b ω) : finiteProbability μ a ≤ finiteProbability μ b := by
  classical
  apply Finset.sum_le_sum_of_subset_of_nonneg
  · intro ω hω
    exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, hab ω (Finset.mem_filter.mp hω).2⟩
  · intro ω _ _
    exact μ.nonneg ω

theorem finiteProbability_or_le (μ : Distribution Ω) (a b : Ω → Prop) :
    finiteProbability μ (fun ω => a ω ∨ b ω) ≤ finiteProbability μ a + finiteProbability μ b := by
  classical
  simp only [finiteProbability, Finset.sum_filter]
  rw [← Finset.sum_add_distrib]
  apply Finset.sum_le_sum
  intro ω _
  by_cases ha : a ω <;> by_cases hb : b ω <;>
    simp [ha, hb] <;> linarith [μ.nonneg ω]

theorem finiteProbability_union_le {J : Type*} [Fintype J]
    (μ : Distribution Ω) (events : J → Ω → Prop) :
    finiteProbability μ (fun ω => ∃ j, events j ω) ≤ ∑ j, finiteProbability μ (events j) := by
  classical
  have hp : ∀ ω, (if ∃ j, events j ω then μ.mass ω else 0) ≤
      ∑ j, if events j ω then μ.mass ω else 0 := by
    intro ω
    by_cases h : ∃ j, events j ω
    · have hex := h
      obtain ⟨j, hj⟩ := h
      simp only [if_pos hex]
      have hs := Finset.single_le_sum
        (f := fun i => if events i ω then μ.mass ω else 0)
        (fun i (_ : i ∈ Finset.univ) => by
          dsimp only
          split_ifs <;> linarith [μ.nonneg ω])
        (Finset.mem_univ j)
      simpa only [if_pos hj] using hs
    · have hn : ∀ j, ¬ events j ω := fun j hj => h ⟨j, hj⟩
      simp [h, hn]
  simp only [finiteProbability, Finset.sum_filter]
  rw [← Finset.sum_comm]
  apply Finset.sum_le_sum
  intro ω _
  by_cases hex : ∃ j, events j ω
  · simpa only [if_pos hex] using hp ω
  · simpa only [if_neg hex] using hp ω

/-- A union budget needs no independence assumption between callbacks. -/
theorem finiteProbability_union_budget {J : Type*} [Fintype J]
    (μ : Distribution Ω) (events : J → Ω → Prop) (budgets : J → ℚ)
    (hb : ∀ j, finiteProbability μ (events j) ≤ budgets j) :
    finiteProbability μ (fun ω => ∃ j, events j ω) ≤ ∑ j, budgets j :=
  le_trans (finiteProbability_union_le μ events) (Finset.sum_le_sum (fun j _ => hb j))

theorem finiteProbability_three_failure_budget (μ : Distribution Ω)
    (bad binding realization graph : Ω → Prop) (εbind εreal εgraph : ℚ)
    (hreduce : ∀ ω, bad ω → binding ω ∨ realization ω ∨ graph ω)
    (hbind : finiteProbability μ binding ≤ εbind)
    (hreal : finiteProbability μ realization ≤ εreal)
    (hgraph : finiteProbability μ graph ≤ εgraph) :
    finiteProbability μ bad ≤ εbind + εreal + εgraph := by
  have h₁ := finiteProbability_mono μ bad (fun ω => binding ω ∨ realization ω ∨ graph ω) hreduce
  have h₂ := finiteProbability_or_le μ binding (fun ω => realization ω ∨ graph ω)
  have h₃ := finiteProbability_or_le μ realization graph
  linarith

/-- One shared binding/realization budget plus the sum of all callback
algebra/graph budgets. Callback failures may be arbitrarily correlated.
-/
theorem overall_lookup_failure_budget {J : Type*} [Fintype J]
    (μ : Distribution Ω) (bad binding realization : Ω → Prop)
    (callbackFailure : J → Ω → Prop) (εbind εreal : ℚ) (budgets : J → ℚ)
    (hreduce : ∀ ω, bad ω → binding ω ∨ realization ω ∨ ∃ j, callbackFailure j ω)
    (hbind : finiteProbability μ binding ≤ εbind)
    (hreal : finiteProbability μ realization ≤ εreal)
    (hcallbacks : ∀ j, finiteProbability μ (callbackFailure j) ≤ budgets j) :
    finiteProbability μ bad ≤ εbind + εreal + ∑ j, budgets j :=
  finiteProbability_three_failure_budget μ bad binding realization
    (fun ω => ∃ j, callbackFailure j ω) εbind εreal (∑ j, budgets j)
    hreduce hbind hreal (finiteProbability_union_budget μ callbackFailure budgets hcallbacks)

end FiniteProbability

section AesExperiment

variable [Fact (Nat.Prime Order)]

/-- Actual radix batches chosen before conditional challenge sampling. The
point-mass premise applies to each frozen pre-stage law, so adaptive
post-challenge coins introduce no unproved independence assumption. Conditioning
on a selected cached grinding query can violate a small point-mass cap; such a
reduction must apply per first query/candidate and use an attempt union budget.
-/
theorem radix_staged_acceptance_budget {A C : Type*} [Fintype A] [Fintype C] {d : ℕ}
    (B D : ℕ) (b : A → TupleBatch F d n m) (hsize : n + m < B) (hchar : m < Order)
    (hbad : ∀ a, ∃ j : Fin m, ∀ i, (b a).table i ≠ (b a).query j)
    (hdegree : ∀ a t, t ∈ (b a).support → (separatedDenominator B t).natDegree ≤ D)
    (pre : Distribution A) (challenge : A → Distribution F)
    (post : A → F → Distribution C) (cap : ℚ) (hcap : 0 ≤ cap)
    (hpoint : ∀ a x, (challenge a).mass x ≤ cap) (r : ℕ) (hr : 0 < r) :
    finiteProbability (stagedLaw pre challenge post)
      (fun ω => Accepted Finset.univ ((b ω.1).asBatch B).denominator
        ((b ω.1).asBatch B).weight (ω.2.1 ^ r)) ≤
      (((n + m - 1) * D : ℕ) : ℚ) * ((r : ℚ) * cap) := by
  apply staged_event_uniform_budget pre challenge post
    (fun a root => Accepted Finset.univ ((b a).asBatch B).denominator
      ((b a).asBatch B).weight (root ^ r))
  intro a
  obtain ⟨j, hj⟩ := hbad a
  have hb := invalid_tuple_acceptance_mass_callback_le B D (b a) hsize hchar j hj
    (hdegree a) (challenge a) cap hcap (hpoint a) r hr
  rw [pushforward_eventMass_eq] at hb
  exact hb

inductive OracleRecord where
  | commitment (input : List F) (challengePreimage : List MiMC.Byte) (answer : F)
  | mimc (input : List F) (answer : F)

structure OracleBudget where
  commitmentRequests : ℕ
  mimcEvaluations : ℕ

def oracleLogWithin (budget : OracleBudget) (log : List OracleRecord) : Prop :=
  (log.filter (fun record => match record with | .commitment _ _ _ => true | _ => false)).length ≤
      budget.commitmentRequests ∧
  (log.map (fun record => match record with | .mimc messages _ => messages.length | _ => 0)).sum ≤
      budget.mimcEvaluations

def mimcLogConsistent (keccak : MiMC.Hash256) (log : List OracleRecord) : Prop :=
  ∀ input answer, OracleRecord.mimc input answer ∈ log → answer = MiMC.hash (MiMC.constants keccak) input

/-- The configured backend challenge hash is a separate explicit source
parameter. Commitment inputs are *not* its hash preimage: the latter contains
the serialized commitment and backend public/previous-commitment data.
-/
def commitmentLogConsistent (rootHash : List MiMC.Byte → F) (log : List OracleRecord) : Prop :=
  ∀ input preimage answer, OracleRecord.commitment input preimage answer ∈ log →
    answer = rootHash preimage

def nativeFieldBytes (value : F) : List.Vector MiMC.Byte 32 :=
  List.Vector.ofFn (fun i => ⟨value.val / 256 ^ (31 - i.val) % 256, Nat.mod_lt _ (by norm_num)⟩)

/-- Groth16 BN254 `SerializeCommitment`: the 64-byte uncompressed commitment
encoding followed by canonical 32-byte big-endian public/previous-commitment
field values. The actual point encoding and frontend public/private wire
selection still need backend realization; the concatenation is explicit.
-/
def serializedCommitment (point : List.Vector MiMC.Byte 64) (publicValues : List F) : List MiMC.Byte :=
  point.toList ++ publicValues.flatMap (fun value => (nativeFieldBytes value).toList)

/-- Both prover and verifier take at most the first 32 bytes from the
configured hash digest and reduce them into Fr. The configured digest
implementation remains an explicit source parameter.
-/
def configuredRootHash (digest : List MiMC.Byte → List MiMC.Byte) (preimage : List MiMC.Byte) : F :=
  (MiMC.bytesBE ((digest preimage).take 32) : F)

/-- Frozen pre-challenge values. Query indices, returned values and arbitrary
table multiplicities are part of this snapshot, as in gnark `toCommit`.
Constant table contents are compile-time metadata; variable contents also
need commitment coverage in the source refinement.
-/
structure AesCommitStage (n m : ℕ) where
  snapshot : TupleBatch F 1 n m
  constantTable : Bool
  commitmentPoint : List.Vector MiMC.Byte 64
  publicCommittedValues : List F
  prefixLog : List OracleRecord

def AesCommitStage.challengePreimage (stage : AesCommitStage n m) : List MiMC.Byte :=
  serializedCommitment stage.commitmentPoint stage.publicCommittedValues

/-- Exact `logderivarg.Build` argument order before frontend commitment
canonicalization: optional variable table pairs, all query pairs, all counts.
Constant entries skipped by the frontend remain compile-time metadata and
must agree with the circuit in the realization certificate.
-/
def aesCommittedInputs (stage : AesCommitStage n m) : List F :=
  let table := (List.ofFn stage.snapshot.table).flatMap (fun t => [t.1, t.2 0])
  let queries := (List.ofFn stage.snapshot.query).flatMap (fun t => [t.1, t.2 0])
  (if stage.constantTable then [] else table) ++ queries ++ List.ofFn stage.snapshot.multiplicity

structure AesOpenStage (n m : ℕ) where
  opened : TupleBatch F 1 n m
  suffixLog : List OracleRecord
  accepted : Bool

variable {PreCoins PostCoins : Type*} [Fintype PreCoins] [Fintype PostCoins]

/-- The root is absent from the pre-challenge strategy's arguments. The
distribution may model correlated adaptive oracle/grinding behavior; the
theorems do not infer independence from the staged type alone. All relevant
local public MiMC evaluations must be included by an algorithm-model
refinement when imposing an oracle budget.
-/
structure AesStrategy (n m : ℕ) where
  commit : PreCoins → AesCommitStage n m
  openWitness : AesCommitStage n m → F → PostCoins → AesOpenStage n m

abbrev AesSample (PreCoins PostCoins : Type*) := PreCoins × F × PostCoins

def committed (strategy : AesStrategy (PreCoins := PreCoins) (PostCoins := PostCoins) n m)
    (ω : AesSample PreCoins PostCoins) : AesCommitStage n m := strategy.commit ω.1

def opened (strategy : AesStrategy (PreCoins := PreCoins) (PostCoins := PostCoins) n m)
    (ω : AesSample PreCoins PostCoins) : AesOpenStage n m :=
  strategy.openWitness (committed strategy ω) ω.2.1 ω.2.2

/-- The commitment request is placed at the stage boundary, after the frozen
input list and before post-challenge oracle access. Its answer is exactly the
root subsequently raised to the callback power.
-/
def aesExperimentLog (strategy : AesStrategy (PreCoins := PreCoins) (PostCoins := PostCoins) n m)
    (ω : AesSample PreCoins PostCoins) : List OracleRecord :=
  (committed strategy ω).prefixLog ++
    [OracleRecord.commitment (aesCommittedInputs (committed strategy ω))
      (committed strategy ω).challengePreimage ω.2.1] ++
      (opened strategy ω).suffixLog

def aesExecutionBad (strategy : AesStrategy (PreCoins := PreCoins) (PostCoins := PostCoins) n m)
    (ω : AesSample PreCoins PostCoins) : Prop :=
  (opened strategy ω).accepted = true ∧
    ∃ j, ∀ i, (opened strategy ω).opened.table i ≠ (opened strategy ω).opened.query j

def aesExecutionGraphZero (keccak : MiMC.Hash256)
    (strategy : AesStrategy (PreCoins := PreCoins) (PostCoins := PostCoins) n m) (r : ℕ)
    (ω : AesSample PreCoins PostCoins) : Prop :=
  aesGraphZero keccak (committed strategy ω).snapshot r ω.2.1

def aesExperimentAdmissible (keccak : MiMC.Hash256) (rootHash : List MiMC.Byte → F)
    (strategy : AesStrategy (PreCoins := PreCoins) (PostCoins := PostCoins) n m)
    (r : ℕ) (μ : Distribution (AesSample PreCoins PostCoins)) (budget : OracleBudget) : Prop :=
  0 < r ∧
    (∀ ω, μ.mass ω ≠ 0 → oracleLogWithin budget (aesExperimentLog strategy ω)) ∧
    (∀ ω, μ.mass ω ≠ 0 → mimcLogConsistent keccak (aesExperimentLog strategy ω)) ∧
    (∀ ω, μ.mass ω ≠ 0 → commitmentLogConsistent rootHash (aesExperimentLog strategy ω))

/-- Explicit cryptographic assumption for the actual graph and the actual
strategy/coin law with its transcript budget. No theorem here supplies this
assumption from MiMC's arithmetic definition. In particular it is not a
claim of closeness to an independent-uniform `(callback, coefficient)` pair.
-/
def AdversarialMiMCGraphBound (keccak : MiMC.Hash256) (rootHash : List MiMC.Byte → F)
    (strategy : AesStrategy (PreCoins := PreCoins) (PostCoins := PostCoins) n m)
    (r : ℕ) (μ : Distribution (AesSample PreCoins PostCoins)) (budget : OracleBudget)
    (εgraph : ℚ) : Prop :=
  aesExperimentAdmissible keccak rootHash strategy r μ budget →
    finiteProbability μ (aesExecutionGraphZero keccak strategy r) ≤ εgraph

/-- Per-execution binding relates the opened query/count values to those
frozen before the challenge. Gate realization interprets actual source
equations. Neither premise asserts lookup membership. -/
theorem aesExecution_bad_reduces (keccak : MiMC.Hash256)
    (strategy : AesStrategy (PreCoins := PreCoins) (PostCoins := PostCoins) n m)
    (r : ℕ) (hchar : m < Order) (ω : AesSample PreCoins PostCoins)
    (hbind : (opened strategy ω).opened = (committed strategy ω).snapshot)
    (hreal : (opened strategy ω).accepted = true →
      Nonempty (RawGateTrace (aesBatch keccak (opened strategy ω).opened) (ω.2.1 ^ r)))
    (hbad : aesExecutionBad strategy ω) : aesExecutionGraphZero keccak strategy r ω := by
  obtain ⟨ha, j, hj⟩ := hbad
  obtain ⟨trace⟩ := hreal ha
  rw [hbind] at trace hj
  exact ⟨invalid_aes_multivariate_residual_ne_zero _ hchar j hj,
    aes_accepted_graph_zero keccak _ _ trace.accepted⟩

/-- The per-execution good event establishes only this execution's recorded
tuple memberships. It does not create a universal `LookupAssumptions` value.
-/
theorem good_aesExecution_queries (keccak : MiMC.Hash256)
    (strategy : AesStrategy (PreCoins := PreCoins) (PostCoins := PostCoins) n m)
    (r : ℕ) (hchar : m < Order) (ω : AesSample PreCoins PostCoins)
    (hbind : (opened strategy ω).opened = (committed strategy ω).snapshot)
    (hreal : (opened strategy ω).accepted = true →
      Nonempty (RawGateTrace (aesBatch keccak (opened strategy ω).opened) (ω.2.1 ^ r)))
    (ha : (opened strategy ω).accepted = true)
    (hgraph : ¬ aesExecutionGraphZero keccak strategy r ω) :
    ∀ j, ∃ i, (opened strategy ω).opened.table i = (opened strategy ω).opened.query j := by
  classical
  by_contra h
  push_neg at h
  exact hgraph (aesExecution_bad_reduces keccak strategy r hchar ω hbind hreal ⟨ha, h⟩)

def indexedAesTupleBatch (table : Fin n → F) (indices values : Fin m → F)
    (counts : Fin n → F) : TupleBatch F 1 n m where
  table := fun i => ((i.val : F), fun _ => table i)
  query := fun j => (indices j, fun _ => values j)
  multiplicity := counts

/-- The tuple equality is obtained on the good event above; this final step
ties its index and output to the exact table graph already used by the AES
semantic relations. It does not assume an output-correctness proposition.
-/
theorem indexedAesTupleBatch_member (table : Fin n → F) (indices values : Fin m → F)
    (counts : Fin n → F) (j : Fin m)
    (h : ∃ i, (indexedAesTupleBatch table indices values counts).table i =
      (indexedAesTupleBatch table indices values counts).query j) :
    (indices j, values j) ∈ indexedTable table := by
  obtain ⟨i, he⟩ := h
  have hi : (i.val : F) = indices j := congrArg Prod.fst he
  have hv : table i = values j := congrFun (congrArg Prod.snd he) 0
  exact Finset.mem_image.mpr ⟨i, Finset.mem_univ _, Prod.ext hi hv⟩

/-- Compile-time table metadata is stated independently from gate/witness
constraints. With that exact metadata, the good execution's recorded index
and output belong to the specified table rather than an arbitrary submitted
table. The table can be instantiated by any of the three AES row accessors.
-/
theorem good_aesExecution_indexed_membership (keccak : MiMC.Hash256)
    (strategy : AesStrategy (PreCoins := PreCoins) (PostCoins := PostCoins) n m)
    (table : Fin n → F) (r : ℕ) (hchar : m < Order) (ω : AesSample PreCoins PostCoins)
    (hmetadata : (committed strategy ω).snapshot.table =
      fun i => ((i.val : F), fun _ : Fin 1 => table i))
    (hbind : (opened strategy ω).opened = (committed strategy ω).snapshot)
    (hreal : (opened strategy ω).accepted = true →
      Nonempty (RawGateTrace (aesBatch keccak (opened strategy ω).opened) (ω.2.1 ^ r)))
    (ha : (opened strategy ω).accepted = true)
    (hgraph : ¬ aesExecutionGraphZero keccak strategy r ω) :
    ∀ j, (((opened strategy ω).opened.query j).1,
      ((opened strategy ω).opened.query j).2 0) ∈ indexedTable table := by
  intro j
  obtain ⟨i, he⟩ := good_aesExecution_queries keccak strategy r hchar ω hbind hreal ha hgraph j
  have ht : (opened strategy ω).opened.table = fun i => ((i.val : F), fun _ : Fin 1 => table i) := by
    rw [hbind, hmetadata]
  rw [ht] at he
  have hi := congrArg Prod.fst he
  have hv := congrFun (congrArg Prod.snd he) 0
  exact Finset.mem_image.mpr ⟨i, Finset.mem_univ _, Prod.ext hi hv⟩

/-- A local extracted-call anchor supplies the actual continuation at its
recorded output. Indexed membership then derives the continuation at the
specified table value; no claim is made about other calls/witnesses.
-/
theorem indexed_call_continuation (table : Fin n → F)
    (index value : F) (k : F → Prop)
    (hmember : (index, value) ∈ indexedTable table) (hcontinuation : k value) :
    ∃ i : Fin n, index = (i.val : F) ∧ k (table i) := by
  obtain ⟨i, hi, hv⟩ := indexedTable_member table index value hmember
  exact ⟨i, hi, hv ▸ hcontinuation⟩

theorem spread_recorded_continuation (index value : F) (k : F → Prop)
    (hmember : (index, value) ∈ spreadTable) (hcontinuation : k value) :
    index.val < 256 ∧ k ((AesTables.spreadBytes.getD index.val 0 : ℕ) : F) := by
  obtain ⟨hi, hv⟩ := spread_member_semantics index value hmember
  exact ⟨hi, hv ▸ hcontinuation⟩

theorem substitution_recorded_continuation (index value : F) (k : F → Prop)
    (hmember : (index, value) ∈ substitutionTable) (hcontinuation : k value) :
    index.val < 1280 ∧ k ((Aes.substitutionAt index.val : ℕ) : F) := by
  obtain ⟨hi, hv⟩ := substitution_member_semantics index value hmember
  exact ⟨hi, hv ▸ hcontinuation⟩

theorem chunk_recorded_continuation (index value : F) (k : F → Prop)
    (hmember : (index, value) ∈ chunkTable) (hcontinuation : k value) :
    index.val < 1296 ∧ k ((AesTables.chunkParity.getD index.val 0 : ℕ) : F) := by
  obtain ⟨hi, hv⟩ := chunk_member_semantics index value hmember
  exact ⟨hi, hv ▸ hcontinuation⟩

/-- Security assumptions are explicit experiment premises: binding/extraction
failure, backend/trace realization failure, and actual MiMC graph-root
probability. The graph premise ranges over the strategy's adaptive transcripts
and frozen snapshots under this same law, not independent alpha samples.
Resource/log consistency is a premise of the chosen experiment and does not
by itself prove any of these cryptographic bounds.
-/
theorem aesExperiment_failure_budget (keccak : MiMC.Hash256) (rootHash : List MiMC.Byte → F)
    (strategy : AesStrategy (PreCoins := PreCoins) (PostCoins := PostCoins) n m)
    (r : ℕ) (hchar : m < Order)
    (μ : Distribution (AesSample PreCoins PostCoins)) (budget : OracleBudget)
    (bindingFailure realizationFailure : AesSample PreCoins PostCoins → Prop)
    (hadmissible : aesExperimentAdmissible keccak rootHash strategy r μ budget)
    (hbinding : ∀ ω, ¬ bindingFailure ω →
      (opened strategy ω).opened = (committed strategy ω).snapshot)
    (hrealization : ∀ ω, ¬ realizationFailure ω → (opened strategy ω).accepted = true →
      Nonempty (RawGateTrace (aesBatch keccak (opened strategy ω).opened) (ω.2.1 ^ r)))
    (εbind εreal εgraph : ℚ)
    (hbindProbability : finiteProbability μ bindingFailure ≤ εbind)
    (hrealProbability : finiteProbability μ realizationFailure ≤ εreal)
    (hgraph : AdversarialMiMCGraphBound keccak rootHash strategy r μ budget εgraph) :
    finiteProbability μ (aesExecutionBad strategy) ≤ εbind + εreal + εgraph := by
  classical
  apply finiteProbability_three_failure_budget μ (aesExecutionBad strategy)
    bindingFailure realizationFailure (aesExecutionGraphZero keccak strategy r)
    εbind εreal εgraph ?_ hbindProbability hrealProbability (hgraph hadmissible)
  intro ω hbad
  by_cases hb : bindingFailure ω
  · exact Or.inl hb
  by_cases hg : realizationFailure ω
  · exact Or.inr (Or.inl hg)
  exact Or.inr (Or.inr (aesExecution_bad_reduces keccak strategy r hchar ω
    (hbinding ω hb) (hrealization ω hg) hbad))

end AesExperiment

end ZolanaVE.Lookup
