import «ProvenZk»
import FormalVerification.Circuit
import FormalVerification.Lemmas
import FormalVerification.FullField
import FormalVerification.Poseidon
import FormalVerification.RangeTree
import Mathlib

open ZolanaProver (F Order Gates)
open ZolanaProver renaming MerkleRootGadget_32_32_32 → StateMerkleRootGadget,
                           MerkleRootGadget_40_40_40 → AddressMerkleRootGadget,
                           InclusionProof_8_8_8_32_8_8_32 → InclusionProof,
                           InclusionCircuit_8_8_8_32_8_8_32 → InclusionCircuit,
                           NonInclusionProof_8_8_8_8_8_40_8_8_40 → NonInclusionProof,
                           NonInclusionCircuit_8_8_8_8_8_40_8_8_40 → NonInclusionCircuit,
                           HashChainGadget_8 → HashChainGadget_B,
                           HashChainGadget_2 → HashChainGadget_Two

private abbrev SD := 32
private abbrev AD := 40
private abbrev B := 8

def hashLevel (d : Bool) (s h : F): F := match d with
| false => poseidon₂ vec![h,s]
| true => poseidon₂ vec![s,h]

theorem hashLevel_def (d : Bool) (s h : F):
  hashLevel d s h = match d with
  | false => poseidon₂ vec![h,s]
  | true => poseidon₂ vec![s,h] := by rfl

@[simp]
lemma ProveParentHash_rw {d : Bool} {h s : F} {k : F → Prop}:
  ZolanaProver.ProveParentHash d.toZMod h s k ↔
    (k $ hashLevel d s h)
  := by
  cases d <;> simp [ZolanaProver.ProveParentHash, Gates, GatesGnark12, GatesGnark9, GatesGnark8, hashLevel]

lemma MerkleTree.recover_succ' {ix : List.Vector Bool (Nat.succ N)} {proof : List.Vector F (Nat.succ N)} :
  MerkleTree.recover poseidon₂ ix proof item = hashLevel ix.head proof.head (MerkleTree.recover poseidon₂ ix.tail proof.tail item) := Eq.refl _

theorem StateMerkleRootGadget_rw {h : F} {i : List.Vector Bool SD} {p : List.Vector F SD} {k : F → Prop}:
    StateMerkleRootGadget h (i.map Bool.toZMod) p k ↔ k (MerkleTree.recover poseidon₂ i.reverse p.reverse h) := by
  unfold StateMerkleRootGadget
  simp only [List.Vector.getElem_map, ProveParentHash_rw]
  rw [←List.Vector.ofFn_get (v:=p), ←List.Vector.ofFn_get (v:=i)]
  rfl

set_option maxRecDepth 10000 in
theorem AddressMerkleRootGadget_rw {h : F} {i : List.Vector Bool AD} {p : List.Vector F AD} {k : F → Prop}:
    AddressMerkleRootGadget h (i.map Bool.toZMod) p k ↔ k (MerkleTree.recover poseidon₂ i.reverse p.reverse h) := by
  unfold AddressMerkleRootGadget
  simp only [List.Vector.getElem_map, ProveParentHash_rw]
  rw [←List.Vector.ofFn_get (v:=p), ←List.Vector.ofFn_get (v:=i)]
  rfl

theorem StateInclusionProofStep_rw {l i e r} {k : F → Prop}:
    (∃b, Gates.to_binary i SD b ∧ StateMerkleRootGadget l b e fun o => Gates.eq o r ∧ k o) ↔
    (∃ (hi : i.val < 2^SD), MerkleTree.recoverAtFin poseidon₂ ⟨i.val, hi⟩ e.reverse l = r) ∧ k r := by
  have : 2^SD < Order := by decide
  simp only [Gates, GatesGnark12, GatesDef.to_binary_12, GatesGnark8, GatesGnark9]
  simp only [←exists_and_right]
  rw [←exists_comm]
  simp only [exists_eq_left, StateMerkleRootGadget_rw, GatesDef.eq, MerkleTree.recoverAtFin, Fin.toBitsLE]
  apply Iff.intro
  · rintro ⟨_, _, _⟩
    simp_all
  · rintro ⟨_, _⟩
    simp_all

theorem AddressInclusionProofStep_rw {l i e r} {k : F → Prop}:
    (∃b, Gates.to_binary i AD b ∧ AddressMerkleRootGadget l b e fun o => Gates.eq o r ∧ k o) ↔
    (∃ (hi : i.val < 2^AD), MerkleTree.recoverAtFin poseidon₂ ⟨i.val, hi⟩ e.reverse l = r) ∧ k r := by
  have : 2^AD < Order := by decide
  simp only [Gates, GatesGnark12, GatesDef.to_binary_12, GatesGnark8, GatesGnark9]
  simp only [←exists_and_right]
  rw [←exists_comm]
  simp only [exists_eq_left, AddressMerkleRootGadget_rw, GatesDef.eq, MerkleTree.recoverAtFin, Fin.toBitsLE]
  apply Iff.intro
  · rintro ⟨_, _, _⟩
    simp_all
  · rintro ⟨_, _⟩
    simp_all

lemma InclusionProof_rw {roots leaves inPathIndices inPathElements k}:
  InclusionProof roots leaves inPathIndices inPathElements k ↔
  k roots ∧
  ∀i (_: i ∈ [0:B]), ∃ (hi : (inPathIndices[i]).val < 2^SD), MerkleTree.recoverAtFin poseidon₂ ⟨(inPathIndices[i]).val, hi⟩ (inPathElements[i]).reverse (leaves[i]) = roots[i] := by
  unfold InclusionProof
  simp_rw [StateInclusionProofStep_rw]
  apply Iff.intro
  . intro hp
    repeat rcases hp with ⟨_, hp⟩
    apply And.intro (by rw [←List.Vector.ofFn_get (v:=roots)]; exact hp)
    intro i ir
    have hir : i ∈ ([0:B].toList) := Std.Range.mem_toList_of_mem ir
    conv at hir => arg 1; simp [Std.Range.toList, Std.Range.toList.go]
    fin_cases hir <;> assumption
  . rintro ⟨hk, hp⟩
    repeat apply And.intro (by apply hp _ ⟨by decide, by decide⟩)
    rw [←List.Vector.ofFn_get (v:=roots)] at hk
    exact hk

theorem InclusionProof_correct [Fact (CollisionResistant poseidon₂)]  {trees : List.Vector (MerkleTree F poseidon₂ SD) B} {leaves : List.Vector F B}:
  (∃inPathIndices proofs, InclusionProof (trees.map (·.root)) leaves inPathIndices proofs k) ↔
  k (trees.map (·.root)) ∧ ∀i (_: i∈[0:B]), leaves[i] ∈ trees[i] := by
  simp [InclusionProof_rw, MerkleTree.recoverAtFin_eq_root_iff_proof_and_item_correct]
  intro
  apply Iff.intro
  . rintro ⟨_, _, hp⟩ i ir
    have := hp i ir
    rcases this with ⟨h, _, hp⟩
    exact Exists.intro _ (Eq.symm hp)
  . intro hp
    have ⟨ind, indhp⟩ := Vector.exists_ofElems.mp fun (i : Fin B) => hp i.val ⟨by simp, And.intro i.prop (by simp [Nat.mod_one])⟩
    use ind.map fun i => (⟨i.val, Nat.lt_trans i.prop (by decide)⟩: F)
    use List.Vector.ofFn fun (i : Fin B) => (List.Vector.reverse $ trees[i.val].proofAtFin ind[i])
    intro i ir
    use by
      simp only [List.Vector.getElem_map, ZMod.val, Order]
      apply Fin.prop
    simp [getElem]
    apply And.intro
    . rfl
    . have := indhp i ir.2.1
      simp [getElem] at this
      rw [←this]
      congr

-- The public input hash: the circuit chains each column, then chains the
-- column hashes — the same compression the SPP transaction circuit applies.
def hashChain : List.Vector F (d + 1) → F := fun v =>
  v.tail.toList.foldl (fun h l => poseidon₂ vec![h, l]) v.head

lemma hashChain_body_inj [Fact (CollisionResistant poseidon₂)] {d : Nat} {a₁ a₂} {v₁ v₂ : List.Vector F d}:
  v₁.toList.foldl (fun h l => poseidon₂ vec![h, l]) a₁ = v₂.toList.foldl (fun h l => poseidon₂ vec![h, l]) a₂ ↔
  a₁ = a₂ ∧ v₁ = v₂ := by
  induction d generalizing a₁ a₂ with
  | zero =>
    cases v₁ using List.Vector.casesOn
    cases v₂ using List.Vector.casesOn
    simp
  | succ d ih =>
    cases v₁ using List.Vector.casesOn
    cases v₂ using List.Vector.casesOn
    simp [ih, List.Vector.eq_cons]
    tauto

theorem hashChain_injective [Fact (CollisionResistant poseidon₂)] {d:Nat} {v₁ v₂ : List.Vector F d.succ}:
  hashChain v₁ = hashChain v₂ ↔ v₁ = v₂ := by
  cases v₁ using List.Vector.casesOn
  cases v₂ using List.Vector.casesOn
  simp [hashChain, hashChain_body_inj, List.Vector.eq_cons]

theorem HashChainGadget_B_rw {v : List.Vector F B} {k : F → Prop}: HashChainGadget_B v k ↔ k (hashChain v) := by
  unfold HashChainGadget_B
  simp only [Poseidon_2_iff_uniqueAssignment]
  rw [←List.Vector.ofFn_get (v:=v)]
  rfl

theorem HashChainGadget_Two_rw {v : List.Vector F 2} {k : F → Prop}: HashChainGadget_Two v k ↔ k (hashChain v) := by
  unfold HashChainGadget_Two
  simp only [Poseidon_2_iff_uniqueAssignment]
  rw [←List.Vector.ofFn_get (v:=v)]
  rfl

def inputHash (l r : List.Vector F B) : F := hashChain vec![hashChain l, hashChain r]

theorem inputHash_correct [Fact (CollisionResistant poseidon₂)] {l₁ r₁ l₂ r₂ : List.Vector F B}:
    inputHash l₁ r₁ = inputHash l₂ r₂ ↔ l₁ = l₂ ∧ r₁ = r₂ := by
  have hpair : ∀ (a b : F), hashChain vec![a, b] = poseidon₂ vec![a, b] := fun _ _ => rfl
  simp only [inputHash, hpair, CollisionResistant_def, List.Vector.eq_cons, and_true]
  simp [hashChain_injective]

theorem InclusionCircuit_rw:
    InclusionCircuit h roots leaves inPathIndices inPathElements ↔
    h = inputHash roots leaves ∧
    InclusionProof roots leaves inPathIndices inPathElements (fun _ => True) := by
  unfold InclusionCircuit
  simp only [HashChainGadget_B_rw, HashChainGadget_Two_rw, Gates, GatesGnark8, GatesGnark9, GatesGnark12, GatesDef.eq, inputHash]

theorem InclusionCircuit_correct [Fact (CollisionResistant poseidon₂)] {ih : F} {trees : List.Vector (MerkleTree F poseidon₂ SD) B} {leaves : List.Vector F B}:
  (∃inPathIndices proofs, InclusionCircuit ih (trees.map (·.root)) leaves inPathIndices proofs) ↔
   ih = (inputHash (trees.map (·.root)) leaves) ∧ ∀i (_: i∈[0:B]), leaves[i] ∈ trees[i] := by
  simp [InclusionCircuit_rw, InclusionProof_correct]

theorem AddressMerkleRootGadget_eq_rw [Fact (CollisionResistant poseidon₂)] {h i : F} {p : List.Vector F AD} {tree : MerkleTree F poseidon₂ AD} {k : F → Prop}:
  (∃gate, Gates.to_binary i AD gate ∧ AddressMerkleRootGadget h gate p (fun r => Gates.eq r tree.root ∧ k r)) ↔ (∃(hi: i.val < 2^AD), h = tree.itemAtFin ⟨i.val, hi⟩ ∧ p.reverse = tree.proofAtFin ⟨i.val, hi⟩) ∧ k tree.root := by
  rw [AddressInclusionProofStep_rw]
  simp [and_comm]

theorem Range.hashOpt_eq_poseidon_iff_is_some {lo hi : F} {r : Option Range} [Fact poseidon₂_no_zero_preimage] [Fact (CollisionResistant poseidon₂)]:
    (Range.hashOpt r = poseidon₂ vec![lo, hi]) ↔ ∃(h:r.isSome), lo = (r.get h).lo ∧ hi = (r.get h).hi := by
  have : poseidon₂_no_zero_preimage := Fact.elim inferInstance
  unfold poseidon₂_no_zero_preimage at this
  apply Iff.intro
  · intro h
    cases r
    · simp only [Range.hashOpt, Option.map, Option.getD] at h
      rw [eq_comm] at h
      have := this _ _ h
      cases this
    · simp only [Range.hashOpt, Option.map, Option.getD, Range.hash, CollisionResistant_def, List.Vector.eq_cons, and_true] at h
      rcases h with ⟨hlo, hhi⟩
      exact ⟨rfl, hlo.symm, hhi.symm⟩
  · rintro ⟨h, rfl, rfl⟩
    cases r
    · cases h
    · rfl

/-- One item of the non-inclusion proof: the low leaf `poseidon₂(lo, hi)` is in
the range tree at the given index, and the value is strictly inside `(lo, hi)`
by the full-field ordering gadget. -/
theorem NonInclusionStep_rw [Fact poseidon₂_no_zero_preimage] [Fact (CollisionResistant poseidon₂)]
    {lo hi v ind : F} {proof : List.Vector F AD} {ranges : RangeVector (2^AD)} {k : F → Prop} :
    (ZolanaProver.Poseidon_2 vec![lo, hi] (0:F) fun r =>
      ∃lv, Gates.to_binary ind AD lv ∧
      AddressMerkleRootGadget r lv proof fun root =>
      Gates.eq root ranges.root ∧ ZolanaProver.AssertStrictlyOrdered (0:F) lo v hi ∧ k root)
    ↔ ∃(range : Range) (hind : ind.val < 2^AD),
        ranges.ranges ⟨ind.val, hind⟩ = some range ∧ lo = range.lo ∧ hi = range.hi ∧
        proof.reverse = (rangeTree ranges).proofAtFin ⟨ind.val, hind⟩ ∧
        v.val ∈ range ∧ k ranges.root := by
  simp only [Poseidon_2_iff_uniqueAssignment, RangeVector.root]
  rw [AddressMerkleRootGadget_eq_rw (tree := rangeTree ranges)]
  simp only [rangeTree, MerkleTree.ofFn_itemAtFin, AssertStrictlyOrdered_zero_rw]
  apply Iff.intro
  · rintro ⟨⟨hind, hhash, hproof⟩, ⟨hlo, hhi⟩, hk⟩
    rw [eq_comm, Range.hashOpt_eq_poseidon_iff_is_some] at hhash
    rcases hhash with ⟨hsome, hloeq, hhieq⟩
    refine ⟨(ranges.ranges ⟨ind.val, hind⟩).get hsome, hind, by simp, hloeq, hhieq, by simpa [rangeTree] using hproof, ?_, hk⟩
    refine ⟨?_, ?_⟩
    · rw [←hloeq]; exact hlo
    · rw [←hhieq]; exact hhi
  · rintro ⟨range, hind, hrget, rfl, rfl, hproof, hmem, hk⟩
    rcases hmem with ⟨hlomem, hhimem⟩
    exact ⟨⟨hind, by rw [hrget]; rfl, by simpa [rangeTree] using hproof⟩, ⟨hlomem, hhimem⟩, hk⟩

def NonInclusionProof_rec {n : Nat} (lo hi leaf inds roots : List.Vector F n) (proofs : List.Vector (List.Vector F AD) n) (k : List.Vector F n → Prop): Prop :=
  match n with
  | 0 => k List.Vector.nil
  | _ + 1 => ZolanaProver.Poseidon_2 vec![lo.head, hi.head] (0:F) fun r =>
    ∃lv, Gates.to_binary inds.head AD lv ∧
    AddressMerkleRootGadget r lv proofs.head fun root =>
    Gates.eq root roots.head ∧
    ZolanaProver.AssertStrictlyOrdered (0:F) lo.head leaf.head hi.head ∧
    NonInclusionProof_rec lo.tail hi.tail leaf.tail inds.tail roots.tail proofs.tail fun rs => k (root ::ᵥ rs)

lemma NonInclusionProof_rec_equiv {lo hi leaf inds roots proofs k}:
  NonInclusionProof_rec lo hi leaf inds roots proofs k ↔
  NonInclusionProof roots leaf lo hi inds proofs k := by
  rw [ ←List.Vector.ofFn_get (v:=roots)
     , ←List.Vector.ofFn_get (v:=lo)
     , ←List.Vector.ofFn_get (v:=hi)
     , ←List.Vector.ofFn_get (v:=leaf)
     , ←List.Vector.ofFn_get (v:=inds)
     , ←List.Vector.ofFn_get (v:=proofs)
     ]
  rfl

theorem NonInclusionCircuit_rec_correct [Fact poseidon₂_no_zero_preimage] [Fact (CollisionResistant poseidon₂)] {n : Nat} {trees : List.Vector (RangeVector (2^AD)) n} {leaves : List.Vector F n} {k : List.Vector F n → Prop}:
  (∃lo hi inds proofs, NonInclusionProof_rec lo hi leaves inds (trees.map (·.root)) proofs k) ↔
  k (trees.map (·.root)) ∧ ∀i (_: i∈[0:n]), leaves[i].val ∈ trees[i] := by
  unfold AD at *
  induction n with
  | zero =>
    cases trees using List.Vector.casesOn
    simp [NonInclusionProof_rec]
    intro _ _ k
    linarith [k.2]
  | succ n ih =>
    apply Iff.intro
    . intro ⟨lo, hi, inds, proofs, hp⟩
      cases lo using List.Vector.casesOn with | cons hlo tlo =>
      cases hi using List.Vector.casesOn with | cons hhi thi =>
      cases leaves using List.Vector.casesOn with | cons hleaf tleaf =>
      cases inds using List.Vector.casesOn with | cons hinds tinds =>
      cases proofs using List.Vector.casesOn with | cons hproof tproof =>
      cases trees using List.Vector.casesOn with | cons htree ttree =>
      -- `simp [NonInclusionStep_rw]` would not fire: the default-simp lemma
      -- `Poseidon_2_iff_uniqueAssignment` rewrites the head first and destroys
      -- the pattern. Unfold one step, then rewrite with the step lemma directly.
      simp only [NonInclusionProof_rec, List.Vector.head_cons, List.Vector.tail_cons,
        List.Vector.map_cons] at hp
      rw [NonInclusionStep_rw] at hp
      rcases hp with ⟨range, hind, hsome, ⟨_⟩, ⟨_⟩, hproof, hmem, hp⟩
      have := ih.mp $ Exists.intro _ $ Exists.intro _ $ Exists.intro _ $ Exists.intro _ hp
      rcases this with ⟨hl, hr⟩
      apply And.intro
      . simpa [*]
      . intro i ir
        cases i with
        | zero =>
          simp [Membership.mem]
          exact ⟨⟨hinds.val, hind⟩, range, hmem, hsome.symm⟩
        | succ i =>
          rcases ir with ⟨l, r⟩
          simp
          exact hr i ⟨by simp, by simp [Nat.mod_one]; linarith⟩
    . intro ⟨hk, hmem⟩
      cases trees using List.Vector.casesOn with | cons htree ttree =>
      cases leaves using List.Vector.casesOn with | cons hleaf tleaf =>
      have := (ih (trees := ttree) (leaves := tleaf) (k := fun roots => k $ htree.root ::ᵥ roots)).mpr $ by
        simp at hk
        apply And.intro hk
        intro i ir
        have := hmem (i+1) ⟨by simp, by simp [Nat.mod_one]; linarith [ir.2]⟩
        simp at this
        exact this
      rcases this with ⟨lo, hi, inds, proofs, hp⟩
      have := hmem 0 ⟨by simp, by simp⟩
      simp at this
      rcases this with ⟨ix, r, hmem0, hsome⟩
      simp only [NonInclusionProof_rec, List.Vector.head_cons, List.Vector.tail_cons, List.Vector.map_cons]
      use r.lo ::ᵥ lo
      use r.hi ::ᵥ hi
      use (↑ix.val : F) ::ᵥ inds
      use ((rangeTree htree).proofAtFin ix).reverse ::ᵥ proofs
      rw [NonInclusionStep_rw]
      use r
      have hvix : (ZMod.val (ix.val : F)) = ix.val := by
        rw [ZMod.val_natCast, Nat.mod_eq_of_lt]
        exact Nat.lt_trans ix.prop (by decide)
      have hind : (ZMod.val (ix.val : F)) < 2^40 := by rw [hvix]; exact ix.prop
      use hind
      refine ⟨?_, rfl, rfl, ?_, hmem0, ?_⟩
      · refine Eq.trans (congrArg htree.ranges (Fin.eq_of_val_eq ?_)) hsome.symm
        simpa using hvix
      · simp
        congr 1
        apply Fin.eq_of_val_eq
        simpa using hvix.symm
      · simpa using hp

theorem NonInclusionCircuit_rw:
    NonInclusionCircuit h roots values lo hi inds proofs ↔
    h = inputHash roots values ∧
    NonInclusionProof roots values lo hi inds proofs (fun _ => True) := by
  unfold NonInclusionCircuit
  simp only [HashChainGadget_B_rw, HashChainGadget_Two_rw, Gates, GatesGnark8, GatesGnark9, GatesGnark12, GatesDef.eq, inputHash]

theorem NonInclusionCircuit_correct [Fact poseidon₂_no_zero_preimage] [Fact (CollisionResistant poseidon₂)] {trees : List.Vector (RangeVector (2^AD)) B} {leaves : List.Vector F B}:
    (∃lo hi inds proofs, NonInclusionCircuit h (trees.map (·.root)) leaves lo hi inds proofs) ↔
    h = inputHash (trees.map (·.root)) leaves ∧ ∀i (_: i∈[0:B]), leaves[i].val ∈ trees[i] := by
  simp only [NonInclusionCircuit_rw, ←NonInclusionProof_rec_equiv]
  apply Iff.intro
  · rintro ⟨lo, hi, inds, proofs, hh, hp⟩
    exact ⟨hh, (NonInclusionCircuit_rec_correct.mp ⟨lo, hi, inds, proofs, hp⟩).2⟩
  · rintro ⟨hh, hp⟩
    have := (NonInclusionCircuit_rec_correct (k := fun _ => True)).mpr ⟨trivial, hp⟩
    rcases this with ⟨lo, hi, inds, proofs, hp⟩
    exact ⟨lo, hi, inds, proofs, hh, hp⟩
