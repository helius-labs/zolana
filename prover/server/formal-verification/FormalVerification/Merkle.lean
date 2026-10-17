import «ProvenZk»
import FormalVerification.Circuit
import FormalVerification.Lemmas
import FormalVerification.FullField
import FormalVerification.Poseidon
import FormalVerification.RangeTree
import FormalVerification.Collision
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

@[simp]
lemma ProveParentHash_rw {d : Bool} {h s : F} {k : F → Prop}:
  ZolanaProver.ProveParentHash d.toZMod h s k ↔
    (k $ hashLevel d s h)
  := by
  cases d <;> simp [ZolanaProver.ProveParentHash, Gates, GatesGnark12, GatesGnark9, GatesGnark8, hashLevel]

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

def InclusionCollision (tree : MerkleTree F poseidon₂ SD) (leaf ind : F) (path : List.Vector F SD) : Prop :=
  ∃ hi : ind.val < 2^SD, tree.recoverCollision (Fin.toBitsBE ⟨ind.val, hi⟩) path.reverse leaf

theorem InclusionProof_sound {trees : List.Vector (MerkleTree F poseidon₂ SD) B} {leaves : List.Vector F B}
    {inPathIndices inPathElements k}
    (h : InclusionProof (trees.map (·.root)) leaves inPathIndices inPathElements k) :
    k (trees.map (·.root)) ∧ ∀i (_: i∈[0:B]), leaves[i] ∈ trees[i] ∨
      InclusionCollision trees[i] leaves[i] inPathIndices[i] inPathElements[i] := by
  rw [InclusionProof_rw] at h
  refine ⟨h.1, fun i ir => ?_⟩
  rcases h.2 i ir with ⟨hi, hrec⟩
  simp only [List.Vector.getElem_map] at hrec
  rcases MerkleTree.recoverAtFin_eq_root hrec with ⟨_, hitem⟩ | hcol
  · exact Or.inl ⟨_, hitem.symm⟩
  · exact Or.inr ⟨hi, hcol⟩

theorem InclusionProof_complete {trees : List.Vector (MerkleTree F poseidon₂ SD) B} {leaves : List.Vector F B} {k}
    (hk : k (trees.map (·.root))) (hmem : ∀i (_: i∈[0:B]), leaves[i] ∈ trees[i]) :
    ∃inPathIndices proofs, InclusionProof (trees.map (·.root)) leaves inPathIndices proofs k := by
  have ⟨ind, indhp⟩ := Vector.exists_ofElems.mp fun (i : Fin B) => hmem i.val ⟨by simp, And.intro i.prop (by simp [Nat.mod_one])⟩
  refine ⟨ind.map fun i => (⟨i.val, Nat.lt_trans i.prop (by decide)⟩: F),
    List.Vector.ofFn fun (i : Fin B) => (List.Vector.reverse $ trees[i.val].proofAtFin ind[i]), ?_⟩
  rw [InclusionProof_rw]
  refine ⟨hk, fun i ir => ?_⟩
  use by
    simp only [List.Vector.getElem_map, ZMod.val, Order]
    apply Fin.prop
  have := indhp i ir.2.1
  simp [getElem] at this ⊢
  rw [←this]
  exact MerkleTree.recoverAtFin_proofAtFin_itemAtFin

-- The public input hash: the circuit chains each column, then chains the
-- column hashes — the same compression the SPP transaction circuit applies.
def hashChain : List.Vector F (d + 1) → F := fun v =>
  v.tail.toList.foldl (fun h l => poseidon₂ vec![h, l]) v.head

def foldCollision : {d : Nat} → F → F → List.Vector F d → List.Vector F d → Prop
  | 0, _, _, _, _ => False
  | _ + 1, a₁, a₂, v₁, v₂ =>
    Collision poseidon₂ vec![a₁, v₁.head] vec![a₂, v₂.head] ∨
      foldCollision (poseidon₂ vec![a₁, v₁.head]) (poseidon₂ vec![a₂, v₂.head]) v₁.tail v₂.tail

lemma hashChain_body_eq {d : Nat} {a₁ a₂} {v₁ v₂ : List.Vector F d}
    (h : v₁.toList.foldl (fun h l => poseidon₂ vec![h, l]) a₁ = v₂.toList.foldl (fun h l => poseidon₂ vec![h, l]) a₂) :
    (a₁ = a₂ ∧ v₁ = v₂) ∨ foldCollision a₁ a₂ v₁ v₂ := by
  induction d generalizing a₁ a₂ with
  | zero =>
    cases v₁ using List.Vector.casesOn
    cases v₂ using List.Vector.casesOn
    exact Or.inl ⟨h, rfl⟩
  | succ d ih =>
    cases v₁ using List.Vector.casesOn with | cons x₁ xs₁ =>
    cases v₂ using List.Vector.casesOn with | cons x₂ xs₂ =>
    simp only [List.Vector.toList_cons, List.foldl_cons] at h
    rcases ih h with ⟨hacc, rfl⟩ | hcol
    · rcases eq_or_collision hacc with hin | hcol
      · simp only [List.Vector.eq_cons, and_true] at hin
        exact Or.inl ⟨hin.1, by rw [hin.2]⟩
      · exact Or.inr (Or.inl hcol)
    · exact Or.inr (Or.inr hcol)

def hashChainCollision {d : Nat} (v₁ v₂ : List.Vector F (d + 1)) : Prop :=
  foldCollision v₁.head v₂.head v₁.tail v₂.tail

theorem hashChain_eq {d : Nat} {v₁ v₂ : List.Vector F d.succ} (h : hashChain v₁ = hashChain v₂) :
    v₁ = v₂ ∨ hashChainCollision v₁ v₂ := by
  cases v₁ using List.Vector.casesOn with | cons x₁ xs₁ =>
  cases v₂ using List.Vector.casesOn with | cons x₂ xs₂ =>
  simp only [hashChain, List.Vector.head_cons, List.Vector.tail_cons] at h
  rcases hashChain_body_eq h with ⟨rfl, rfl⟩ | hcol
  · exact Or.inl rfl
  · exact Or.inr hcol

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

def inputHashCollision (l₁ r₁ l₂ r₂ : List.Vector F B) : Prop :=
  Collision poseidon₂ vec![hashChain l₁, hashChain r₁] vec![hashChain l₂, hashChain r₂] ∨
    hashChainCollision l₁ l₂ ∨ hashChainCollision r₁ r₂

theorem inputHash_eq {l₁ r₁ l₂ r₂ : List.Vector F B} (h : inputHash l₁ r₁ = inputHash l₂ r₂) :
    (l₁ = l₂ ∧ r₁ = r₂) ∨ inputHashCollision l₁ r₁ l₂ r₂ := by
  have hpair : ∀ (a b : F), hashChain vec![a, b] = poseidon₂ vec![a, b] := fun _ _ => rfl
  simp only [inputHash, hpair] at h
  rcases eq_or_collision h with hin | hcol
  · simp only [List.Vector.eq_cons, and_true] at hin
    rcases hashChain_eq hin.1 with rfl | hl
    · rcases hashChain_eq hin.2 with rfl | hr
      · exact Or.inl ⟨rfl, rfl⟩
      · exact Or.inr (Or.inr (Or.inr hr))
    · exact Or.inr (Or.inr (Or.inl hl))
  · exact Or.inr (Or.inl hcol)

theorem InclusionCircuit_rw:
    InclusionCircuit h roots leaves inPathIndices inPathElements ↔
    h = inputHash roots leaves ∧
    InclusionProof roots leaves inPathIndices inPathElements (fun _ => True) := by
  unfold InclusionCircuit
  simp only [HashChainGadget_B_rw, HashChainGadget_Two_rw, Gates, GatesGnark8, GatesGnark9, GatesGnark12, GatesDef.eq, inputHash]

theorem InclusionCircuit_sound {ih : F} {trees : List.Vector (MerkleTree F poseidon₂ SD) B} {leaves : List.Vector F B}
    {inPathIndices proofs}
    (h : InclusionCircuit ih (trees.map (·.root)) leaves inPathIndices proofs) :
    ih = inputHash (trees.map (·.root)) leaves ∧ ∀i (_: i∈[0:B]), leaves[i] ∈ trees[i] ∨
      InclusionCollision trees[i] leaves[i] inPathIndices[i] proofs[i] := by
  rw [InclusionCircuit_rw] at h
  exact ⟨h.1, (InclusionProof_sound h.2).2⟩

theorem InclusionCircuit_complete {trees : List.Vector (MerkleTree F poseidon₂ SD) B} {leaves : List.Vector F B}
    (hmem : ∀i (_: i∈[0:B]), leaves[i] ∈ trees[i]) :
    ∃inPathIndices proofs,
      InclusionCircuit (inputHash (trees.map (·.root)) leaves) (trees.map (·.root)) leaves inPathIndices proofs := by
  have ⟨inPathIndices, proofs, hp⟩ := InclusionProof_complete (k := fun _ => True) trivial hmem
  exact ⟨inPathIndices, proofs, InclusionCircuit_rw.mpr ⟨rfl, hp⟩⟩

def NonInclusionCollision (ranges : RangeVector (2^AD)) (lo hi ind : F) (proof : List.Vector F AD) : Prop :=
  ∃ hind : ind.val < 2^AD,
    (rangeTree ranges).recoverCollision (Fin.toBitsBE ⟨ind.val, hind⟩) proof.reverse (poseidon₂ vec![lo, hi]) ∨
      Range.hashCollision lo hi (ranges.ranges ⟨ind.val, hind⟩)

/-- One item of the non-inclusion proof: the low leaf `poseidon₂(lo, hi)` is in
the range tree at the given index, and the value is strictly inside `(lo, hi)`
by the full-field ordering gadget. -/
theorem NonInclusionStep_sound
    {lo hi v ind : F} {proof : List.Vector F AD} {ranges : RangeVector (2^AD)} {k : F → Prop}
    (h : ZolanaProver.Poseidon_2 vec![lo, hi] (0:F) fun r =>
      ∃lv, Gates.to_binary ind AD lv ∧
      AddressMerkleRootGadget r lv proof fun root =>
      Gates.eq root ranges.root ∧ ZolanaProver.AssertStrictlyOrdered lo v hi ∧ k root) :
    k ranges.root ∧ (v.val ∈ ranges ∨ NonInclusionCollision ranges lo hi ind proof) := by
  simp only [Poseidon_2_iff_uniqueAssignment] at h
  rw [AddressInclusionProofStep_rw] at h
  rcases h with ⟨⟨hind, hrec⟩, hord, hk⟩
  rw [AssertStrictlyOrdered_rw] at hord
  refine ⟨hk, ?_⟩
  rcases MerkleTree.recoverAtFin_eq_root (tree := rangeTree ranges) hrec with ⟨_, hleaf⟩ | hcol
  · simp only [rangeTree, MerkleTree.ofFn_itemAtFin] at hleaf
    rcases Range.hashOpt_eq hleaf with ⟨range, hsome, rfl, rfl⟩ | hcol
    · exact Or.inl ⟨⟨ind.val, hind⟩, range, hord, hsome.symm⟩
    · exact Or.inr ⟨hind, Or.inr hcol⟩
  · exact Or.inr ⟨hind, Or.inl hcol⟩

theorem NonInclusionStep_complete
    {v ind : F} {proof : List.Vector F AD} {ranges : RangeVector (2^AD)} {k : F → Prop} {range : Range}
    (hind : ind.val < 2^AD) (hsome : ranges.ranges ⟨ind.val, hind⟩ = some range)
    (hproof : proof.reverse = (rangeTree ranges).proofAtFin ⟨ind.val, hind⟩)
    (hmem : v.val ∈ range) (hk : k ranges.root) :
    ZolanaProver.Poseidon_2 vec![range.lo, range.hi] (0:F) fun r =>
      ∃lv, Gates.to_binary ind AD lv ∧
      AddressMerkleRootGadget r lv proof fun root =>
      Gates.eq root ranges.root ∧ ZolanaProver.AssertStrictlyOrdered range.lo v range.hi ∧ k root := by
  simp only [Poseidon_2_iff_uniqueAssignment]
  rw [AddressInclusionProofStep_rw, AssertStrictlyOrdered_rw]
  refine ⟨⟨hind, ?_⟩, hmem, hk⟩
  have hleaf : poseidon₂ vec![range.lo, range.hi] = (rangeTree ranges).itemAtFin ⟨ind.val, hind⟩ := by
    simp only [rangeTree, MerkleTree.ofFn_itemAtFin, hsome]
    rfl
  rw [hproof, hleaf]
  exact MerkleTree.recoverAtFin_proofAtFin_itemAtFin

def NonInclusionProof_rec {n : Nat} (lo hi leaf inds roots : List.Vector F n) (proofs : List.Vector (List.Vector F AD) n) (k : List.Vector F n → Prop): Prop :=
  match n with
  | 0 => k List.Vector.nil
  | _ + 1 => ZolanaProver.Poseidon_2 vec![lo.head, hi.head] (0:F) fun r =>
    ∃lv, Gates.to_binary inds.head AD lv ∧
    AddressMerkleRootGadget r lv proofs.head fun root =>
    Gates.eq root roots.head ∧
    ZolanaProver.AssertStrictlyOrdered lo.head leaf.head hi.head ∧
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

theorem NonInclusionProof_rec_sound {n : Nat} {trees : List.Vector (RangeVector (2^AD)) n}
    {lo hi leaves inds : List.Vector F n} {proofs : List.Vector (List.Vector F AD) n} {k : List.Vector F n → Prop}
    (h : NonInclusionProof_rec lo hi leaves inds (trees.map (·.root)) proofs k) :
    k (trees.map (·.root)) ∧ ∀i (_: i∈[0:n]), leaves[i].val ∈ trees[i] ∨
      NonInclusionCollision trees[i] lo[i] hi[i] inds[i] proofs[i] := by
  induction n with
  | zero =>
    cases trees using List.Vector.casesOn
    refine ⟨by simpa [NonInclusionProof_rec] using h, fun i ir => ?_⟩
    exact absurd ir.2.1 (Nat.not_lt_zero _)
  | succ n ih =>
    cases lo using List.Vector.casesOn with | cons hlo tlo =>
    cases hi using List.Vector.casesOn with | cons hhi thi =>
    cases leaves using List.Vector.casesOn with | cons hleaf tleaf =>
    cases inds using List.Vector.casesOn with | cons hinds tinds =>
    cases proofs using List.Vector.casesOn with | cons hproof tproof =>
    cases trees using List.Vector.casesOn with | cons htree ttree =>
    -- `simp only`: the default `Poseidon_2_iff_uniqueAssignment` would rewrite
    -- the head out of the shape `NonInclusionStep_sound` expects.
    simp only [NonInclusionProof_rec, List.Vector.head_cons, List.Vector.tail_cons,
      List.Vector.map_cons] at h
    obtain ⟨hk, hstep⟩ := NonInclusionStep_sound h
    obtain ⟨hk, hrest⟩ := ih hk
    refine ⟨by simpa using hk, fun i ir => ?_⟩
    cases i with
    | zero => simpa using hstep
    | succ i =>
      rcases ir with ⟨l, r⟩
      simpa using hrest i ⟨by simp, by simp [Nat.mod_one]; linarith⟩

theorem NonInclusionProof_rec_complete {n : Nat} {trees : List.Vector (RangeVector (2^AD)) n}
    {leaves : List.Vector F n} {k : List.Vector F n → Prop}
    (hk : k (trees.map (·.root))) (hmem : ∀i (_: i∈[0:n]), leaves[i].val ∈ trees[i]) :
    ∃lo hi inds proofs, NonInclusionProof_rec lo hi leaves inds (trees.map (·.root)) proofs k := by
  induction n with
  | zero =>
    cases trees using List.Vector.casesOn
    exact ⟨List.Vector.nil, List.Vector.nil, List.Vector.nil, List.Vector.nil, by simpa [NonInclusionProof_rec] using hk⟩
  | succ n ih =>
    cases trees using List.Vector.casesOn with | cons htree ttree =>
    cases leaves using List.Vector.casesOn with | cons hleaf tleaf =>
    have := ih (trees := ttree) (leaves := tleaf) (k := fun roots => k $ htree.root ::ᵥ roots)
      (by simpa using hk)
      (by
        intro i ir
        have := hmem (i+1) ⟨by simp, by simp [Nat.mod_one]; linarith [ir.2]⟩
        simp at this
        exact this)
    rcases this with ⟨lo, hi, inds, proofs, hp⟩
    have := hmem 0 ⟨by simp, by simp⟩
    simp at this
    rcases this with ⟨ix, r, hmem0, hsome⟩
    have hvix : (ZMod.val (ix.val : F)) = ix.val := by
      rw [ZMod.val_natCast, Nat.mod_eq_of_lt]
      exact Nat.lt_trans ix.prop (by decide)
    have hind : (ZMod.val (ix.val : F)) < 2^AD := by rw [hvix]; exact ix.prop
    refine ⟨r.lo ::ᵥ lo, r.hi ::ᵥ hi, (↑ix.val : F) ::ᵥ inds, ((rangeTree htree).proofAtFin ix).reverse ::ᵥ proofs, ?_⟩
    simp only [NonInclusionProof_rec, List.Vector.head_cons, List.Vector.tail_cons, List.Vector.map_cons]
    refine NonInclusionStep_complete hind ?_ ?_ hmem0 (by simpa using hp)
    · refine Eq.trans (congrArg htree.ranges (Fin.eq_of_val_eq ?_)) hsome.symm
      simpa using hvix
    · simp
      congr 1
      apply Fin.eq_of_val_eq
      simpa using hvix.symm

theorem NonInclusionCircuit_rw:
    NonInclusionCircuit h roots values lo hi inds proofs ↔
    h = inputHash roots values ∧
    NonInclusionProof roots values lo hi inds proofs (fun _ => True) := by
  unfold NonInclusionCircuit
  simp only [HashChainGadget_B_rw, HashChainGadget_Two_rw, Gates, GatesGnark8, GatesGnark9, GatesGnark12, GatesDef.eq, inputHash]

theorem NonInclusionCircuit_sound {ih : F} {trees : List.Vector (RangeVector (2^AD)) B}
    {leaves lo hi inds : List.Vector F B} {proofs : List.Vector (List.Vector F AD) B}
    (h : NonInclusionCircuit ih (trees.map (·.root)) leaves lo hi inds proofs) :
    ih = inputHash (trees.map (·.root)) leaves ∧ ∀i (_: i∈[0:B]), leaves[i].val ∈ trees[i] ∨
      NonInclusionCollision trees[i] lo[i] hi[i] inds[i] proofs[i] := by
  rw [NonInclusionCircuit_rw, ←NonInclusionProof_rec_equiv] at h
  exact ⟨h.1, (NonInclusionProof_rec_sound h.2).2⟩

theorem NonInclusionCircuit_complete {trees : List.Vector (RangeVector (2^AD)) B} {leaves : List.Vector F B}
    (hmem : ∀i (_: i∈[0:B]), leaves[i].val ∈ trees[i]) :
    ∃lo hi inds proofs,
      NonInclusionCircuit (inputHash (trees.map (·.root)) leaves) (trees.map (·.root)) leaves lo hi inds proofs := by
  have ⟨lo, hi, inds, proofs, hp⟩ := NonInclusionProof_rec_complete (k := fun _ => True) trivial hmem
  exact ⟨lo, hi, inds, proofs, NonInclusionCircuit_rw.mpr ⟨rfl, NonInclusionProof_rec_equiv.mp hp⟩⟩
