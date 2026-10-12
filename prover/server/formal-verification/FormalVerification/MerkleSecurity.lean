import FormalVerification.Merkle
import FormalVerification.Collision

/-!
Security reductions for the actual extracted predicates. No global injectivity
or no-zero-preimage premise is used. These are deterministic reductions, not a
proof that finding the returned collision or zero preimage is computationally
hard.
-/

open ZolanaProver (F)
open ZolanaProver renaming InclusionCircuit_8_8_8_32_8_8_32 → InclusionCircuit,
                           NonInclusionCircuit_8_8_8_8_8_40_8_8_40 → NonInclusionCircuit

namespace HashReduction

theorem hashChain_correct_or_collision {d : ℕ} {xs ys : List.Vector F (d + 1)}
    (h : hashChain xs = hashChain ys) : xs = ys ∨ Collision poseidon₂ := by
  rcases chain_correct_or_collision h with ⟨hh, ht⟩ | ⟨pair, _, hc⟩
  · left
    rw [← List.Vector.cons_head_tail xs, ← List.Vector.cons_head_tail ys, hh, ht]
  · exact Or.inr ⟨pair.1, pair.2, hc⟩

theorem inputHash_correct_or_collision {l₁ r₁ l₂ r₂ : List.Vector F 8}
    (h : inputHash l₁ r₁ = inputHash l₂ r₂) :
    (l₁ = l₂ ∧ r₁ = r₂) ∨ Collision poseidon₂ := by
  classical
  change poseidon₂ vec![hashChain l₁, hashChain r₁] =
    poseidon₂ vec![hashChain l₂, hashChain r₂] at h
  by_cases he : vec![hashChain l₁, hashChain r₁] = vec![hashChain l₂, hashChain r₂]
  · have hl := congrArg (fun v : List.Vector F 2 => v.get 0) he
    have hr := congrArg (fun v : List.Vector F 2 => v.get 1) he
    rcases hashChain_correct_or_collision hl with hl | hc
    · rcases hashChain_correct_or_collision hr with hr | hc
      · exact Or.inl ⟨hl, hr⟩
      · exact Or.inr hc
    · exact Or.inr hc
  · exact Or.inr ⟨_, _, he, h⟩

/-- A wrong state-tree opening produces a collision along its supplied path. -/
theorem state_opening_collision {tree : MerkleTree F poseidon₂ 32}
    {leaf index : F} {proof : List.Vector F 32}
    (h : ∃ b, ZolanaProver.Gates.to_binary index 32 b ∧
      ZolanaProver.MerkleRootGadget_32_32_32 leaf b proof
        (fun root => ZolanaProver.Gates.eq root tree.root ∧ True))
    (hwrong : ∀ hi : index.val < 2 ^ 32,
      proof.reverse ≠ tree.proofAtFin ⟨index.val, hi⟩ ∨
        leaf ≠ tree.itemAtFin ⟨index.val, hi⟩) :
    ∃ (hi : index.val < 2 ^ 32)
      (pair : List.Vector F 2 × List.Vector F 2),
      pair ∈ recoveryPairs tree (Fin.toBitsBE ⟨index.val, hi⟩) proof.reverse leaf ∧
        pair.1 ≠ pair.2 ∧ poseidon₂ pair.1 = poseidon₂ pair.2 := by
  rcases StateInclusionProofStep_rw.mp h with ⟨⟨hi, hr⟩, _⟩
  rcases recoverAtFin_correct_or_collision hr with ⟨hp, hl⟩ | ⟨pair, hm, hc⟩
  · rcases hwrong hi with hw | hw
    · exact False.elim (hw hp)
    · exact False.elim (hw hl)
  · exact ⟨hi, pair, hm, hc⟩

/-- Incorrect membership accepted by the extracted inclusion circuit. -/
theorem inclusion_collision {trees : List.Vector (MerkleTree F poseidon₂ 32) 8}
    {leaves indices : List.Vector F 8}
    {proofs : List.Vector (List.Vector F 32) 8} {ih : F}
    (h : InclusionCircuit ih (trees.map (·.root)) leaves indices proofs)
    (hwrong : ∃ i : Fin 8, ¬ leaves.get i ∈ trees.get i) :
    Collision poseidon₂ := by
  rcases InclusionCircuit_rw.mp h with ⟨_, hp⟩
  rcases InclusionProof_rw.mp hp with ⟨_, hp⟩
  rcases hwrong with ⟨i, hw⟩
  rcases hp i.val ⟨by simp, i.isLt, by simp⟩ with ⟨hi, hr⟩
  rcases recoverAtFin_correct_or_collision (tree := trees.get i) hr with
    ⟨_, hl⟩ | ⟨pair, _, hc⟩
  · exact False.elim (hw ⟨⟨(indices.get i).val, hi⟩, hl.symm⟩)
  · exact ⟨pair.1, pair.2, hc⟩

/-- The range leaf either opens correctly or exhibits a collision/zero preimage. -/
theorem range_hash_correct_or_collision_or_zero {lo hi : F} {r : Option Range}
    (h : Range.hashOpt r = poseidon₂ vec![lo, hi]) :
    (∃ actual : Range, r = some actual ∧ lo = actual.lo ∧ hi = actual.hi) ∨
      Collision poseidon₂ ∨ poseidon₂ vec![lo, hi] = 0 := by
  classical
  cases r with
  | none => exact Or.inr (Or.inr h.symm)
  | some actual =>
    by_cases he : vec![actual.lo, actual.hi] = vec![lo, hi]
    · left
      have hl := congrArg (fun v : List.Vector F 2 => v.get 0) he
      have hh := congrArg (fun v : List.Vector F 2 => v.get 1) he
      exact ⟨actual, rfl, hl.symm, hh.symm⟩
    · exact Or.inr (Or.inl ⟨_, _, he, h⟩)

/-- An accepted address-tree range step is correct or breaks a hash property. -/
theorem nonInclusionStep_correct_or_collision_or_zero
    {lo hi value index : F} {proof : List.Vector F 40}
    {ranges : RangeVector (2 ^ 40)} {k : F → Prop}
    (h : ZolanaProver.Poseidon_2 vec![lo, hi] (0 : F) fun leaf =>
      ∃ bits, ZolanaProver.Gates.to_binary index 40 bits ∧
      ZolanaProver.MerkleRootGadget_40_40_40 leaf bits proof fun root =>
      ZolanaProver.Gates.eq root ranges.root ∧
        ZolanaProver.AssertStrictlyOrdered lo value hi ∧ k root) :
    (∃ (actual : Range) (hind : index.val < 2 ^ 40),
      ranges.ranges ⟨index.val, hind⟩ = some actual ∧ lo = actual.lo ∧ hi = actual.hi ∧
      proof.reverse = (rangeTree ranges).proofAtFin ⟨index.val, hind⟩ ∧
      value.val ∈ actual ∧ k ranges.root) ∨
      Collision poseidon₂ ∨ poseidon₂ vec![lo, hi] = 0 := by
  rw [Poseidon_2_iff_uniqueAssignment, AddressInclusionProofStep_rw] at h
  rcases h with ⟨⟨hind, hr⟩, horder, hk⟩
  rcases recoverAtFin_correct_or_collision (tree := rangeTree ranges) hr with
    ⟨hp, hl⟩ | ⟨pair, _, hc⟩
  · have hleaf : Range.hashOpt (ranges.ranges ⟨index.val, hind⟩) =
        poseidon₂ vec![lo, hi] := by
      simpa only [rangeTree, MerkleTree.ofFn_itemAtFin] using hl.symm
    rcases range_hash_correct_or_collision_or_zero hleaf with
      ⟨actual, ha, hlo, hhi⟩ | hc
    · left
      refine ⟨actual, hind, ha, hlo, hhi, hp, ?_, hk⟩
      rw [AssertStrictlyOrdered_rw] at horder
      simpa only [Membership.mem, hlo, hhi] using horder
    · exact Or.inr hc
  · exact Or.inr (Or.inl ⟨pair.1, pair.2, hc⟩)

/-- Compose the range-step reduction through the extracted recursive batch. -/
theorem nonInclusionProof_correct_or_collision_or_zero {n : ℕ}
    {trees : List.Vector (RangeVector (2 ^ 40)) n}
    {leaves lo hi indices : List.Vector F n}
    {proofs : List.Vector (List.Vector F 40) n} {k : List.Vector F n → Prop}
    (h : NonInclusionProof_rec lo hi leaves indices (trees.map (·.root)) proofs k) :
    (k (trees.map (·.root)) ∧ ∀ i : Fin n, (leaves.get i).val ∈ trees.get i) ∨
      Collision poseidon₂ ∨
        ∃ i : Fin n, poseidon₂ vec![lo.get i, hi.get i] = 0 := by
  induction n with
  | zero =>
    cases trees using List.Vector.casesOn
    exact Or.inl ⟨h, fun i => Fin.elim0 i⟩
  | succ n ih =>
    cases trees using List.Vector.casesOn with
    | cons tree trees =>
      cases leaves using List.Vector.casesOn with
      | cons leaf leaves =>
        cases lo using List.Vector.casesOn with
        | cons low lo =>
          cases hi using List.Vector.casesOn with
          | cons high hi =>
            cases indices using List.Vector.casesOn with
            | cons index indices =>
              cases proofs using List.Vector.casesOn with
              | cons proof proofs =>
                rcases nonInclusionStep_correct_or_collision_or_zero h with
                  ⟨actual, hind, hr, hlo, hhi, hp, hmem, ht⟩ | hc | hz
                · rcases ih ht with ⟨hk, hm⟩ | hc | ⟨i, hz⟩
                  · left
                    refine ⟨hk, ?_⟩
                    intro i
                    refine Fin.cases ?_ (fun j => ?_) i
                    · exact ⟨⟨index.val, hind⟩, actual, hmem, hr.symm⟩
                    · exact hm j
                  · exact Or.inr (Or.inl hc)
                  · exact Or.inr (Or.inr ⟨i.succ, hz⟩)
                · exact Or.inr (Or.inl hc)
                · exact Or.inr (Or.inr ⟨0, hz⟩)

/-- An incorrect range-membership claim accepted by the extracted circuit. -/
theorem nonInclusion_collision_or_zero
    {trees : List.Vector (RangeVector (2 ^ 40)) 8}
    {leaves lo hi indices : List.Vector F 8}
    {proofs : List.Vector (List.Vector F 40) 8} {ih : F}
    (h : NonInclusionCircuit ih (trees.map (·.root)) leaves lo hi indices proofs)
    (hwrong : ∃ i : Fin 8, ¬ (leaves.get i).val ∈ trees.get i) :
    Collision poseidon₂ ∨
      ∃ i : Fin 8, poseidon₂ vec![lo.get i, hi.get i] = 0 := by
  rcases NonInclusionCircuit_rw.mp h with ⟨_, hp⟩
  rw [← NonInclusionProof_rec_equiv] at hp
  rcases nonInclusionProof_correct_or_collision_or_zero hp with ⟨_, hm⟩ | hc
  · rcases hwrong with ⟨i, hw⟩
    exact False.elim (hw (hm i))
  · exact hc

end HashReduction
