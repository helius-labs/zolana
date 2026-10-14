import «ProvenZk»
import FormalVerification.Circuit
import FormalVerification.Collision
import FormalVerification.Lemmas
import FormalVerification.Merkle

open ZolanaProver (F)

open ZolanaProver renaming InclusionCircuit_8_8_8_32_8_8_32 → InclusionCircuit,
                           NonInclusionCircuit_8_8_8_8_8_40_8_8_40 → NonInclusionCircuit

abbrev SD := 32
abbrev AD := 40
abbrev B := 8

theorem poseidon₂_testVector :
  poseidon₂ vec![1, 2] = 7853200120776062878684798364095072458815029376092732009249414926327459813530 := by native_decide

/-!
Nothing is assumed about Poseidon: soundness concludes that the claim holds or
the witness exhibits a Poseidon collision (or a preimage of the empty-slot hash
0) between concrete values of the witness and the public trees. The
`#print axioms` pins at the end of this file keep it that way.
-/

namespace InclusionCircuit

/-- A satisfying witness fixes the public input hash to the roots and leaves,
and proves every `leaves[i]` is a leaf of the state tree with root `roots[i]`
unless its Merkle path collides with that tree. -/
theorem sound
  {trees : List.Vector (MerkleTree F poseidon₂ SD) B}
  {leaves : List.Vector F B}:
    InclusionCircuit ih (trees.map (·.root)) leaves inds paths →
    ih = inputHash (trees.map (·.root)) leaves ∧
    ∀i (_: i∈[0:B]), leaves[i] ∈ trees[i] ∨ InclusionCollision trees[i] leaves[i] inds[i] paths[i]
  := InclusionCircuit_sound

/-- Leaves of their state trees always have a witness. -/
theorem complete
  {trees : List.Vector (MerkleTree F poseidon₂ SD) B}
  {leaves : List.Vector F B}:
    (∀i (_: i∈[0:B]), leaves[i] ∈ trees[i]) →
    ∃p₁ p₂, InclusionCircuit (inputHash (trees.map (·.root)) leaves) (trees.map (·.root)) leaves p₁ p₂
  := InclusionCircuit_complete

/-- The public input hash is determined by the public columns. -/
theorem inputHash_deterministic:
    InclusionCircuit h₁ trees leaves i₁ p₁ ∧
    InclusionCircuit h₂ trees leaves i₂ p₂ →
    h₁ = h₂ := by
  simp only [InclusionCircuit_rw]
  intros
  simp_all

/-- The public input hash binds the public columns: equal hashes imply equal
roots and leaves unless the hashes collide. -/
theorem inputHash_binding:
    InclusionCircuit h roots₁ leaves₁ i₁ p₁ →
    InclusionCircuit h roots₂ leaves₂ i₂ p₂ →
    (roots₁ = roots₂ ∧ leaves₁ = leaves₂) ∨ inputHashCollision roots₁ leaves₁ roots₂ leaves₂ := by
  simp only [InclusionCircuit_rw]
  rintro ⟨h₁, _⟩ ⟨h₂, _⟩
  -- Term-level: `cases h₁` (subst) forces deep whnf through `inputHash`/`poseidon₂`.
  exact inputHash_eq (h₁.symm.trans h₂)

end InclusionCircuit

namespace NonInclusionCircuit

/-- A satisfying witness fixes the public input hash to the roots and values,
and proves every `leaves[i]` lies strictly inside a stored range of the
nullifier range vector with root `roots[i]` (so it is absent from the tree),
unless the witness for that value collides with the range tree. -/
theorem sound
  {trees : List.Vector (RangeVector (2^AD)) B}
  {leaves : List.Vector F B}:
    NonInclusionCircuit ih (trees.map (·.root)) leaves lo hi inds paths →
    ih = inputHash (trees.map (·.root)) leaves ∧
    ∀i (_: i∈[0:B]), leaves[i].val ∈ trees[i] ∨
      NonInclusionCollision trees[i] lo[i] hi[i] inds[i] paths[i]
  := NonInclusionCircuit_sound

/-- Values inside stored ranges always have a witness. -/
theorem complete
  {trees : List.Vector (RangeVector (2^AD)) B}
  {leaves : List.Vector F B}:
    (∀i (_: i∈[0:B]), leaves[i].val ∈ trees[i]) →
    ∃p₁ p₂ p₃ p₄,
      NonInclusionCircuit (inputHash (trees.map (·.root)) leaves) (trees.map (·.root)) leaves p₁ p₂ p₃ p₄
  := NonInclusionCircuit_complete

theorem inputHash_deterministic:
    NonInclusionCircuit h₁ trees leaves lo₁ hi₁ i₁ p₁ →
    NonInclusionCircuit h₂ trees leaves lo₂ hi₂ i₂ p₂ →
    h₁ = h₂ := by
  simp only [NonInclusionCircuit_rw]
  rintro ⟨e₁, _⟩ ⟨e₂, _⟩
  exact e₁.trans e₂.symm

theorem inputHash_binding:
    NonInclusionCircuit h roots₁ leaves₁ lo₁ hi₁ i₁ p₁ →
    NonInclusionCircuit h roots₂ leaves₂ lo₂ hi₂ i₂ p₂ →
    (roots₁ = roots₂ ∧ leaves₁ = leaves₂) ∨ inputHashCollision roots₁ leaves₁ roots₂ leaves₂ := by
  simp only [NonInclusionCircuit_rw]
  rintro ⟨h₁, _⟩ ⟨h₂, _⟩
  exact inputHash_eq (h₁.symm.trans h₂)

end NonInclusionCircuit

-- Only Lean's standard axioms and the primality of the BN254 scalar field.
/-- info: 'InclusionCircuit.sound' depends on axioms: [bn254_Fr_prime, propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms InclusionCircuit.sound

/-- info: 'InclusionCircuit.complete' depends on axioms: [bn254_Fr_prime, propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms InclusionCircuit.complete

/-- info: 'InclusionCircuit.inputHash_deterministic' depends on axioms: [bn254_Fr_prime, propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms InclusionCircuit.inputHash_deterministic

/-- info: 'InclusionCircuit.inputHash_binding' depends on axioms: [bn254_Fr_prime, propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms InclusionCircuit.inputHash_binding

/-- info: 'NonInclusionCircuit.sound' depends on axioms: [bn254_Fr_prime, propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms NonInclusionCircuit.sound

/-- info: 'NonInclusionCircuit.complete' depends on axioms: [bn254_Fr_prime, propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms NonInclusionCircuit.complete

/-- info: 'NonInclusionCircuit.inputHash_deterministic' depends on axioms: [bn254_Fr_prime, propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms NonInclusionCircuit.inputHash_deterministic

/-- info: 'NonInclusionCircuit.inputHash_binding' depends on axioms: [bn254_Fr_prime, propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms NonInclusionCircuit.inputHash_binding

def main : IO Unit := pure ()
