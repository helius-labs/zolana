import «ProvenZk»
import FormalVerification.Circuit
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

axiom poseidon₂_collisionResistant : CollisionResistant poseidon₂
instance : Fact (CollisionResistant poseidon₂) := ⟨poseidon₂_collisionResistant⟩

axiom poseidon₂_nez : poseidon₂_no_zero_preimage
instance : Fact poseidon₂_no_zero_preimage := ⟨poseidon₂_nez⟩

namespace InclusionCircuit

/-- The inclusion circuit is satisfiable with public input hash `ih` iff every
`leaves[i]` is a leaf of the state tree with root `roots[i]` (and `ih` is the
chained hash of the two public columns). -/
theorem sound_and_complete
  {trees : List.Vector (MerkleTree F poseidon₂ SD) B}
  {leaves : List.Vector F B}:
    (∃ih p₁ p₂, InclusionCircuit ih (trees.map (·.root)) leaves p₁ p₂)
    ↔ ∀i (_: i∈[0:B]), leaves[i] ∈ trees[i]
  := by simp [InclusionCircuit_correct]

/-- The public input hash is determined by the public columns. -/
theorem inputHash_deterministic:
    InclusionCircuit h₁ trees leaves i₁ p₁ ∧
    InclusionCircuit h₂ trees leaves i₂ p₂ →
    h₁ = h₂ := by
  simp only [InclusionCircuit_rw]
  intros
  simp_all

/-- The public input hash binds the public columns: equal hashes imply equal
roots and leaves. -/
theorem inputHash_injective:
    InclusionCircuit h trees₁ leaves₁ i₁ p₁ →
    InclusionCircuit h trees₂ leaves₂ i₂ p₂ →
    trees₁ = trees₂ ∧ leaves₁ = leaves₂ := by
  simp only [InclusionCircuit_rw]
  rintro ⟨h₁, _⟩ ⟨h₂, _⟩
  -- Term-level: `cases h₁` (subst) forces deep whnf through `inputHash`/`poseidon₂`.
  exact inputHash_correct.mp (h₁.symm.trans h₂)

end InclusionCircuit

namespace NonInclusionCircuit

/-- The non-inclusion circuit is satisfiable with public input hash `ih` iff
every `leaves[i]` lies strictly inside a stored range of the nullifier range
vector with root `roots[i]` — i.e. it is provably absent from the tree. -/
theorem sound_and_complete
  {trees : List.Vector (RangeVector (2^AD)) B}
  {leaves : List.Vector F B}:
    (∃ih p₁ p₂ p₃ p₄,
      NonInclusionCircuit ih (trees.map (·.root)) leaves p₁ p₂ p₃ p₄)
    ↔ ∀i (_: i∈[0:B]), leaves[i].val ∈ trees[i]
  := by
    conv => lhs; arg 1; intro ih; rw [NonInclusionCircuit_correct]
    simp

theorem inputHash_deterministic:
    NonInclusionCircuit h₁ trees leaves lo₁ hi₁ i₁ p₁ →
    NonInclusionCircuit h₂ trees leaves lo₂ hi₂ i₂ p₂ →
    h₁ = h₂ := by
  simp only [NonInclusionCircuit_rw]
  rintro ⟨e₁, _⟩ ⟨e₂, _⟩
  exact e₁.trans e₂.symm

theorem inputHash_injective:
    NonInclusionCircuit h trees₁ leaves₁ lo₁ hi₁ i₁ p₁ →
    NonInclusionCircuit h trees₂ leaves₂ lo₂ hi₂ i₂ p₂ →
    trees₁ = trees₂ ∧ leaves₁ = leaves₂ := by
  simp only [NonInclusionCircuit_rw]
  rintro ⟨h₁, _⟩ ⟨h₂, _⟩
  exact inputHash_correct.mp (h₁.symm.trans h₂)

end NonInclusionCircuit

def main : IO Unit := pure ()
