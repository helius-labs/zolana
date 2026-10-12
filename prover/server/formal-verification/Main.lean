import «ProvenZk»
import FormalVerification.Circuit
import FormalVerification.Lemmas
import FormalVerification.Merkle
import FormalVerification.MerkleSecurity

open ZolanaProver (F)

open ZolanaProver renaming InclusionCircuit_8_8_8_32_8_8_32 → InclusionCircuit,
                           NonInclusionCircuit_8_8_8_8_8_40_8_8_40 → NonInclusionCircuit

abbrev SD := 32
abbrev AD := 40
abbrev B := 8

theorem poseidon₂_testVector :
  poseidon₂ vec![1, 2] = 7853200120776062878684798364095072458815029376092732009249414926327459813530 := by native_decide

namespace InclusionCircuit

/-- Acceptance gives membership or explicit colliding compression inputs. -/
theorem membership_or_collision
  {trees : List.Vector (MerkleTree F poseidon₂ SD) B}
  {leaves indices : List.Vector F B}
  {proofs : List.Vector (List.Vector F SD) B} {ih : F}
  (h : InclusionCircuit ih (trees.map (·.root)) leaves indices proofs) :
    (∀ i : Fin B, leaves.get i ∈ trees.get i) ∨ HashReduction.Collision poseidon₂ := by
  classical
  by_cases hm : ∀ i : Fin B, leaves.get i ∈ trees.get i
  · exact Or.inl hm
  · exact Or.inr (HashReduction.inclusion_collision h (not_forall.mp hm))

/-- The public input hash is determined by the public columns. -/
theorem inputHash_deterministic:
    InclusionCircuit h₁ trees leaves i₁ p₁ ∧
    InclusionCircuit h₂ trees leaves i₂ p₂ →
    h₁ = h₂ := by
  simp only [InclusionCircuit_rw]
  intros
  simp_all

/-- Different accepted public columns with the same hash give a collision. -/
theorem inputHash_binding_collision
    (h₁ : InclusionCircuit h trees₁ leaves₁ i₁ p₁)
    (h₂ : InclusionCircuit h trees₂ leaves₂ i₂ p₂)
    (hne : trees₁ ≠ trees₂ ∨ leaves₁ ≠ leaves₂) :
    HashReduction.Collision poseidon₂ := by
  simp only [InclusionCircuit_rw] at h₁ h₂
  rcases HashReduction.inputHash_correct_or_collision (h₁.1.symm.trans h₂.1) with
    ⟨ht, hl⟩ | hc
  · rcases hne with hn | hn
    · exact False.elim (hn ht)
    · exact False.elim (hn hl)
  · exact hc

end InclusionCircuit

namespace NonInclusionCircuit

/-- Incorrect accepted range membership gives a collision or a zero preimage. -/
theorem membership_or_collision_or_zero
  {trees : List.Vector (RangeVector (2^AD)) B}
  {leaves lo hi indices : List.Vector F B}
  {proofs : List.Vector (List.Vector F AD) B} {ih : F}
  (h : NonInclusionCircuit ih (trees.map (·.root)) leaves lo hi indices proofs) :
    (∀ i : Fin B, (leaves.get i).val ∈ trees.get i) ∨
      HashReduction.Collision poseidon₂ ∨
        ∃ i : Fin B, poseidon₂ vec![lo.get i, hi.get i] = 0 := by
  classical
  by_cases hm : ∀ i : Fin B, (leaves.get i).val ∈ trees.get i
  · exact Or.inl hm
  · exact Or.inr (HashReduction.nonInclusion_collision_or_zero h (not_forall.mp hm))

theorem inputHash_deterministic:
    NonInclusionCircuit h₁ trees leaves lo₁ hi₁ i₁ p₁ →
    NonInclusionCircuit h₂ trees leaves lo₂ hi₂ i₂ p₂ →
    h₁ = h₂ := by
  simp only [NonInclusionCircuit_rw]
  rintro ⟨e₁, _⟩ ⟨e₂, _⟩
  exact e₁.trans e₂.symm

theorem inputHash_binding_collision
    (h₁ : NonInclusionCircuit h trees₁ leaves₁ lo₁ hi₁ i₁ p₁)
    (h₂ : NonInclusionCircuit h trees₂ leaves₂ lo₂ hi₂ i₂ p₂)
    (hne : trees₁ ≠ trees₂ ∨ leaves₁ ≠ leaves₂) :
    HashReduction.Collision poseidon₂ := by
  simp only [NonInclusionCircuit_rw] at h₁ h₂
  rcases HashReduction.inputHash_correct_or_collision (h₁.1.symm.trans h₂.1) with
    ⟨ht, hl⟩ | hc
  · rcases hne with hn | hn
    · exact False.elim (hn ht)
    · exact False.elim (hn hl)
  · exact hc

end NonInclusionCircuit

def main : IO Unit := pure ()
