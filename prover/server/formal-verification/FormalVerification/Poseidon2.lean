import FormalVerification.Circuit
import FormalVerification.Lemmas
import Mathlib
import «ProvenZk»

open ZolanaProver (F Order)

/-!
Poseidon2 (width 2, 6 full and 50 partial rounds, gnark-crypto round keys):
the nullifier tree hash. Extracted from `gadget/poseidon2.go`, one gadget per
round type, so the same round-by-round composition as `Poseidon.lean`.
-/

def Poseidon2ExternalRound_2_2_uniqueAssignment (S K : List.Vector F 2):
    UniqueAssignment (ZolanaProver.Poseidon2ExternalRound_2_2 S K) id := UniqueAssignment.mk _ $ by
  simp [ZolanaProver.Poseidon2ExternalRound_2_2]; tauto

def Poseidon2InternalRound_2_uniqueAssignment (S : List.Vector F 2) (K : F):
    UniqueAssignment (ZolanaProver.Poseidon2InternalRound_2 S K) id := UniqueAssignment.mk _ $ by
  simp [ZolanaProver.Poseidon2InternalRound_2]; tauto

set_option maxRecDepth 100000 in
def Poseidon2Permutation_2_uniqueAssignment (S : List.Vector F 2):
    UniqueAssignment (ZolanaProver.Poseidon2Permutation_2 S) id := by
  unfold ZolanaProver.Poseidon2Permutation_2
  simp only [exists_eq_left]
  iterate 3 refine UniqueAssignment.compose (Poseidon2ExternalRound_2_2_uniqueAssignment _ _) fun _ => ?_
  iterate 50 refine UniqueAssignment.compose (Poseidon2InternalRound_2_uniqueAssignment _ _) fun _ => ?_
  iterate 3 refine UniqueAssignment.compose (Poseidon2ExternalRound_2_2_uniqueAssignment _ _) fun _ => ?_
  exact UniqueAssignment.constant' _ _ _ rfl

/-- `perm(l, r)[1] + r`, over the vector so that `nullifierHash` below is a
plain projection and no lemma has to unfold the composition. -/
def Poseidon2Compress_uniqueAssignment (v : List.Vector F 2):
    UniqueAssignment (ZolanaProver.Poseidon2Compress v.head v.tail.head) id := by
  unfold ZolanaProver.Poseidon2Compress
  refine UniqueAssignment.compose (Poseidon2Permutation_2_uniqueAssignment _) fun _ => ?_
  simp only [exists_eq_left]
  exact UniqueAssignment.constant' _ _ _ rfl

/-- The nullifier tree hash: nodes `H(left, right)` and leaves `H(lo, hi)`. -/
def nullifierHash : Hash F 2 := fun v => (Poseidon2Compress_uniqueAssignment v).val

@[simp]
lemma Poseidon2Compress_iff_uniqueAssignment {l r : F} {k : F -> Prop}:
    ZolanaProver.Poseidon2Compress l r k ↔ k (nullifierHash vec![l, r]) := by
  have h := (Poseidon2Compress_uniqueAssignment vec![l, r]).equiv k
  simp only [List.Vector.head_cons, List.Vector.tail_cons, id_eq] at h
  exact Iff.of_eq h
