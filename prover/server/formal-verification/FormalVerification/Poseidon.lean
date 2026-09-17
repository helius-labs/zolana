import FormalVerification.Circuit
import FormalVerification.Lemmas
import Mathlib
import «ProvenZk»

open ZolanaProver (F Order)

def PoseidonFullRound_3_3_uniqueAssignment (S A : List.Vector F 3):
    UniqueAssignment (ZolanaProver.PoseidonFullRound_3_3 S A) id := UniqueAssignment.mk _ $ by
  simp [ZolanaProver.PoseidonFullRound_3_3]; tauto

def PoseidonFullRoundP_3_3_uniqueAssignment (S A : List.Vector F 3):
    UniqueAssignment (ZolanaProver.PoseidonFullRoundP_3_3 S A) id := UniqueAssignment.mk _ $ by
  simp [ZolanaProver.PoseidonFullRoundP_3_3]; tauto

def PoseidonPartialRound_3_5_uniqueAssignment (St : List.Vector F 3) (A : F) (S : List.Vector F 5):
    UniqueAssignment (ZolanaProver.PoseidonPartialRound_3_5 St A S) id := UniqueAssignment.mk _ $ by
  simp [ZolanaProver.PoseidonPartialRound_3_5]; tauto

def PoseidonFinalRound_3_uniqueAssignment (S : List.Vector F 3):
    UniqueAssignment (ZolanaProver.PoseidonFinalRound_3 S) id := UniqueAssignment.mk _ $ by
  simp [ZolanaProver.PoseidonFinalRound_3]; tauto

set_option maxRecDepth 100000 in
def Poseidon_2_uniqueAssignment (inp : List.Vector F 2) (initState : F):
    UniqueAssignment (ZolanaProver.Poseidon_2 inp initState) id := by
  unfold ZolanaProver.Poseidon_2
  simp only [exists_eq_left]
  iterate 3 refine UniqueAssignment.compose (PoseidonFullRound_3_3_uniqueAssignment _ _) fun _ => ?_
  refine UniqueAssignment.compose (PoseidonFullRoundP_3_3_uniqueAssignment _ _) fun _ => ?_
  iterate 57 refine UniqueAssignment.compose (PoseidonPartialRound_3_5_uniqueAssignment _ _ _) fun _ => ?_
  iterate 3 refine UniqueAssignment.compose (PoseidonFullRound_3_3_uniqueAssignment _ _) fun _ => ?_
  refine UniqueAssignment.compose (PoseidonFinalRound_3_uniqueAssignment _) fun _ => ?_
  exact UniqueAssignment.constant' _ _ _ rfl

def poseidon₂ : Hash F 2 := fun a => (Poseidon_2_uniqueAssignment a 0).val

@[simp]
lemma Poseidon_2_iff_uniqueAssignment {v : List.Vector F 2} {k : F -> Prop}:
    ZolanaProver.Poseidon_2 v (0:F) k ↔ k (poseidon₂ v) := by
  unfold poseidon₂
  apply Iff.of_eq
  rw [(Poseidon_2_uniqueAssignment _ _).equiv]
  rfl

/-!
Poseidon2 (width 2, 6 full and 50 partial rounds, gnark-crypto round keys):
the nullifier tree hash. Extracted from `gadget/poseidon2.go`, one gadget per
round type, so the same round-by-round composition as Poseidon above.
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

/-- `perm(l, r)[1] + r`. -/
def Poseidon2Compress_uniqueAssignment (l r : F):
    UniqueAssignment (ZolanaProver.Poseidon2Compress l r) id := by
  unfold ZolanaProver.Poseidon2Compress
  refine UniqueAssignment.compose (Poseidon2Permutation_2_uniqueAssignment _) fun _ => ?_
  simp only [exists_eq_left]
  exact UniqueAssignment.constant' _ _ _ rfl

/-- The nullifier tree hash: nodes `H(left, right)` and leaves `H(lo, hi)`. -/
def nullifierHash : Hash F 2 := fun a => (Poseidon2Compress_uniqueAssignment a[0] a[1]).val

@[simp]
lemma Poseidon2Compress_iff_uniqueAssignment {l r : F} {k : F -> Prop}:
    ZolanaProver.Poseidon2Compress l r k ↔ k (nullifierHash vec![l, r]) := by
  unfold nullifierHash
  apply Iff.of_eq
  rw [(Poseidon2Compress_uniqueAssignment _ _).equiv]
  rfl
