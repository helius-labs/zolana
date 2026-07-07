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
