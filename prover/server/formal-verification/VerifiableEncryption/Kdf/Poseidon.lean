import VerifiableEncryption.Circuit.Kdf
import VerifiableEncryption.Kdf.Poseidon.Width3
import VerifiableEncryption.Kdf.Poseidon.Layers
import ProvenZk

/-!
The extracted Poseidon permutations of arity 2, 3, 7 and 8 are functions: each
round gadget assigns its output uniquely, so `Poseidon_n xs 0 k ↔ k (poseidonₙ xs)`.
Determinism is all the key schedule needs; no collision resistance is assumed.
Width-three round assignments below additionally use independent upstream M/P
parameters and mathematical round semantics. All four public hashes use the
independent optimized specification and frozen parameters. Their rewrite
lemmas check the extracted schedules against those independent functions.
-/

set_option linter.unusedSectionVars false

namespace ZolanaVE.Kdf

open ZolanaVE

variable [Fact (Nat.Prime Order)]

def ua_let {β : Type} {e : F} {P : F → (β → Prop) → Prop}
    (h : UniqueAssignment (P e) id) : UniqueAssignment (fun k => ∃g, g = e ∧ P g k) id :=
  ⟨h.val, fun k => by rw [← h.equiv k]; exact propext ⟨fun ⟨_, hg, hk⟩ => hg ▸ hk, fun hk => ⟨_, rfl, hk⟩⟩⟩

macro "round_unique" d:ident : tactic =>
  `(tactic| (unfold $d:ident; repeat refine ua_let ?_
             exact UniqueAssignment.constant _ id))

def fullRound3_ua (S A : List.Vector F 3) :
    UniqueAssignment (PoseidonFullRound_3_3 S A) id :=
  ⟨PoseidonSpecification.fullRound3 S A,
    fun k => propext (PoseidonSpecification.fullRound3_rw S A k)⟩
def fullRoundP3_ua (S A : List.Vector F 3) :
    UniqueAssignment (PoseidonFullRoundP_3_3 S A) id :=
  ⟨PoseidonSpecification.transitionRound3 S A,
    fun k => propext (PoseidonSpecification.transitionRound3_rw S A k)⟩
def partialRound3_ua (St : List.Vector F 3) (A : F) (S : List.Vector F 5) :
    UniqueAssignment (PoseidonPartialRound_3_5 St A S) id :=
  ⟨PoseidonSpecification.partialRound3 St A S,
    fun k => propext (PoseidonSpecification.partialRound3_rw St A S k)⟩
def finalRound3_ua (S : List.Vector F 3) :
    UniqueAssignment (PoseidonFinalRound_3 S) id :=
  ⟨PoseidonSpecification.finalRound3 S,
    fun k => propext (PoseidonSpecification.finalRound3_rw S k)⟩

def fullRound4_ua (S A : List.Vector F 4) :
    UniqueAssignment (PoseidonFullRound_4_4 S A) id := by
  round_unique PoseidonFullRound_4_4
def fullRoundP4_ua (S A : List.Vector F 4) :
    UniqueAssignment (PoseidonFullRoundP_4_4 S A) id := by
  round_unique PoseidonFullRoundP_4_4
def partialRound4_ua (St : List.Vector F 4) (A : F) (S : List.Vector F 7) :
    UniqueAssignment (PoseidonPartialRound_4_7 St A S) id := by
  round_unique PoseidonPartialRound_4_7
def finalRound4_ua (S : List.Vector F 4) :
    UniqueAssignment (PoseidonFinalRound_4 S) id := by
  round_unique PoseidonFinalRound_4

def fullRound8_ua (S A : List.Vector F 8) :
    UniqueAssignment (PoseidonFullRound_8_8 S A) id := by
  round_unique PoseidonFullRound_8_8
def fullRoundP8_ua (S A : List.Vector F 8) :
    UniqueAssignment (PoseidonFullRoundP_8_8 S A) id := by
  round_unique PoseidonFullRoundP_8_8
def partialRound8_ua (St : List.Vector F 8) (A : F) (S : List.Vector F 15) :
    UniqueAssignment (PoseidonPartialRound_8_15 St A S) id := by
  round_unique PoseidonPartialRound_8_15
def finalRound8_ua (S : List.Vector F 8) :
    UniqueAssignment (PoseidonFinalRound_8 S) id := by
  round_unique PoseidonFinalRound_8

def fullRound9_ua (S A : List.Vector F 9) :
    UniqueAssignment (PoseidonFullRound_9_9 S A) id := by
  round_unique PoseidonFullRound_9_9
def fullRoundP9_ua (S A : List.Vector F 9) :
    UniqueAssignment (PoseidonFullRoundP_9_9 S A) id := by
  round_unique PoseidonFullRoundP_9_9
def partialRound9_ua (St : List.Vector F 9) (A : F) (S : List.Vector F 17) :
    UniqueAssignment (PoseidonPartialRound_9_17 St A S) id := by
  round_unique PoseidonPartialRound_9_17
def finalRound9_ua (S : List.Vector F 9) :
    UniqueAssignment (PoseidonFinalRound_9 S) id := by
  round_unique PoseidonFinalRound_9


def poseidon2_ua (inp : List.Vector F 2) (initState : F) :
    UniqueAssignment (Poseidon_2 inp initState) id := by
  unfold Poseidon_2
  iterate 3 refine ua_let ?_
  iterate 3 refine UniqueAssignment.compose (fullRound3_ua _ _) fun _ => ?_
  refine UniqueAssignment.compose (fullRoundP3_ua _ _) fun _ => ?_
  iterate 57 refine UniqueAssignment.compose (partialRound3_ua _ _ _) fun _ => ?_
  iterate 3 refine UniqueAssignment.compose (fullRound3_ua _ _) fun _ => ?_
  refine UniqueAssignment.compose (finalRound3_ua _) fun _ => ?_
  exact UniqueAssignment.constant' _ _ _ rfl

def poseidon3_ua (inp : List.Vector F 3) (initState : F) :
    UniqueAssignment (Poseidon_3 inp initState) id := by
  unfold Poseidon_3
  iterate 4 refine ua_let ?_
  iterate 3 refine UniqueAssignment.compose (fullRound4_ua _ _) fun _ => ?_
  refine UniqueAssignment.compose (fullRoundP4_ua _ _) fun _ => ?_
  iterate 56 refine UniqueAssignment.compose (partialRound4_ua _ _ _) fun _ => ?_
  iterate 3 refine UniqueAssignment.compose (fullRound4_ua _ _) fun _ => ?_
  refine UniqueAssignment.compose (finalRound4_ua _) fun _ => ?_
  exact UniqueAssignment.constant' _ _ _ rfl

def poseidon7_ua (inp : List.Vector F 7) (initState : F) :
    UniqueAssignment (Poseidon_7 inp initState) id := by
  unfold Poseidon_7
  iterate 8 refine ua_let ?_
  iterate 3 refine UniqueAssignment.compose (fullRound8_ua _ _) fun _ => ?_
  refine UniqueAssignment.compose (fullRoundP8_ua _ _) fun _ => ?_
  iterate 64 refine UniqueAssignment.compose (partialRound8_ua _ _ _) fun _ => ?_
  iterate 3 refine UniqueAssignment.compose (fullRound8_ua _ _) fun _ => ?_
  refine UniqueAssignment.compose (finalRound8_ua _) fun _ => ?_
  exact UniqueAssignment.constant' _ _ _ rfl

def poseidon8_ua (inp : List.Vector F 8) (initState : F) :
    UniqueAssignment (Poseidon_8 inp initState) id := by
  unfold Poseidon_8
  iterate 9 refine ua_let ?_
  iterate 3 refine UniqueAssignment.compose (fullRound9_ua _ _) fun _ => ?_
  refine UniqueAssignment.compose (fullRoundP9_ua _ _) fun _ => ?_
  iterate 63 refine UniqueAssignment.compose (partialRound9_ua _ _ _) fun _ => ?_
  iterate 3 refine UniqueAssignment.compose (fullRound9_ua _ _) fun _ => ?_
  refine UniqueAssignment.compose (finalRound9_ua _) fun _ => ?_
  exact UniqueAssignment.constant' _ _ _ rfl

def poseidon₂ (v : List.Vector F 2) : F := PoseidonSpecification.poseidon2 v
def poseidon₃ (v : List.Vector F 3) : F := PoseidonSpecification.poseidon3 v
def poseidon₇ (v : List.Vector F 7) : F := PoseidonSpecification.poseidon7 v
def poseidon₈ (v : List.Vector F 8) : F := PoseidonSpecification.poseidon8 v

theorem Poseidon_2_rw {v : List.Vector F 2} {k : F → Prop} :
    Poseidon_2 v 0 k ↔ k (poseidon₂ v) :=
  PoseidonSpecification.Poseidon_2_spec_rw v k

theorem Poseidon_3_rw {v : List.Vector F 3} {k : F → Prop} :
    Poseidon_3 v 0 k ↔ k (poseidon₃ v) :=
  PoseidonSpecification.Poseidon_3_spec_rw v k

theorem Poseidon_7_rw {v : List.Vector F 7} {k : F → Prop} :
    Poseidon_7 v 0 k ↔ k (poseidon₇ v) :=
  PoseidonSpecification.Poseidon_7_spec_rw v k

theorem Poseidon_8_rw {v : List.Vector F 8} {k : F → Prop} :
    Poseidon_8 v 0 k ↔ k (poseidon₈ v) :=
  PoseidonSpecification.Poseidon_8_spec_rw v k

attribute [irreducible] poseidon₂ poseidon₃ poseidon₇ poseidon₈

/-- Poseidon over an input list, dispatching on the arity the circuits use. -/
def poseidon (xs : List F) : F :=
  if h : xs.length = 2 then poseidon₂ ⟨xs, h⟩
  else if h : xs.length = 3 then poseidon₃ ⟨xs, h⟩
  else if h : xs.length = 7 then poseidon₇ ⟨xs, h⟩
  else if h : xs.length = 8 then poseidon₈ ⟨xs, h⟩
  else 0

end ZolanaVE.Kdf
