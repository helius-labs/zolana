import VerifiableEncryption.Kdf.Poseidon.Specification
import VerifiableEncryption.Circuit.Kdf

/-!
Concrete width-three round bridges. The dense matrices come from the frozen
upstream literal tables, independently of the extracted K_* definitions.
The statements quantify over arbitrary state, ARK and sparse coefficients;
they check layer wiring, not the full permutation's round-constant schedule.
-/

namespace ZolanaVE.Kdf.PoseidonSpecification

open PoseidonParameters

variable [Fact (Nat.Prime Order)]

private theorem gate_add (a b : F) : Gates.add a b = a + b := rfl
private theorem gate_mul (a b : F) : Gates.mul a b = a * b := rfl

/-- Explicit three-term column-major product, with independently fixed matrix. -/
def mix3 (matrix : List.Vector (List.Vector ℕ 3) 3)
    (state : List.Vector F 3) : List.Vector F 3 :=
  vec![
    ((matrix.get 0).get 0 : F) * state.get 0 +
      ((matrix.get 1).get 0 : F) * state.get 1 +
      ((matrix.get 2).get 0 : F) * state.get 2,
    ((matrix.get 0).get 1 : F) * state.get 0 +
      ((matrix.get 1).get 1 : F) * state.get 1 +
      ((matrix.get 2).get 1 : F) * state.get 2,
    ((matrix.get 0).get 2 : F) * state.get 0 +
      ((matrix.get 1).get 2 : F) * state.get 1 +
      ((matrix.get 2).get 2 : F) * state.get 2]

def fullRound3 (state ark : List.Vector F 3) : List.Vector F 3 :=
  mix3 m3 vec![sbox (state.get 0) + ark.get 0,
    sbox (state.get 1) + ark.get 1, sbox (state.get 2) + ark.get 2]

def transitionRound3 (state ark : List.Vector F 3) : List.Vector F 3 :=
  mix3 p3 vec![sbox (state.get 0) + ark.get 0,
    sbox (state.get 1) + ark.get 1, sbox (state.get 2) + ark.get 2]

def finalRound3 (state : List.Vector F 3) : List.Vector F 3 :=
  mix3 m3 vec![sbox (state.get 0), sbox (state.get 1), sbox (state.get 2)]

def partialRound3 (state : List.Vector F 3) (ark : F)
    (coeff : List.Vector F 5) : List.Vector F 3 :=
  let head := sbox (state.get 0) + ark
  vec![coeff.get 0 * head + coeff.get 1 * state.get 1 + coeff.get 2 * state.get 2,
    state.get 1 + head * coeff.get 3, state.get 2 + head * coeff.get 4]

/-- The explicit product used by the gate bridges is the mathematical mix. -/
theorem mix3_get (matrix : List.Vector (List.Vector ℕ 3) 3)
    (state : List.Vector F 3) (i : Fin 3) :
    (mix3 matrix state).get i = mix matrix state.get i := by
  fin_cases i <;> simp [mix3, mix, Fin.sum_univ_succ, add_assoc]

theorem partialRound3_get (state : List.Vector F 3) (ark : F)
    (coeff : List.Vector F 5) (i : Fin 3) :
    (partialRound3 state ark coeff).get i =
      sparseMix (t := 2) coeff.get
        (Fin.cases (sbox (state.get 0) + ark) (fun j => state.get j.succ)) i := by
  fin_cases i <;> simp [partialRound3, sparseMix, Fin.sum_univ_succ, add_assoc]

theorem fullRound3_eq_denseRound (state constants : List.Vector F 3) :
    fullRound3 state constants = denseRound m3 state constants := by
  apply List.Vector.ext
  intro i
  simp [fullRound3, denseRound, mix3_get, mix, Fin.sum_univ_succ, add_assoc]

theorem transitionRound3_eq_denseRound (state constants : List.Vector F 3) :
    transitionRound3 state constants = denseRound p3 state constants := by
  apply List.Vector.ext
  intro i
  simp [transitionRound3, denseRound, mix3_get, mix, Fin.sum_univ_succ, add_assoc]

theorem finalRound3_eq_finalDenseRound (state : List.Vector F 3) :
    finalRound3 state = finalDenseRound m3 state := by
  apply List.Vector.ext
  intro i
  simp [finalRound3, finalDenseRound, mix3_get, mix, Fin.sum_univ_succ, add_assoc]

theorem partialRound3_eq_sparseRound (state : List.Vector F 3) (constant : F)
    (coeff : List.Vector F 5) :
    partialRound3 state constant coeff = sparseRound state constant coeff := by
  apply List.Vector.ext
  intro i
  simp [partialRound3_get, sparseRound]

theorem fullRound3_rw (state ark : List.Vector F 3) (k : List.Vector F 3 → Prop) :
    PoseidonFullRound_3_3 state ark k ↔ k (fullRound3 state ark) := by
  unfold PoseidonFullRound_3_3
  simp only [exists_eq_left, gate_mul, gate_add, zero_add, sbox_mul]
  rfl

theorem transitionRound3_rw (state ark : List.Vector F 3)
    (k : List.Vector F 3 → Prop) :
    PoseidonFullRoundP_3_3 state ark k ↔ k (transitionRound3 state ark) := by
  unfold PoseidonFullRoundP_3_3
  simp only [exists_eq_left, gate_mul, gate_add, zero_add, sbox_mul]
  rfl

theorem finalRound3_rw (state : List.Vector F 3) (k : List.Vector F 3 → Prop) :
    PoseidonFinalRound_3 state k ↔ k (finalRound3 state) := by
  unfold PoseidonFinalRound_3
  simp only [exists_eq_left, gate_mul, gate_add, zero_add, sbox_mul]
  rfl

theorem partialRound3_rw (state : List.Vector F 3) (ark : F)
    (coeff : List.Vector F 5) (k : List.Vector F 3 → Prop) :
    PoseidonPartialRound_3_5 state ark coeff k ↔ k (partialRound3 state ark coeff) := by
  unfold PoseidonPartialRound_3_5
  simp only [exists_eq_left, gate_mul, gate_add, zero_add, sbox_mul]
  rfl

/--
The complete two-input schedule is checked against the independent frozen
parameters, including initial ARK, all C/S slices, and coordinate-zero output.
This is an optimized-iden3 specification bridge, not a proof of equivalence
with a separately parameterized unoptimized HADES permutation.
-/
theorem Poseidon_2_spec_rw (input : List.Vector F 2) (k : F → Prop) :
    Poseidon_2 input 0 k ↔ k (poseidon2 input) := by
  unfold Poseidon_2
  simp only [exists_eq_left, fullRound3_rw, transitionRound3_rw,
    partialRound3_rw, finalRound3_rw, gate_add, gate_mul, zero_add]
  apply Iff.of_eq
  congr 1
  -- Compare the finite schedule while keeping state-coordinate layers opaque.
  -- Independent literals on the right must match the extracted literals on
  -- the left; a changed circuit constant cannot change this specification.
  simp [poseidon2, permutation, fullRound, ark, partialRound, initialState,
    fullRound3_eq_denseRound, transitionRound3_eq_denseRound,
    partialRound3_eq_sparseRound, finalRound3_eq_finalDenseRound,
    c3, s3, List.finRange] <;> rfl

end ZolanaVE.Kdf.PoseidonSpecification
