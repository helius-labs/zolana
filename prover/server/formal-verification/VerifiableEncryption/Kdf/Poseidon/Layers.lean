import VerifiableEncryption.Kdf.Poseidon.Specification
import VerifiableEncryption.Circuit.Kdf

/-!
Round bridges for the remaining extracted widths. The semantic operations are
finite sums over independently frozen matrices and x^5; no extracted evaluator
is used to define their values. Each matrix coefficient and wire is checked
in the width-specific proofs below.
-/

namespace ZolanaVE.Kdf.PoseidonSpecification

open PoseidonParameters

variable [Fact (Nat.Prime Order)]

private theorem gate_add (a b : F) : Gates.add a b = a + b := rfl
private theorem gate_mul (a b : F) : Gates.mul a b = a * b := rfl

theorem fullRound4_rw (state constants : List.Vector F 4)
    (k : List.Vector F 4 → Prop) :
    PoseidonFullRound_4_4 state constants k ↔ k (denseRound m4 state constants) := by
  unfold PoseidonFullRound_4_4
  simp only [exists_eq_left, gate_mul, gate_add, zero_add, sbox_mul]
  apply Iff.of_eq
  apply congrArg k
  apply List.Vector.ext
  intro i
  fin_cases i <;> simp [denseRound, mix, m4, Fin.sum_univ_succ, add_assoc] <;> rfl

theorem transitionRound4_rw (state constants : List.Vector F 4)
    (k : List.Vector F 4 → Prop) :
    PoseidonFullRoundP_4_4 state constants k ↔ k (denseRound p4 state constants) := by
  unfold PoseidonFullRoundP_4_4
  simp only [exists_eq_left, gate_mul, gate_add, zero_add, sbox_mul]
  apply Iff.of_eq
  apply congrArg k
  apply List.Vector.ext
  intro i
  fin_cases i <;> simp [denseRound, mix, p4, Fin.sum_univ_succ, add_assoc] <;> rfl

theorem finalRound4_rw (state : List.Vector F 4) (k : List.Vector F 4 → Prop) :
    PoseidonFinalRound_4 state k ↔ k (finalDenseRound m4 state) := by
  unfold PoseidonFinalRound_4
  simp only [exists_eq_left, gate_mul, gate_add, zero_add, sbox_mul]
  apply Iff.of_eq
  apply congrArg k
  apply List.Vector.ext
  intro i
  fin_cases i <;> simp [finalDenseRound, mix, m4, Fin.sum_univ_succ, add_assoc] <;> rfl

theorem partialRound4_rw (state : List.Vector F 4) (constant : F)
    (coeff : List.Vector F 7) (k : List.Vector F 4 → Prop) :
    PoseidonPartialRound_4_7 state constant coeff k ↔ k (sparseRound state constant coeff) := by
  unfold PoseidonPartialRound_4_7
  simp only [exists_eq_left, gate_mul, gate_add, zero_add, sbox_mul]
  apply Iff.of_eq
  apply congrArg k
  apply List.Vector.ext
  intro i
  fin_cases i <;> simp [sparseRound, sparseMix, Fin.sum_univ_succ, add_assoc] <;> rfl

theorem fullRound8_rw (state constants : List.Vector F 8)
    (k : List.Vector F 8 → Prop) :
    PoseidonFullRound_8_8 state constants k ↔ k (denseRound m8 state constants) := by
  unfold PoseidonFullRound_8_8
  simp only [exists_eq_left, gate_mul, gate_add, zero_add, sbox_mul]
  apply Iff.of_eq
  apply congrArg k
  apply List.Vector.ext
  intro i
  fin_cases i <;> simp [denseRound, mix, m8, Fin.sum_univ_succ, add_assoc] <;> rfl

theorem transitionRound8_rw (state constants : List.Vector F 8)
    (k : List.Vector F 8 → Prop) :
    PoseidonFullRoundP_8_8 state constants k ↔ k (denseRound p8 state constants) := by
  unfold PoseidonFullRoundP_8_8
  simp only [exists_eq_left, gate_mul, gate_add, zero_add, sbox_mul]
  apply Iff.of_eq
  apply congrArg k
  apply List.Vector.ext
  intro i
  fin_cases i <;> simp [denseRound, mix, p8, Fin.sum_univ_succ, add_assoc] <;> rfl

theorem finalRound8_rw (state : List.Vector F 8) (k : List.Vector F 8 → Prop) :
    PoseidonFinalRound_8 state k ↔ k (finalDenseRound m8 state) := by
  unfold PoseidonFinalRound_8
  simp only [exists_eq_left, gate_mul, gate_add, zero_add, sbox_mul]
  apply Iff.of_eq
  apply congrArg k
  apply List.Vector.ext
  intro i
  fin_cases i <;> simp [finalDenseRound, mix, m8, Fin.sum_univ_succ, add_assoc] <;> rfl

theorem partialRound8_rw (state : List.Vector F 8) (constant : F)
    (coeff : List.Vector F 15) (k : List.Vector F 8 → Prop) :
    PoseidonPartialRound_8_15 state constant coeff k ↔ k (sparseRound state constant coeff) := by
  unfold PoseidonPartialRound_8_15
  simp only [exists_eq_left, gate_mul, gate_add, zero_add, sbox_mul]
  apply Iff.of_eq
  apply congrArg k
  apply List.Vector.ext
  intro i
  fin_cases i <;> simp [sparseRound, sparseMix, Fin.sum_univ_succ, add_assoc] <;> rfl

theorem fullRound9_rw (state constants : List.Vector F 9)
    (k : List.Vector F 9 → Prop) :
    PoseidonFullRound_9_9 state constants k ↔ k (denseRound m9 state constants) := by
  unfold PoseidonFullRound_9_9
  simp only [exists_eq_left, gate_mul, gate_add, zero_add, sbox_mul]
  apply Iff.of_eq
  apply congrArg k
  apply List.Vector.ext
  intro i
  fin_cases i <;> simp [denseRound, mix, m9, Fin.sum_univ_succ, add_assoc] <;> rfl

theorem transitionRound9_rw (state constants : List.Vector F 9)
    (k : List.Vector F 9 → Prop) :
    PoseidonFullRoundP_9_9 state constants k ↔ k (denseRound p9 state constants) := by
  unfold PoseidonFullRoundP_9_9
  simp only [exists_eq_left, gate_mul, gate_add, zero_add, sbox_mul]
  apply Iff.of_eq
  apply congrArg k
  apply List.Vector.ext
  intro i
  fin_cases i <;> simp [denseRound, mix, p9, Fin.sum_univ_succ, add_assoc] <;> rfl

theorem finalRound9_rw (state : List.Vector F 9) (k : List.Vector F 9 → Prop) :
    PoseidonFinalRound_9 state k ↔ k (finalDenseRound m9 state) := by
  unfold PoseidonFinalRound_9
  simp only [exists_eq_left, gate_mul, gate_add, zero_add, sbox_mul]
  apply Iff.of_eq
  apply congrArg k
  apply List.Vector.ext
  intro i
  fin_cases i <;> simp [finalDenseRound, mix, m9, Fin.sum_univ_succ, add_assoc] <;> rfl

theorem partialRound9_rw (state : List.Vector F 9) (constant : F)
    (coeff : List.Vector F 17) (k : List.Vector F 9 → Prop) :
    PoseidonPartialRound_9_17 state constant coeff k ↔ k (sparseRound state constant coeff) := by
  unfold PoseidonPartialRound_9_17
  simp only [exists_eq_left, gate_mul, gate_add, zero_add, sbox_mul]
  apply Iff.of_eq
  apply congrArg k
  apply List.Vector.ext
  intro i
  fin_cases i <;> simp [sparseRound, sparseMix, Fin.sum_univ_succ, add_assoc] <;> rfl

theorem Poseidon_3_spec_rw (input : List.Vector F 3) (k : F → Prop) :
    Poseidon_3 input 0 k ↔ k (poseidon3 input) := by
  unfold Poseidon_3
  simp only [exists_eq_left, fullRound4_rw, transitionRound4_rw,
    partialRound4_rw, finalRound4_rw, gate_add, gate_mul, zero_add]
  apply Iff.of_eq
  congr 1
  simp [poseidon3, permutation, fullRound, ark, partialRound,
    initialState, c4, s4, List.finRange] <;> rfl

theorem Poseidon_7_spec_rw (input : List.Vector F 7) (k : F → Prop) :
    Poseidon_7 input 0 k ↔ k (poseidon7 input) := by
  unfold Poseidon_7
  simp only [exists_eq_left, fullRound8_rw, transitionRound8_rw,
    partialRound8_rw, finalRound8_rw, gate_add, gate_mul, zero_add]
  apply Iff.of_eq
  congr 1
  simp [poseidon7, permutation, fullRound, ark, partialRound,
    initialState, c8, s8, List.finRange] <;> rfl

theorem Poseidon_8_spec_rw (input : List.Vector F 8) (k : F → Prop) :
    Poseidon_8 input 0 k ↔ k (poseidon8 input) := by
  unfold Poseidon_8
  simp only [exists_eq_left, fullRound9_rw, transitionRound9_rw,
    partialRound9_rw, finalRound9_rw, gate_add, gate_mul, zero_add]
  apply Iff.of_eq
  congr 1
  simp [poseidon8, permutation, fullRound, ark, partialRound,
    initialState, c9, s9, List.finRange] <;> rfl

end ZolanaVE.Kdf.PoseidonSpecification
