import VerifiableEncryption.Kdf.Poseidon.Parameters
import Mathlib

/-!
An independent specification of the pinned iden3 optimized permutation.
The state is [capacity, input₀, …], the capacity is zero for hashing, and
the output is coordinate zero. There is no byte encoding or sponge padding.

The schedule has eight x^5 full rounds (3 M, 1 P, 3 M, 1 M with no ARK)
and the width-specific number of sparse partial rounds. Initial ARK precedes
the first full round. Constants have the upstream optimized layout, not the
unoptimized HADES round-constant layout. In particular, replacing P/S by M
while retaining these C constants is NOT an unoptimized reference Poseidon.

This module imports no extracted Poseidon predicate or unique-assignment
evaluator. Its concrete functions fix the intended optimized algorithm and
parameters, but the extracted-to-specification bridge is a separate obligation.
-/

namespace ZolanaVE.Kdf.PoseidonSpecification

open PoseidonParameters

/-- The specification fixes the BN254 scalar modulus as well as its tables. -/
theorem field_modulus :
    Order = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 := rfl

abbrev State (t : ℕ) := Fin t → F

def sbox (x : F) : F := x ^ 5

theorem sbox_mul (x : F) : ((x * x) * (x * x)) * x = sbox x := by
  unfold sbox
  ring

/-- Entries are indexed [input][output], as in upstream's column-major mix. -/
def mix {t : ℕ} (matrix : List.Vector (List.Vector ℕ t) t)
    (state : State t) : State t :=
  fun i => ∑ j : Fin t, ((matrix.get j).get i : F) * state j

def ark {t cLen : ℕ} (constants : List.Vector ℕ cLen) (offset : ℕ)
    (bound : offset + t ≤ cLen) (state : List.Vector F t) : List.Vector F t :=
  List.Vector.ofFn fun i => state.get i + (constants.get ⟨offset + i.val, by omega⟩ : F)

/-- A sparse layer uses the old head for every tail update, not the new head. -/
def sparseMix {t : ℕ} (coeff : Fin (2 * (t + 1) - 1) → F)
    (state : State (t + 1)) : State (t + 1) :=
  Fin.cases
    (∑ j : Fin (t + 1), coeff ⟨j.val, by omega⟩ * state j)
    (fun i => state i.succ + state 0 * coeff ⟨t + 1 + i.val, by omega⟩)

def denseRound {t : ℕ} (matrix : List.Vector (List.Vector ℕ t) t)
    (state constants : List.Vector F t) : List.Vector F t :=
  List.Vector.ofFn (mix matrix (fun j => sbox (state.get j) + constants.get j))

def finalDenseRound {t : ℕ} (matrix : List.Vector (List.Vector ℕ t) t)
    (state : List.Vector F t) : List.Vector F t :=
  List.Vector.ofFn (mix matrix (fun j => sbox (state.get j)))

def sparseRound {t : ℕ} (state : List.Vector F (t + 1)) (constant : F)
    (coeff : List.Vector F (2 * (t + 1) - 1)) : List.Vector F (t + 1) :=
  List.Vector.ofFn (sparseMix coeff.get
    (Fin.cases (sbox (state.get 0) + constant) (fun j => state.get j.succ)))

/-- Slice constants without expanding the state semantics when comparing schedules. -/
def fullRound {t cLen : ℕ} (constants : List.Vector ℕ cLen)
    (matrix : List.Vector (List.Vector ℕ t) t) (offset : ℕ)
    (bound : offset + t ≤ cLen) (state : List.Vector F t) : List.Vector F t :=
  denseRound matrix state
    (List.Vector.ofFn fun i => (constants.get ⟨offset + i.val, by omega⟩ : F))

def partialRound {t rp : ℕ} (constants : List.Vector ℕ (8 * (t + 1) + rp))
    (sparse : List.Vector ℕ ((2 * (t + 1) - 1) * rp))
    (round : Fin rp) (state : List.Vector F (t + 1)) : List.Vector F (t + 1) :=
  let constant := (constants.get ⟨5 * (t + 1) + round.val, by omega⟩ : F)
  let coeff : List.Vector F (2 * (t + 1) - 1) := List.Vector.ofFn fun i =>
    (sparse.get ⟨round.val * (2 * (t + 1) - 1) + i.val, by
      have h := Nat.mul_le_mul_right (2 * (t + 1) - 1)
        (Nat.succ_le_of_lt round.isLt)
      rw [Nat.add_mul, Nat.one_mul] at h
      rw [Nat.mul_comm (2 * (t + 1) - 1) rp]
      omega⟩ : F)
  sparseRound state constant coeff

def permutation {t rp : ℕ} (constants : List.Vector ℕ (8 * (t + 1) + rp))
    (sparse : List.Vector ℕ ((2 * (t + 1) - 1) * rp))
    (mds transition : List.Vector (List.Vector ℕ (t + 1)) (t + 1))
    (state : List.Vector F (t + 1)) : List.Vector F (t + 1) :=
  let state := ark constants 0 (by omega) state
  let state := fullRound constants mds (t + 1) (by omega) state
  let state := fullRound constants mds (2 * (t + 1)) (by omega) state
  let state := fullRound constants mds (3 * (t + 1)) (by omega) state
  let state := fullRound constants transition (4 * (t + 1)) (by omega) state
  -- A Fin-indexed fold fixes both iteration count and sparse-row indexing.
  let state := (List.finRange rp).foldl
    (fun state round => partialRound constants sparse round state) state
  let state := fullRound constants mds (5 * (t + 1) + rp) (by omega) state
  let state := fullRound constants mds (6 * (t + 1) + rp) (by omega) state
  let state := fullRound constants mds (7 * (t + 1) + rp) (by omega) state
  finalDenseRound mds state

def initialState {n : ℕ} (input : List.Vector F n) (capacity : F) : List.Vector F (n + 1) :=
  List.Vector.ofFn (Fin.cases capacity input.get)

def poseidon2 (input : List.Vector F 2) : F :=
  (permutation c3 s3 m3 p3 (initialState input 0)).get 0

def poseidon3 (input : List.Vector F 3) : F :=
  (permutation c4 s4 m4 p4 (initialState input 0)).get 0

def poseidon7 (input : List.Vector F 7) : F :=
  (permutation c8 s8 m8 p8 (initialState input 0)).get 0

def poseidon8 (input : List.Vector F 8) : F :=
  (permutation c9 s9 m9 p9 (initialState input 0)).get 0

end ZolanaVE.Kdf.PoseidonSpecification
