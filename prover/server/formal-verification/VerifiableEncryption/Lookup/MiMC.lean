import VerifiableEncryption.Lookup.ProductionAlgebra

/-!
Source-aligned BN254 MiMC coefficient of gnark v0.16.4. The installed
gnark-crypto revision uses 110 exponent-five rounds and LegacyKeccak256
constants derived from the ASCII seed `seed`. `Hash256` is the explicit
parameter-generation boundary: a production realization must supply the
actual LegacyKeccak256 function, not an arbitrary replacement coefficient.

The coefficient is computed from exactly two field messages `[2, callback]`,
with zero initial hash state and field-addition Miyaguchi--Preneel compression.
Nothing here asserts pseudorandomness, independence or random-oracle security.
-/

namespace ZolanaVE.Lookup.MiMC

open scoped Polynomial

variable [Fact (Nat.Prime Order)]

abbrev Byte := Fin 256
abbrev Hash256 := List Byte → List.Vector Byte 32

def seed : List Byte := [115, 101, 101, 100]

def digestChain (keccak : Hash256) : ℕ → List.Vector Byte 32
  | 0 => keccak seed
  | n + 1 => keccak (digestChain keccak n).toList

def bytesBE (bytes : List Byte) : ℕ :=
  bytes.foldl (fun acc byte => 256 * acc + byte.val) 0

/-- `initConstants` prehashes the seed, hashes that digest for constant zero,
then repeatedly hashes the preceding digest. `SetBytes` reduces big-endian
bytes modulo the native field order; natural casting expresses that reduction.
-/
def constants (keccak : Hash256) (i : Fin 110) : F :=
  (bytesBE (digestChain keccak (i.val + 1)).toList : F)

def round (key constant state : F) : F := (state + key + constant) ^ 5

def permutation (params : Fin 110 → F) (key message : F) : F :=
  (List.ofFn params).foldl (fun state constant => round key constant state) message

/-- `encryptPow5` returns `permutation + key`; `Sum` additionally adds the
old hash state and message. The resulting update is `2*state+permutation+msg`.
-/
def compress (params : Fin 110 → F) (state message : F) : F :=
  state + (permutation params state message + state) + message

def hash2 (params : Fin 110 → F) (left right : F) : F :=
  compress params (compress params 0 left) right

def hash (params : Fin 110 → F) (messages : List F) : F :=
  messages.foldl (compress params) 0

def coefficient (keccak : Hash256) (callback : F) : F :=
  hash2 (constants keccak) 2 callback

def denominator (keccak : Hash256) (index value callback : F) : F :=
  callback - (index + coefficient keccak callback * value)

noncomputable def permutationPolynomial (params : Fin 110 → F) (key : F)
    (message : F[X]) : F[X] :=
  (List.ofFn params).foldl
    (fun state constant => (state + Polynomial.C key + Polynomial.C constant) ^ 5) message

theorem fold_rounds_eval (rounds : List F) (key : F) (message : F[X]) (x : F) :
    (rounds.foldl
      (fun state constant => (state + Polynomial.C key + Polynomial.C constant) ^ 5)
      message).eval x =
    rounds.foldl (fun state constant => round key constant state) (message.eval x) := by
  induction rounds generalizing message with
  | nil => rfl
  | cons constant rounds ih =>
    simp only [List.foldl_cons]
    rw [ih]
    congr 1
    simp only [round, Polynomial.eval_pow, Polynomial.eval_add, Polynomial.eval_C]

theorem permutationPolynomial_eval (params : Fin 110 → F) (key : F)
    (message : F[X]) (x : F) :
    (permutationPolynomial params key message).eval x = permutation params key (message.eval x) :=
  fold_rounds_eval (List.ofFn params) key message x

/-- An exact formal polynomial for the public coefficient graph. Its degree
can exceed the native field size, so merely applying a univariate root bound
does not establish a useful AES security bound. -/
noncomputable def coefficientPolynomial (keccak : Hash256) : F[X] :=
  let state := compress (constants keccak) 0 2
  Polynomial.C state +
    (permutationPolynomial (constants keccak) state Polynomial.X + Polynomial.C state) +
      Polynomial.X

theorem coefficientPolynomial_eval (keccak : Hash256) (x : F) :
    (coefficientPolynomial keccak).eval x = coefficient keccak x := by
  simp [coefficientPolynomial, coefficient, hash2, compress, permutationPolynomial_eval]

theorem fold_rounds_degree (rounds : List F) (key : F) (message : F[X]) :
    (rounds.foldl
      (fun state constant => (state + Polynomial.C key + Polynomial.C constant) ^ 5)
      message).natDegree = 5 ^ rounds.length * message.natDegree := by
  induction rounds generalizing message with
  | nil => simp
  | cons constant rounds ih =>
    rw [List.foldl_cons, ih, Polynomial.natDegree_pow,
      Polynomial.natDegree_add_C, Polynomial.natDegree_add_C]
    simp only [List.length_cons]
    rw [pow_succ]
    ring

theorem permutationPolynomial_degree (params : Fin 110 → F) (key : F) :
    (permutationPolynomial params key Polynomial.X).natDegree = 5 ^ 110 := by
  simpa [permutationPolynomial] using fold_rounds_degree (List.ofFn params) key Polynomial.X

theorem coefficientPolynomial_degree (keccak : Hash256) :
    (coefficientPolynomial keccak).natDegree = 5 ^ 110 := by
  let state := compress (constants keccak) 0 2
  have hinner : (Polynomial.C state +
      (permutationPolynomial (constants keccak) state Polynomial.X + Polynomial.C state)).natDegree =
      5 ^ 110 := by
    simp only [Polynomial.natDegree_C_add, Polynomial.natDegree_add_C,
      permutationPolynomial_degree]
  have hlt : (Polynomial.X : F[X]).natDegree <
      (Polynomial.C state +
        (permutationPolynomial (constants keccak) state Polynomial.X + Polynomial.C state)).natDegree := by
    rw [hinner]
    norm_num
  exact (Polynomial.natDegree_add_eq_left_of_natDegree_lt hlt).trans hinner

/-- The exact univariate degree already exceeds the native field cardinal.
Consequently its uniform-field root-count bound is larger than one, before
any lookup residual factors are included. It cannot justify a small AES bound.
-/
theorem coefficientPolynomial_degree_exceeds_order (keccak : Hash256) :
    Order < (coefficientPolynomial keccak).natDegree := by
  rw [coefficientPolynomial_degree]
  unfold Order
  norm_num

def inverseFifthExponent : ℕ := (4 * (Order - 1) + 1) / 5

theorem inverseFifthExponent_pos : 0 < inverseFifthExponent := by
  unfold inverseFifthExponent Order
  norm_num

theorem inverseFifthExponent_equation : 5 * inverseFifthExponent = 4 * (Order - 1) + 1 := by
  unfold inverseFifthExponent Order
  norm_num

theorem fifth_power_left_inverse (value : F) : (value ^ 5) ^ inverseFifthExponent = value := by
  by_cases hv : value = 0
  · simp [hv, Nat.ne_of_gt inverseFifthExponent_pos]
  · rw [← pow_mul, inverseFifthExponent_equation, pow_add, pow_one,
      Nat.mul_comm 4 (Order - 1), pow_mul, ZMod.pow_card_sub_one_eq_one hv]
    simp

theorem fifth_power_right_inverse (value : F) : (value ^ inverseFifthExponent) ^ 5 = value := by
  rw [← pow_mul, Nat.mul_comm inverseFifthExponent 5, pow_mul]
  exact fifth_power_left_inverse value

theorem round_bijective (key constant : F) : Function.Bijective (round key constant) := by
  let inverse := fun value : F => value ^ inverseFifthExponent - key - constant
  have hleft : Function.LeftInverse inverse (round key constant) := by
    intro value
    simp only [inverse, round, fifth_power_left_inverse]
    ring
  have hright : Function.RightInverse inverse (round key constant) := by
    intro value
    change (value ^ inverseFifthExponent - key - constant + key + constant) ^ 5 = value
    have he : value ^ inverseFifthExponent - key - constant + key + constant = value ^ inverseFifthExponent := by ring
    rw [he]
    exact fifth_power_right_inverse value
  exact ⟨hleft.injective, hright.surjective⟩

theorem rounds_bijective (rounds : List F) (key : F) :
    Function.Bijective (fun message => rounds.foldl (fun state constant => round key constant state) message) := by
  induction rounds with
  | nil => exact Function.bijective_id
  | cons constant rounds ih => exact ih.comp (round_bijective key constant)

theorem permutation_bijective (params : Fin 110 → F) (key : F) :
    Function.Bijective (permutation params key) := rounds_bijective (List.ofFn params) key

/-- The fixed key and offset are public. This algebraic permutation fact is
not a cryptographic ideal-permutation replacement theorem.
-/
theorem coefficient_permutation_graph (keccak : Hash256) (challenge : F) :
    let key := compress (constants keccak) 0 2
    coefficient keccak challenge = permutation (constants keccak) key challenge + challenge + 2 * key := by
  simp only [coefficient, hash2, compress]
  ring

theorem coefficient_two_messages (keccak : Hash256) (callback : F) :
    coefficient keccak callback =
      ([2, callback] : List F).foldl (compress (constants keccak)) 0 := rfl

theorem coefficient_eq_hash (keccak : Hash256) (callback : F) :
    coefficient keccak callback = hash (constants keccak) [2, callback] := rfl

theorem denominator_eq_source (keccak : Hash256) (index value callback : F) :
    denominator keccak index value callback =
      aesDenominator (coefficient keccak) index value callback := rfl

end ZolanaVE.Lookup.MiMC
