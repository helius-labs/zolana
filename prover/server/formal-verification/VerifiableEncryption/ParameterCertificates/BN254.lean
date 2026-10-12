import VerifiableEncryption.ParameterCertificates.Lucas

/-!
Literal Lucas certificate source for the BN254 scalar field.

Top-level and three large-node data come from:
https://github.com/NethermindEth/CompPolyFri/blob/master/CompPoly/Fields/BN254.lean
(Copyright 2024 ArkLib Contributors, Quang Dao; Apache 2.0).

The four missing predecessor factorizations were obtained by read-only
https://factordb.com/api?query=... queries for 405928798, 639533338,
12048837556, and 5156902474396. They are untrusted literal data whose product,
terminal primalities, and modular witness equations remain checked obligations.

Unknown witnesses have complete alternatives using Lean's existing first
tactic; no certificate generator, factoring, tactic macro, or evaluator is
defined here. This source has not been elaborated or executed.
-/

namespace ZolanaVE.ParameterCertificates.BN254

theorem prime_405928799 : Nat.Prime 405928799 := by
  have candidate (a : ℕ)
      (hfull : (a : ZMod 405928799) ^ (405928799 - 1) = 1)
      (h2 : (a : ZMod 405928799) ^ ((405928799 - 1) / 2) ≠ 1)
      (h11 : (a : ZMod 405928799) ^ ((405928799 - 1) / 11) ≠ 1)
      (h3691 : (a : ZMod 405928799) ^ ((405928799 - 1) / 3691) ≠ 1)
      (h4999 : (a : ZMod 405928799) ^ ((405928799 - 1) / 4999) ≠ 1) :
      Nat.Prime 405928799 := by
    apply lucasFromFactors 405928799 a [(2, 1), (11, 1), (3691, 1), (4999, 1)]
    · norm_num
    · intro f hf
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl <;> norm_num
    · exact hfull
    · intro f hf
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      exacts [h2, h11, h3691, h4999]
  apply candidate 22 <;> (reduce_mod_char <;> decide)

theorem prime_639533339 : Nat.Prime 639533339 := by
  have candidate (a : ℕ)
      (hfull : (a : ZMod 639533339) ^ (639533339 - 1) = 1)
      (h2 : (a : ZMod 639533339) ^ ((639533339 - 1) / 2) ≠ 1)
      (h229 : (a : ZMod 639533339) ^ ((639533339 - 1) / 229) ≠ 1)
      (h853 : (a : ZMod 639533339) ^ ((639533339 - 1) / 853) ≠ 1)
      (h1637 : (a : ZMod 639533339) ^ ((639533339 - 1) / 1637) ≠ 1) :
      Nat.Prime 639533339 := by
    apply lucasFromFactors 639533339 a [(2, 1), (229, 1), (853, 1), (1637, 1)]
    · norm_num
    · intro f hf
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl <;> norm_num
    · exact hfull
    · intro f hf
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      exacts [h2, h229, h853, h1637]
  apply candidate 2 <;> (reduce_mod_char <;> decide)

theorem prime_12048837557 : Nat.Prime 12048837557 := by
  have candidate (a : ℕ)
      (hfull : (a : ZMod 12048837557) ^ (12048837557 - 1) = 1)
      (h2 : (a : ZMod 12048837557) ^ ((12048837557 - 1) / 2) ≠ 1)
      (h7 : (a : ZMod 12048837557) ^ ((12048837557 - 1) / 7) ≠ 1)
      (h661 : (a : ZMod 12048837557) ^ ((12048837557 - 1) / 661) ≠ 1)
      (h93001 : (a : ZMod 12048837557) ^ ((12048837557 - 1) / 93001) ≠ 1) :
      Nat.Prime 12048837557 := by
    apply lucasFromFactors 12048837557 a [(2, 2), (7, 2), (661, 1), (93001, 1)]
    · norm_num
    · intro f hf
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl <;> norm_num
    · exact hfull
    · intro f hf
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
      rcases hf with rfl | rfl | rfl | rfl
      exacts [h2, h7, h661, h93001]
  apply candidate 2 <;> (reduce_mod_char <;> decide)

theorem prime_5156902474397 : Nat.Prime 5156902474397 := by
  have candidate (a : ℕ)
      (hfull : (a : ZMod 5156902474397) ^ (5156902474397 - 1) = 1)
      (h2 : (a : ZMod 5156902474397) ^ ((5156902474397 - 1) / 2) ≠ 1)
      (h107 : (a : ZMod 5156902474397) ^ ((5156902474397 - 1) / 107) ≠ 1)
      (h12048837557 : (a : ZMod 5156902474397) ^ ((5156902474397 - 1) / 12048837557) ≠ 1) :
      Nat.Prime 5156902474397 := by
    apply lucasFromFactors 5156902474397 a [(2, 2), (107, 1), (12048837557, 1)]
    · norm_num
    · intro f hf
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
      rcases hf with rfl | rfl | rfl
      all_goals first | exact prime_12048837557 | norm_num
    · exact hfull
    · intro f hf
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
      rcases hf with rfl | rfl | rfl
      exacts [h2, h107, h12048837557]
  apply candidate 2 <;> (reduce_mod_char <;> decide)

theorem prime_1670836401704629 : Nat.Prime 1670836401704629 := by
  apply lucasFromFactors 1670836401704629 2 [(2, 2), (3, 4), (5156902474397, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl
    all_goals first | exact prime_5156902474397 | norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl <;> (reduce_mod_char <;> decide)

theorem prime_65865678001877903 : Nat.Prime 65865678001877903 := by
  apply lucasFromFactors 65865678001877903 5
    [(2, 1), (83, 1), (379, 1), (1637, 1), (639533339, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl
    all_goals first | exact prime_639533339 | norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl <;> (reduce_mod_char <;> decide)

theorem prime_13818364434197438864469338081 : Nat.Prime 13818364434197438864469338081 := by
  apply lucasFromFactors 13818364434197438864469338081 3
    [(2, 5), (5, 1), (823, 1), (1593227, 1), (65865678001877903, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl
    all_goals first | exact prime_65865678001877903 | norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl <;> (reduce_mod_char <;> decide)

theorem scalar_prime :
    Nat.Prime 21888242871839275222246405745257275088548364400416034343698204186575808495617 := by
  apply lucasFromFactors
    21888242871839275222246405745257275088548364400416034343698204186575808495617 5
    [(2, 28), (3, 2), (13, 1), (29, 1), (983, 1), (11003, 1), (237073, 1),
      (405928799, 1), (1670836401704629, 1), (13818364434197438864469338081, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals first
      | exact prime_405928799
      | exact prime_1670836401704629
      | exact prime_13818364434197438864469338081
      | norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
      (reduce_mod_char <;> decide)

end ZolanaVE.ParameterCertificates.BN254
