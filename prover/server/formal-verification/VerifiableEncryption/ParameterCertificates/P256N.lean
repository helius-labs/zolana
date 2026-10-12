import VerifiableEncryption.ParameterCertificates.Lucas

/-!
Literal P-256 n Lucas certificate data transcribed from the primary source:
https://raw.githubusercontent.com/KeyAIGit/ecdlp-lean-verification/main/Ecdlp/Proved/P256PrimeN.lean

The upstream native evaluation proofs are not imported. Factor arithmetic uses
norm_num and modular powers use Mathlib's proof-producing reduce_mod_char.
Source-only candidate: no elaboration or certificate generator was run.
-/

namespace ZolanaVE.ParameterCertificates.P256N

theorem prime_3969899 : Nat.Prime 3969899 := by
  apply lucasFromFactors 3969899 2 [(2, 1), (19, 1), (104471, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl <;> norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl <;> (reduce_mod_char; decide)

theorem prime_1002328039319 : Nat.Prime 1002328039319 := by
  apply lucasFromFactors 1002328039319 19 [(2, 1), (126241, 1), (3969899, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl
    all_goals first | exact prime_3969899 | norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl <;> (reduce_mod_char; decide)

theorem prime_9350987 : Nat.Prime 9350987 := by
  apply lucasFromFactors 9350987 2 [(2, 1), (17, 1), (229, 1), (1201, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl <;> norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl <;> (reduce_mod_char; decide)

theorem prime_187019741 : Nat.Prime 187019741 := by
  apply lucasFromFactors 187019741 2 [(2, 2), (5, 1), (9350987, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl
    all_goals first | exact prime_9350987 | norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl <;> (reduce_mod_char; decide)

theorem prime_311245691 : Nat.Prime 311245691 := by
  apply lucasFromFactors 311245691 2 [(2, 1), (5, 1), (7, 1), (17, 1), (29, 2), (311, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl | rfl <;> norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl | rfl <;> (reduce_mod_char; decide)

theorem prime_622491383 : Nat.Prime 622491383 := by
  apply lucasFromFactors 622491383 5 [(2, 1), (311245691, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl
    all_goals first | exact prime_311245691 | norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl <;> (reduce_mod_char; decide)

theorem prime_191039911 : Nat.Prime 191039911 := by
  apply lucasFromFactors 191039911 3 [(2, 1), (3, 1), (5, 1), (41, 1), (155317, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl <;> norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl <;> (reduce_mod_char; decide)

theorem prime_208150935158385979 : Nat.Prime 208150935158385979 := by
  apply lucasFromFactors 208150935158385979 2
    [(2, 1), (3, 1), (11, 1), (43, 1), (127, 1), (3023, 1), (191039911, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals first | exact prime_191039911 | norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> (reduce_mod_char; decide)

theorem prime_2624747550333869278416773953 : Nat.Prime 2624747550333869278416773953 := by
  apply lucasFromFactors 2624747550333869278416773953 7
    [(2, 6), (3, 2), (1297, 1), (16879, 1), (208150935158385979, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl
    all_goals first | exact prime_208150935158385979 | norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl <;> (reduce_mod_char; decide)

theorem p256_order_prime :
    Nat.Prime 115792089210356248762697446949407573529996955224135760342422259061068512044369 := by
  apply lucasFromFactors
    115792089210356248762697446949407573529996955224135760342422259061068512044369 7
    [(2, 4), (3, 1), (71, 1), (131, 1), (373, 1), (3407, 1), (17449, 1),
      (38189, 1), (1002328039319, 1), (187019741, 1), (622491383, 1),
      (2624747550333869278416773953, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals first
      | exact prime_1002328039319
      | exact prime_187019741
      | exact prime_622491383
      | exact prime_2624747550333869278416773953
      | norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
      (reduce_mod_char <;> decide)

end ZolanaVE.ParameterCertificates.P256N
