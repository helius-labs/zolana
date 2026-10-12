import VerifiableEncryption.ParameterCertificates.Lucas

/-!
Literal P-256 p Lucas certificate data transcribed from the primary source:
https://raw.githubusercontent.com/KeyAIGit/ecdlp-lean-verification/main/Ecdlp/Proved/P256PrimeP.lean

The upstream native evaluation proofs are not imported. Factor arithmetic uses
norm_num and modular powers use Mathlib's proof-producing reduce_mod_char.
Source-only candidate: no elaboration or certificate generator was run.
-/

namespace ZolanaVE.ParameterCertificates.P256P

theorem prime_6700417 : Nat.Prime 6700417 := by
  apply lucasFromFactors 6700417 5 [(2, 7), (3, 1), (17449, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl <;> norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl <;> (reduce_mod_char; decide)

theorem prime_66417393611 : Nat.Prime 66417393611 := by
  apply lucasFromFactors 66417393611 6
    [(2, 1), (5, 1), (53, 1), (173, 1), (197, 1), (3677, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl | rfl <;> norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl | rfl <;> (reduce_mod_char; decide)

theorem prime_11290956913871 : Nat.Prime 11290956913871 := by
  apply lucasFromFactors 11290956913871 13 [(2, 1), (5, 1), (17, 1), (66417393611, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl
    all_goals first | exact prime_66417393611 | norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl <;> (reduce_mod_char; decide)

theorem prime_204061199 : Nat.Prime 204061199 := by
  apply lucasFromFactors 204061199 11 [(2, 1), (11, 1), (23, 1), (107, 1), (3769, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl <;> norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl <;> (reduce_mod_char; decide)

theorem prime_34282281433 : Nat.Prime 34282281433 := by
  apply lucasFromFactors 34282281433 17 [(2, 3), (3, 1), (7, 1), (204061199, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl
    all_goals first | exact prime_204061199 | norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl <;> (reduce_mod_char; decide)

theorem prime_46076956964474543 : Nat.Prime 46076956964474543 := by
  apply lucasFromFactors 46076956964474543 5
    [(2, 1), (23, 1), (18169, 1), (704251, 1), (78283, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl <;> norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl <;> (reduce_mod_char; decide)

theorem prime_774023187263532362759620327192479577272145303 :
    Nat.Prime 774023187263532362759620327192479577272145303 := by
  apply lucasFromFactors 774023187263532362759620327192479577272145303 3
    [(2, 1), (3, 2), (2411, 1), (11290956913871, 1), (34282281433, 1), (46076956964474543, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl | rfl
    all_goals first
      | exact prime_11290956913871
      | exact prime_34282281433
      | exact prime_46076956964474543
      | norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl | rfl <;> (reduce_mod_char; decide)

theorem prime_835945042244614951780389953367877943453916927241 :
    Nat.Prime 835945042244614951780389953367877943453916927241 := by
  apply lucasFromFactors 835945042244614951780389953367877943453916927241 11
    [(2, 3), (3, 3), (5, 1), (774023187263532362759620327192479577272145303, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl
    all_goals first | exact prime_774023187263532362759620327192479577272145303 | norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl <;> (reduce_mod_char; decide)

theorem p256_prime :
    Nat.Prime 115792089210356248762697446949407573530086143415290314195533631308867097853951 := by
  apply lucasFromFactors
    115792089210356248762697446949407573530086143415290314195533631308867097853951 6
    [(2, 1), (3, 1), (5, 2), (17, 1), (257, 1), (641, 1), (1531, 1),
      (65537, 1), (490463, 1), (6700417, 1), (835945042244614951780389953367877943453916927241, 1)]
  · norm_num
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals first
      | exact prime_6700417
      | exact prime_835945042244614951780389953367877943453916927241
      | norm_num
  · reduce_mod_char
  · intro f hf
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hf
    rcases hf with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
      (reduce_mod_char <;> decide)

end ZolanaVE.ParameterCertificates.P256P
