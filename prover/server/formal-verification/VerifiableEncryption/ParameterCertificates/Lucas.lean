import Mathlib

/-! A finite factor list formulation of Mathlib's Lucas primality theorem.
This is an ordinary mathematical lemma, not a certificate evaluator or tactic.
All factor identities and modular equations remain proof obligations. -/

namespace ZolanaVE.ParameterCertificates

theorem lucasFromFactors (N witness : ℕ) (factors : List (ℕ × ℕ))
    (hfactor : N - 1 = (factors.map (fun f => f.1 ^ f.2)).prod)
    (hprime : ∀ f ∈ factors, Nat.Prime f.1)
    (hfull : (witness : ZMod N) ^ (N - 1) = 1)
    (hproper : ∀ f ∈ factors, (witness : ZMod N) ^ ((N - 1) / f.1) ≠ 1) :
    Nat.Prime N := by
  apply lucas_primality N (witness : ZMod N) hfull
  intro q hq hqd
  rw [hfactor] at hqd
  obtain ⟨power, hmem, hdiv⟩ := (Nat.prime_iff.mp hq).dvd_prod_iff.mp hqd
  obtain ⟨f, hf, he⟩ := List.mem_map.mp hmem
  rw [← he] at hdiv
  have hqr : q = f.1 :=
    (Nat.prime_dvd_prime_iff_eq hq (hprime f hf)).mp (hq.dvd_of_dvd_pow hdiv)
  rw [hqr]
  exact hproper f hf

end ZolanaVE.ParameterCertificates
