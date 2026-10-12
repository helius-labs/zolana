import VerifiableEncryption.Curve.P256
import Mathlib.NumberTheory.DiophantineApproximation.Basic
import Mathlib.RingTheory.Coprime.Lemmas

/-!
Universal mathematical rational decomposition for the variable-base ladder.
Dirichlet approximation supplies a reduced rational q close to s/n. Taking
a=s*q.den-n*q.num gives the bounded signed numerator. Since q.den<n and n
is prime, the residual pair is primitive. No hint, successful ladder run or
extracted-predicate witness is assumed. Scalars need not be canonical.

This source has not been elaborated under the user's execution restriction.
-/

namespace ZolanaVE.P256.Completeness

theorem halfBound_lt_n : (2 : ℕ) ^ 128 < n := by norm_num [n]
theorem fullHalfBound_lt_n : (2 : ℕ) ^ 129 < n := by norm_num [n]

/-- A primitive signed pair with the actual ladder's 129-bit bounds. -/
theorem primitive_decomposition (scalar : ℤ) (hs : (scalar : ZMod n) ≠ 0) :
    ∃ (a : ℤ) (den : ℕ), a ≠ 0 ∧ 0 < den ∧
      |a| < (2 : ℤ) ^ 129 ∧ den < (2 : ℕ) ^ 129 ∧
      Nat.Coprime a.natAbs den ∧ a ≡ scalar * den [ZMOD n] := by
  obtain ⟨q, happrox, hden⟩ :=
    Real.exists_rat_abs_sub_le_and_den_le ((scalar : ℝ) / (n : ℝ))
      (n := 2 ^ 128) (by positivity)
  let a : ℤ := scalar * q.den - (n : ℤ) * q.num
  have hb : 0 < q.den := q.pos
  have hbn : q.den < n := lt_of_le_of_lt hden halfBound_lt_n
  have hbp : (0 : ℝ) < q.den := by exact_mod_cast hb
  have hnp : (0 : ℝ) < n := by exact_mod_cast Assumptions.p256_order_prime.pos
  have hbig : (0 : ℝ) < (2 ^ 128 : ℕ) + 1 := by positivity
  have hidentity :
      |(a : ℝ)| = |(scalar : ℝ) / (n : ℝ) - (q : ℝ)| * ((n : ℝ) * q.den) := by
    calc
      |(a : ℝ)| = |((scalar : ℝ) / (n : ℝ) - (q : ℝ)) * ((n : ℝ) * q.den)| := by
        congr 1
        dsimp [a]
        push_cast
        rw [Rat.cast_def]
        field_simp [hnp.ne', hbp.ne'] <;> ring
      _ = _ := by rw [abs_mul, abs_of_pos (mul_pos hnp hbp)]
  have hsmall : |(a : ℝ)| ≤ (n : ℝ) / ((2 ^ 128 : ℕ) + 1) := by
    rw [hidentity]
    calc
      _ ≤ (1 / (((2 ^ 128 : ℕ) + 1) * (q.den : ℝ))) * ((n : ℝ) * q.den) :=
        mul_le_mul_of_nonneg_right happrox (mul_pos hnp hbp).le
      _ = _ := by field_simp [hbp.ne', hbig.ne'] <;> ring
  have hratio : (n : ℝ) / ((2 ^ 128 : ℕ) + 1) < (2 : ℝ) ^ 129 := by
    apply (div_lt_iff₀ hbig).mpr
    norm_num [n]
  have ha : |a| < (2 : ℤ) ^ 129 := by
    have hreal := lt_of_le_of_lt hsmall hratio
    exact_mod_cast hreal
  have hcopden : Nat.Coprime n q.den :=
    Nat.coprime_of_lt_prime hb hbn Assumptions.p256_order_prime
  have hcopnum : IsCoprime q.num (q.den : ℤ) := by
    apply Int.isCoprime_iff_gcd_eq_one.mpr
    change Nat.Coprime q.num.natAbs q.den
    exact q.reduced
  have hcop : IsCoprime a (q.den : ℤ) := by
    have h := ((hcopden.isCoprime.mul_left hcopnum).neg_left).mul_add_right_left scalar
    convert h using 1 <;> dsimp [a] <;> ring
  have hprimitive : Nat.Coprime a.natAbs q.den := by
    have h := Int.isCoprime_iff_gcd_eq_one.mp hcop
    change Nat.Coprime a.natAbs q.den at h
    exact h
  have hrel : a ≡ scalar * q.den [ZMOD n] := by
    apply Int.modEq_iff_dvd.mpr
    refine ⟨q.num, ?_⟩
    dsimp [a]
    ring
  have hbfield : (q.den : ZMod n) ≠ 0 := by
    intro hz
    have hv := congrArg ZMod.val hz
    rw [ZMod.val_natCast_of_lt hbn, ZMod.val_zero] at hv
    omega
  have hazero : a ≠ 0 := by
    intro hz
    have hfield := (ZMod.intCast_eq_intCast_iff _ _ n).mpr hrel
    rw [hz, Int.cast_zero, Int.cast_mul, Int.cast_natCast] at hfield
    exact (mul_ne_zero hs hbfield) hfield.symm
  refine ⟨a, q.den, hazero, hb, ha, ?_, hprimitive, hrel⟩
  exact lt_of_le_of_lt hden (by norm_num)

/-- Noncanonical integer inputs are covered through their nonzero residue. -/
theorem primitive_decomposition_nat (scalar : ℕ) (hs : scalar % n ≠ 0) :
    ∃ (a : ℤ) (den : ℕ), a ≠ 0 ∧ 0 < den ∧
      |a| < (2 : ℤ) ^ 129 ∧ den < (2 : ℕ) ^ 129 ∧
      Nat.Coprime a.natAbs den ∧ a ≡ (scalar : ℤ) * den [ZMOD n] := by
  apply primitive_decomposition
  intro hz
  have hv := congrArg ZMod.val hz
  have residue : scalar % n = 0 := by
    simpa only [Int.cast_natCast, ZMod.val_natCast, ZMod.val_zero] using hv
  exact hs residue

/-- The sign convention of the actual decomposition equation: sign=true
chooses a negative denominator, and numerator is always a positive magnitude. -/
theorem ladder_decomposition (scalar : ℤ) (hs : (scalar : ZMod n) ≠ 0) :
    ∃ (num den : ℕ) (sign : Bool),
      0 < num ∧ num < 2 ^ 129 ∧ 0 < den ∧ den < 2 ^ 129 ∧
      Nat.Coprime num den ∧
      scalar * ((if sign then -1 else 1 : ℤ) * den) + num ≡ 0 [ZMOD n] := by
  obtain ⟨a, den, ha0, hd0, ha, hd, hcop, hrel⟩ := primitive_decomposition scalar hs
  have hnum0 : 0 < a.natAbs := by
    apply Nat.pos_of_ne_zero
    exact Int.natAbs_ne_zero.mpr ha0
  have hnum : a.natAbs < 2 ^ 129 := by
    have h : (a.natAbs : ℤ) < (2 : ℤ) ^ 129 := by
      simpa only [Int.natCast_natAbs] using ha
    exact_mod_cast h
  by_cases hapos : 0 ≤ a
  · refine ⟨a.natAbs, den, true, hnum0, hnum, hd0, hd, hcop, ?_⟩
    have he : (a.natAbs : ℤ) = a := by rw [Int.natCast_natAbs, abs_of_nonneg hapos]
    simp only [if_true, neg_one_mul, he]
    have h := hrel.sub (Int.ModEq.refl (scalar * den))
    convert h using 1 <;> ring
  · refine ⟨a.natAbs, den, false, hnum0, hnum, hd0, hd, hcop, ?_⟩
    have he : (a.natAbs : ℤ) = -a := by rw [Int.natCast_natAbs, abs_of_neg (by omega)]
    simp only [Bool.false_eq_true, if_false, one_mul, he]
    have h := (Int.ModEq.refl (scalar * den)).sub hrel
    convert h using 1 <;> ring

end ZolanaVE.P256.Completeness
