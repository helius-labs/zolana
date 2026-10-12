import VerifiableEncryption.Curve.CompletenessLadderSelection

/-!
Finiteness of the recoded joint-ladder accumulators before the low-bit step.
For an unconsumed suffix of width w, the positive odd prefix coefficient is
2*floor(value/2^w)+1. The determinant of numerator/denominator prefixes is
small by cancellation, rather than the much weaker product-of-bounds estimate.
Primitivity and the exclusion of the pair (1,1) make that determinant nonzero.
This does not yet prove the separate chord and native-slope guard obligations.
-/

namespace ZolanaVE.P256.Completeness

def prefixCoefficient (value divisor : ℕ) : ℕ := 2 * (value / divisor) + 1

def prefixDeterminant (num den divisor : ℕ) : ℤ :=
  (prefixCoefficient num divisor : ℤ) * den -
    (prefixCoefficient den divisor : ℤ) * num

theorem prefixCoefficient_pos (value divisor : ℕ) : 0 < prefixCoefficient value divisor := by
  unfold prefixCoefficient
  omega

/-- The same radix-four recurrence as the production two-bit ladder step.
Here value/divisor%4 is the next pair of scalar bits. -/
theorem prefixCoefficient_step (value divisor : ℕ) :
    (prefixCoefficient value divisor : ℤ) =
      4 * (prefixCoefficient value (4 * divisor) : ℤ) +
        2 * ((value / divisor % 4 : ℕ) : ℤ) - 3 := by
  have hquot : value / divisor / 4 = value / (4 * divisor) := by
    rw [Nat.div_div_eq_div_mul, Nat.mul_comm divisor 4]
  have hn := Nat.div_add_mod (value / divisor) 4
  rw [hquot] at hn
  rw [Nat.mul_comm 4 (value / (4 * divisor))] at hn
  have hc : ((value / (4 * divisor) : ℕ) : ℤ) * 4 +
      ((value / divisor % 4 : ℕ) : ℤ) = ((value / divisor : ℕ) : ℤ) := by
    exact_mod_cast hn
  simp only [prefixCoefficient, Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat]
  omega

theorem prefixCoefficient_initial (value : ℕ) (hv : value < 2 ^ 129) :
    prefixCoefficient value (2 ^ 129) = 1 := by
  simp only [prefixCoefficient, Nat.div_eq_of_lt hv, mul_zero, zero_add]

/-- The final unmodified Q/R coefficient accounts for the low scalar bit;
the production final row separately adds 3R before the target-side correction. -/
theorem prefixCoefficient_lowbit (value : ℕ) :
    (prefixCoefficient value 2 : ℤ) = (value : ℤ) + 1 - ((value % 2 : ℕ) : ℤ) := by
  have hn := Nat.div_add_mod value 2
  rw [Nat.mul_comm 2 (value / 2)] at hn
  have hc : ((value / 2 : ℕ) : ℤ) * 2 + ((value % 2 : ℕ) : ℤ) = value := by
    exact_mod_cast hn
  simp only [prefixCoefficient, Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat]
  omega

theorem decomposition_pair_nontrivial {Q R : P} (hr : R ≠ -Q)
    (num den : ℕ) (hrel : (num : ℤ) • Q + (den : ℤ) • R = 0) :
    num ≠ 1 ∨ den ≠ 1 := by
  by_contra h
  push_neg at h
  obtain ⟨rfl, rfl⟩ := h
  simp only [Nat.cast_one, one_zsmul] at hrel
  exact hr (eq_neg_of_add_eq_zero_right hrel)

theorem prefixCoefficient_lt (value divisor : ℕ) (hv : 1 < value) (hd : 4 ≤ divisor) :
    prefixCoefficient value divisor < value := by
  have hb : value / divisor ≤ value / 4 := Nat.div_le_div_left hd (by decide)
  unfold prefixCoefficient
  omega

theorem prefixDeterminant_nonzero (num den divisor : ℕ)
    (hn : 0 < num) (hd : 0 < den) (hdiv : 4 ≤ divisor)
    (hcop : Nat.Coprime num den) (hpair : num ≠ 1 ∨ den ≠ 1) :
    prefixDeterminant num den divisor ≠ 0 := by
  intro hz
  have he : prefixCoefficient num divisor * den = prefixCoefficient den divisor * num := by
    have h := sub_eq_zero.mp hz
    exact_mod_cast h
  rcases hpair with hnum | hden
  · have hdvd : num ∣ prefixCoefficient num divisor :=
      hcop.dvd_of_dvd_mul_right (he.symm ▸ dvd_mul_left num (prefixCoefficient den divisor))
    have hlo := Nat.le_of_dvd (prefixCoefficient_pos num divisor) hdvd
    have hhi := prefixCoefficient_lt num divisor (by omega) hdiv
    omega
  · have hdvd : den ∣ prefixCoefficient den divisor :=
      hcop.symm.dvd_of_dvd_mul_right (he ▸ dvd_mul_left den (prefixCoefficient num divisor))
    have hlo := Nat.le_of_dvd (prefixCoefficient_pos den divisor) hdvd
    have hhi := prefixCoefficient_lt den divisor (by omega) hdiv
    omega

/-- The leading-product terms cancel: the determinant is bounded by num+den. -/
theorem prefixDeterminant_abs_le (num den divisor : ℕ) (hdiv : 0 < divisor) :
    |prefixDeterminant num den divisor| ≤ (num : ℤ) + den := by
  have hm : (0 : ℤ) < divisor := by exact_mod_cast hdiv
  have hn0 : (0 : ℤ) ≤ num := by positivity
  have hd0 : (0 : ℤ) ≤ den := by positivity
  have hn := Nat.div_add_mod num divisor
  have hd := Nat.div_add_mod den divisor
  rw [Nat.mul_comm divisor (num / divisor)] at hn
  rw [Nat.mul_comm divisor (den / divisor)] at hd
  have hn' : ((num / divisor : ℕ) : ℤ) * divisor + ((num % divisor : ℕ) : ℤ) = num := by
    exact_mod_cast hn
  have hd' : ((den / divisor : ℕ) : ℤ) * divisor + ((den % divisor : ℕ) : ℤ) = den := by
    exact_mod_cast hd
  have hnr : (0 : ℤ) ≤ ((num % divisor : ℕ) : ℤ) ∧ ((num % divisor : ℕ) : ℤ) < divisor := by
    exact ⟨by positivity, by exact_mod_cast Nat.mod_lt num hdiv⟩
  have hdr : (0 : ℤ) ≤ ((den % divisor : ℕ) : ℤ) ∧ ((den % divisor : ℕ) : ℤ) < divisor := by
    exact ⟨by positivity, by exact_mod_cast Nat.mod_lt den hdiv⟩
  have hid : (divisor : ℤ) * prefixDeterminant num den divisor =
      ((divisor : ℤ) - 2 * ((num % divisor : ℕ) : ℤ)) * den -
        ((divisor : ℤ) - 2 * ((den % divisor : ℕ) : ℤ)) * num := by
    simp only [prefixDeterminant, prefixCoefficient, Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat]
    linear_combination 2 * (den : ℤ) * hn' - 2 * (num : ℤ) * hd'
  have hncoeff : -(divisor : ℤ) ≤ (divisor : ℤ) - 2 * ((num % divisor : ℕ) : ℤ) ∧
      (divisor : ℤ) - 2 * ((num % divisor : ℕ) : ℤ) ≤ divisor := by omega
  have hdcoeff : -(divisor : ℤ) ≤ (divisor : ℤ) - 2 * ((den % divisor : ℕ) : ℤ) ∧
      (divisor : ℤ) - 2 * ((den % divisor : ℕ) : ℤ) ≤ divisor := by omega
  have hnlo := mul_le_mul_of_nonneg_right hncoeff.1 hd0
  have hnhi := mul_le_mul_of_nonneg_right hncoeff.2 hd0
  have hdlo := mul_le_mul_of_nonneg_right hdcoeff.1 hn0
  have hdhi := mul_le_mul_of_nonneg_right hdcoeff.2 hn0
  rw [abs_le]
  constructor
  · apply (mul_le_mul_left hm).mp
    nlinarith only [hid, hnlo, hdhi]
  · apply (mul_le_mul_left hm).mp
    nlinarith only [hid, hnhi, hdlo]

theorem prefixDeterminant_abs_lt_n (num den divisor : ℕ)
    (hn : num < 2 ^ 129) (hd : den < 2 ^ 129) (hdiv : 0 < divisor) :
    |prefixDeterminant num den divisor| < (n : ℤ) := by
  have hc : 2 * (2 : ℕ) ^ 129 < n := by norm_num [n]
  have hs : num + den < n := by omega
  exact lt_of_le_of_lt (prefixDeterminant_abs_le num den divisor hdiv)
    (by exact_mod_cast hs)

/-- Mathematical finite-prefix result, with relation supplied by the chosen
true product and the primitive scalar decomposition, not by ladder constraints. -/
theorem ladder_prefix_nonzero {Q R : P} (hq : Q ≠ 0)
    (num den divisor : ℕ) (hn0 : 0 < num) (hd0 : 0 < den)
    (hn : num < 2 ^ 129) (hd : den < 2 ^ 129) (hdiv : 4 ≤ divisor)
    (hcop : Nat.Coprime num den) (hpair : num ≠ 1 ∨ den ≠ 1)
    (hrel : (num : ℤ) • Q + (den : ℤ) • R = 0) :
    (prefixCoefficient num divisor : ℤ) • Q +
      (prefixCoefficient den divisor : ℤ) • R ≠ 0 := by
  have hr : (den : ℤ) • R = -((num : ℤ) • Q) := eq_neg_of_add_eq_zero_right hrel
  have hg : (den : ℤ) •
      ((prefixCoefficient num divisor : ℤ) • Q + (prefixCoefficient den divisor : ℤ) • R) =
      prefixDeterminant num den divisor • Q := by
    calc
      _ = ((den : ℤ) * prefixCoefficient num divisor) • Q +
          (prefixCoefficient den divisor : ℤ) • ((den : ℤ) • R) := by
        simp only [zsmul_add, ← mul_zsmul]
        rw [mul_comm (den : ℤ) (prefixCoefficient den divisor : ℤ)]
      _ = ((den : ℤ) * prefixCoefficient num divisor) • Q -
          ((prefixCoefficient den divisor : ℤ) * num) • Q := by
        rw [hr, zsmul_neg, ← mul_zsmul, sub_eq_add_neg]
      _ = _ := by
        rw [sub_eq_add_neg, ← sub_zsmul]
        congr 1
        unfold prefixDeterminant
        ring
  intro hz
  rw [hz, zsmul_zero] at hg
  have he := (scalar_faithful hq (prefixDeterminant num den divisor) 0).mp
    (by simpa using hg.symm)
  have hzero : (prefixDeterminant num den divisor : ScalarField) = 0 := by simpa using he
  have hdvd := (ZMod.intCast_zmod_eq_zero_iff_dvd _ n).mp hzero
  have hsmall := prefixDeterminant_abs_lt_n num den divisor hn hd (by omega)
  have habs : (prefixDeterminant num den divisor).natAbs < Int.natAbs (n : ℤ) := by
    have h : ((prefixDeterminant num den divisor).natAbs : ℤ) < (n : ℤ) := by
      simpa only [Int.natCast_natAbs] using hsmall
    exact_mod_cast h
  have hzeroInt := Int.eq_zero_of_dvd_of_natAbs_lt_natAbs hdvd habs
  exact prefixDeterminant_nonzero num den divisor hn0 hd0 hdiv hcop hpair hzeroInt

end ZolanaVE.P256.Completeness
