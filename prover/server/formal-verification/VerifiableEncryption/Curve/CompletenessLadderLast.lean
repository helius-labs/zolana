import VerifiableEncryption.Curve.CompletenessLadderChords

/-!
Final-step chord noncollision, including the extra 3R in the selected row.
The primitive relation excludes both inverse and equal doubled-accumulator
collisions. This is stronger than the final gadget's doubling-aware equation;
it does not construct its field-polynomial witnesses or invoke a native guard.
-/

namespace ZolanaVE.P256.Completeness

theorem forwardLastDen_positive (value : ℕ) :
    0 < forwardChordCoefficient value 2 + 3 := by
  have hquot : value / 2 / 4 = value / 8 := by rw [Nat.div_div_eq_div_mul]
  have hq := Nat.mul_div_le (value / 2) 4
  rw [hquot] at hq
  simp only [forwardChordCoefficient, prefixCoefficient, Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat]
  omega

theorem backwardLastDen_small (value : ℕ) (hv : 1 < value) :
    |backwardChordCoefficient value 2 - 3| < (value : ℤ) := by
  have hquot : value / 2 / 4 = value / 8 := by rw [Nat.div_div_eq_div_mul]
  have hq := Nat.div_add_mod (value / 2) 4
  rw [hquot] at hq
  have hr : value / 2 % 4 < 4 := Nat.mod_lt _ (by decide)
  have hval := Nat.mul_div_le value 8
  have hhalf := Nat.mul_div_le value 2
  rw [backwardChordCoefficient_formula, abs_lt]
  by_cases hz : value / 8 = 0
  · omega
  · omega

theorem forwardLastDeterminant_nonzero (num den : ℕ)
    (hn : 0 < num) (hd : 0 < den) (hc : Nat.Coprime num den) :
    forwardChordCoefficient num 2 * den - (forwardChordCoefficient den 2 + 3) * num ≠ 0 := by
  by_cases hnum : num = 1
  · subst num
    intro hz
    have hcoef : forwardChordCoefficient 1 2 = -1 := by
      norm_num [forwardChordCoefficient, prefixCoefficient]
    rw [hcoef, Nat.cast_one, mul_one] at hz
    have hp := forwardLastDen_positive den
    have hd' : (0 : ℤ) < den := by exact_mod_cast hd
    linarith
  · exact primitive_determinant_nonzero_of_small num den _ _ hc
      (forwardChordCoefficient_nonzero num 2)
      (forwardChordCoefficient_small num 2 (by omega) (by decide))

theorem backwardLastDeterminant_nonzero (num den : ℕ)
    (hn : 0 < num) (hd : 0 < den) (hc : Nat.Coprime num den) :
    backwardChordCoefficient num 2 * den - (backwardChordCoefficient den 2 - 3) * num ≠ 0 := by
  intro hz
  by_cases hden : den = 1
  · subst den
    norm_num [backwardChordCoefficient, prefixCoefficient] at hz
    omega
  · have hv : backwardChordCoefficient den 2 - 3 ≠ 0 := by
      intro he
      rw [he, zero_mul, sub_zero] at hz
      have hd' : (den : ℤ) ≠ 0 := by exact_mod_cast hd.ne'
      exact backwardChordCoefficient_nonzero num 2 ((mul_eq_zero.mp hz).resolve_right hd')
    apply primitive_determinant_nonzero_of_small den num
      (backwardChordCoefficient den 2 - 3) (backwardChordCoefficient num 2) hc.symm hv
      (backwardLastDen_small den (by omega))
    linear_combination -hz

theorem forwardLastDeterminant_bound (num den : ℕ) :
    |forwardChordCoefficient num 2 * den - (forwardChordCoefficient den 2 + 3) * num| ≤
      6 * ((num : ℤ) + den) := by
  have hi : forwardChordCoefficient num 2 * den - (forwardChordCoefficient den 2 + 3) * num =
      (forwardChordCoefficient num 2 * den - forwardChordCoefficient den 2 * num) - 3 * num := by ring
  rw [hi]
  have hs := abs_sub (forwardChordCoefficient num 2 * den - forwardChordCoefficient den 2 * num)
    (3 * (num : ℤ))
  have hp := forwardChordDeterminant_bound num den 2 (by decide)
  have hn : (0 : ℤ) ≤ num := by positivity
  have hd : (0 : ℤ) ≤ den := by positivity
  rw [abs_of_nonneg (by positivity : (0 : ℤ) ≤ 3 * num)] at hs
  linarith

theorem backwardLastDeterminant_bound (num den : ℕ) :
    |backwardChordCoefficient num 2 * den - (backwardChordCoefficient den 2 - 3) * num| ≤
      10 * ((num : ℤ) + den) := by
  have hi : backwardChordCoefficient num 2 * den - (backwardChordCoefficient den 2 - 3) * num =
      (backwardChordCoefficient num 2 * den - backwardChordCoefficient den 2 * num) + 3 * num := by ring
  rw [hi]
  have hs := abs_add_le (backwardChordCoefficient num 2 * den - backwardChordCoefficient den 2 * num)
    (3 * (num : ℤ))
  have hp := backwardChordDeterminant_bound num den 2 (by decide)
  have hn : (0 : ℤ) ≤ num := by positivity
  have hd : (0 : ℤ) ≤ den := by positivity
  rw [abs_of_nonneg (by positivity : (0 : ℤ) ≤ 3 * num)] at hs
  linarith

noncomputable def lastRow (num den : ℕ) (Q R : P) : P := middleRow num den 2 Q R + (3 : ℤ) • R

def lastDigit (value : ℕ) : ℤ := 2 * ((value / 2 % 4 : ℕ) : ℤ) - 3

theorem lastDigit_nonzero (value : ℕ) : lastDigit value ≠ 0 := by
  unfold lastDigit
  omega

theorem lastDigit_abs_le (value : ℕ) : |lastDigit value| ≤ 3 := by
  have h := Nat.mod_lt (value / 2) (by decide : 0 < 4)
  rw [abs_le]
  unfold lastDigit
  omega

theorem lastShiftedDigit_abs_le (value : ℕ) (positive : Bool) :
    |lastDigit value + (if positive then 3 else -3)| ≤ 6 := by
  have h := Nat.mod_lt (value / 2) (by decide : 0 < 4)
  cases positive <;> rw [abs_le] <;> simp only [lastDigit, if_true, Bool.false_eq_true, if_false] <;> omega

theorem lastGuardDeterminant_nonzero (num den : ℕ) (positive : Bool)
    (hn : 0 < num) (hd : 0 < den) (hc : Nat.Coprime num den) :
    lastDigit num * den - (lastDigit den + (if positive then 3 else -3)) * num ≠ 0 := by
  by_cases hsmall : num ≤ 3
  · interval_cases num
    · intro hz
      have hq : lastDigit 1 = -3 := by norm_num [lastDigit]
      rw [hq, Nat.cast_one, mul_one] at hz
      cases positive with
      | false =>
        simp only [Bool.false_eq_true, if_false, lastDigit] at hz
        have hr : (0 : ℤ) ≤ ((den / 2 % 4 : ℕ) : ℤ) := by positivity
        have hb : den ≤ 2 := by omega
        interval_cases den <;> norm_num at hz
      | true =>
        have hr : 0 ≤ lastDigit den + 3 := by
          unfold lastDigit
          have hnonneg : (0 : ℤ) ≤ ((den / 2 % 4 : ℕ) : ℤ) := by positivity
          omega
        have hd' : (0 : ℤ) < den := by exact_mod_cast hd
        simp only [if_true] at hz
        linarith
    · exact primitive_determinant_nonzero_of_small 2 den _ _ hc (lastDigit_nonzero 2)
        (by norm_num [lastDigit])
    · exact primitive_determinant_nonzero_of_small 3 den _ _ hc (lastDigit_nonzero 3)
        (by norm_num [lastDigit])
  · exact primitive_determinant_nonzero_of_small num den _ _ hc (lastDigit_nonzero num)
      (lt_of_le_of_lt (lastDigit_abs_le num) (by exact_mod_cast (show 3 < num by omega)))

theorem lastGuardDeterminant_bound (num den : ℕ) (positive : Bool) :
    |lastDigit num * den - (lastDigit den + (if positive then 3 else -3)) * num| ≤
      3 * (den : ℤ) + 6 * num := by
  have hs := abs_sub (lastDigit num * (den : ℤ))
    ((lastDigit den + (if positive then 3 else -3)) * (num : ℤ))
  rw [abs_mul, abs_mul, abs_of_nonneg (by positivity : (0 : ℤ) ≤ den),
    abs_of_nonneg (by positivity : (0 : ℤ) ≤ num)] at hs
  have hn := mul_le_mul_of_nonneg_right (lastDigit_abs_le num) (by positivity : (0 : ℤ) ≤ den)
  have hd := mul_le_mul_of_nonneg_right (lastShiftedDigit_abs_le den positive) (by positivity : (0 : ℤ) ≤ num)
  linarith

/-- The eager guarded row-plus-3R addition has distinct operands as well as
noninverse operands, including the cases with a zero shifted R digit. -/
theorem last_preadd_noncollision {Q R : P} (hq : Q ≠ 0) (num den : ℕ)
    (hn0 : 0 < num) (hd0 : 0 < den) (hn : num < 2 ^ 129) (hd : den < 2 ^ 129)
    (hc : Nat.Coprime num den) (hrel : (num : ℤ) • Q + (den : ℤ) • R = 0) :
    middleRow num den 2 Q R ≠ (3 : ℤ) • R ∧ middleRow num den 2 Q R ≠ -((3 : ℤ) • R) := by
  have hcap : 9 * (2 : ℕ) ^ 129 < n := by norm_num [n]
  have hsmall : 3 * (den : ℤ) + 6 * num < (n : ℤ) := by
    have hnat : 3 * den + 6 * num < n := by omega
    exact_mod_cast hnat
  have hm : lastDigit num • Q + (lastDigit den + (-3)) • R ≠ 0 :=
    combination_nonzero_of_small_determinant hq num den _ _ hrel
      (lastGuardDeterminant_nonzero num den false hn0 hd0 hc)
      (lt_of_le_of_lt (lastGuardDeterminant_bound num den false) hsmall)
  have hp : lastDigit num • Q + (lastDigit den + 3) • R ≠ 0 :=
    combination_nonzero_of_small_determinant hq num den _ _ hrel
      (lastGuardDeterminant_nonzero num den true hn0 hd0 hc)
      (lt_of_le_of_lt (lastGuardDeterminant_bound num den true) hsmall)
  constructor
  · intro h
    apply hm
    have hz := sub_eq_zero.mpr h
    rw [middleRow_coefficients] at hz
    convert hz using 1 <;> simp only [lastDigit, add_zsmul] <;> abel
  · intro h
    apply hp
    have hz : middleRow num den 2 Q R + (3 : ℤ) • R = 0 := by rw [h, neg_add_cancel]
    rw [middleRow_coefficients] at hz
    convert hz using 1 <;> simp only [lastDigit, add_zsmul] <;> abel

theorem last_chord_noncollision {Q R : P} (hq : Q ≠ 0) (num den : ℕ)
    (hn0 : 0 < num) (hd0 : 0 < den) (hn : num < 2 ^ 129) (hd : den < 2 ^ 129)
    (hc : Nat.Coprime num den) (hrel : (num : ℤ) • Q + (den : ℤ) • R = 0) :
    (2 : ℤ) • middleAccumulator num den 2 Q R ≠ lastRow num den Q R ∧
    (2 : ℤ) • middleAccumulator num den 2 Q R ≠ -lastRow num den Q R := by
  have hcap : 10 * (2 * (2 : ℕ) ^ 129) < n := by norm_num [n]
  have hsmall : 10 * ((num : ℤ) + den) < (n : ℤ) := by
    have hnat : 10 * (num + den) < n := by omega
    exact_mod_cast hnat
  have hsumNonneg : (0 : ℤ) ≤ (num : ℤ) + den := by positivity
  have hb : backwardChordCoefficient num 2 • Q + (backwardChordCoefficient den 2 - 3) • R ≠ 0 :=
    combination_nonzero_of_small_determinant hq num den _ _ hrel
      (backwardLastDeterminant_nonzero num den hn0 hd0 hc)
      (lt_of_le_of_lt (backwardLastDeterminant_bound num den) hsmall)
  have hf : forwardChordCoefficient num 2 • Q + (forwardChordCoefficient den 2 + 3) • R ≠ 0 :=
    combination_nonzero_of_small_determinant hq num den _ _ hrel
      (forwardLastDeterminant_nonzero num den hn0 hd0 hc)
      (lt_of_le_of_lt (forwardLastDeterminant_bound num den) (by linarith [hsmall]))
  constructor
  · intro h
    apply hb
    have hz := sub_eq_zero.mpr h
    convert hz using 1 <;>
      simp only [lastRow, middleRow, middleAccumulator, backwardChordCoefficient,
        sub_zsmul, add_zsmul, mul_zsmul, zsmul_add, zsmul_sub] <;> abel
  · intro h
    apply hf
    have hz : (2 : ℤ) • middleAccumulator num den 2 Q R + lastRow num den Q R = 0 := by
      rw [h, neg_add_cancel]
    convert hz using 1 <;>
      simp only [lastRow, middleRow, middleAccumulator, forwardChordCoefficient,
        sub_zsmul, add_zsmul, mul_zsmul, zsmul_add, zsmul_sub] <;> abel

end ZolanaVE.P256.Completeness
