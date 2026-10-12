import VerifiableEncryption.Curve.CompletenessQuadMath
import VerifiableEncryption.Curve.CompletenessLadderLast

/-! Final-step output finiteness follows from the primitive decomposition.
The num-even case forces den odd; all determinant bounds are far below n.
No point-validity or operation-success branch is added to the input domain. -/

namespace ZolanaVE.P256.Completeness

def finalNumCoefficient (num : ℕ) : ℤ := 1 - ((num % 2 : ℕ) : ℤ)
def finalDenCoefficient (den : ℕ) : ℤ := 4 - ((den % 2 : ℕ) : ℤ)

theorem finalDeterminant_nonzero (num den : ℕ) (hn : 0 < num)
    (hc : Nat.Coprime num den) :
    finalNumCoefficient num * den - finalDenCoefficient den * num ≠ 0 := by
  by_cases he : num % 2 = 0
  · have hd := primitive_den_odd_of_num_even num den hc he
    have hn2 : 1 < num := by omega
    simpa only [finalNumCoefficient, finalDenCoefficient, he, hd, Nat.cast_zero,
      Nat.cast_one, sub_zero, show (4 : ℤ) - 1 = 3 from rfl] using
      primitive_determinant_nonzero_of_small num den 1 3 hc (by norm_num)
        (by norm_num; exact_mod_cast hn2)
  · have hn1 : num % 2 = 1 := by omega
    have hd2 := Nat.mod_lt den (by decide : 0 < 2)
    have hdPos : (0 : ℤ) < finalDenCoefficient den := by
      unfold finalDenCoefficient
      omega
    have hnPos : (0 : ℤ) < num := by exact_mod_cast hn
    simp only [finalNumCoefficient, hn1, Nat.cast_one, sub_self, zero_mul, zero_sub]
    exact neg_ne_zero.mpr (mul_ne_zero hdPos.ne' hnPos.ne')

theorem finalDeterminant_bound (num den : ℕ) :
    |finalNumCoefficient num * den - finalDenCoefficient den * num| ≤ (den : ℤ) + 4 * num := by
  have hn2 := Nat.mod_lt num (by decide : 0 < 2)
  have hd2 := Nat.mod_lt den (by decide : 0 < 2)
  have hnC : 0 ≤ finalNumCoefficient num ∧ finalNumCoefficient num ≤ 1 := by
    unfold finalNumCoefficient; omega
  have hdC : 0 ≤ finalDenCoefficient den ∧ finalDenCoefficient den ≤ 4 := by
    unfold finalDenCoefficient; omega
  calc
    _ ≤ |finalNumCoefficient num * den| + |finalDenCoefficient den * num| := abs_sub _ _
    _ = finalNumCoefficient num * den + finalDenCoefficient den * num := by
      rw [abs_of_nonneg (mul_nonneg hnC.1 (by positivity)),
        abs_of_nonneg (mul_nonneg hdC.1 (by positivity))]
    _ ≤ _ := by
      have h1 := mul_le_mul_of_nonneg_right hnC.2 (show (0 : ℤ) ≤ den by positivity)
      have h2 := mul_le_mul_of_nonneg_right hdC.2 (show (0 : ℤ) ≤ num by positivity)
      linarith

theorem finalCombination_nonzero {Q R : P} (hq : Q ≠ 0) (num den : ℕ)
    (hn0 : 0 < num) (hn : num < 2 ^ 129) (hd : den < 2 ^ 129)
    (hc : Nat.Coprime num den) (hrel : (num : ℤ) • Q + (den : ℤ) • R = 0) :
    finalNumCoefficient num • Q + finalDenCoefficient den • R ≠ 0 := by
  have hcap : 5 * (2 : ℕ) ^ 129 < n := by norm_num [n]
  have hsmall : (den : ℤ) + 4 * num < (n : ℤ) := by
    have hh : den + 4 * num < n := by omega
    exact_mod_cast hh
  exact combination_nonzero_of_small_determinant hq num den _ _ hrel
    (finalDeterminant_nonzero num den hn0 hc)
    (lt_of_le_of_lt (finalDeterminant_bound num den) hsmall)

theorem finalQuad_output_nonzero {Q R : P} (hq : Q ≠ 0) (num den : ℕ)
    (hn0 : 0 < num) (hn : num < 2 ^ 129) (hd : den < 2 ^ 129)
    (hc : Nat.Coprime num den) (hrel : (num : ℤ) • Q + (den : ℤ) • R = 0) :
    (4 : ℤ) • middleAccumulator num den 2 Q R + lastRow num den Q R ≠ 0 := by
  have he : (4 : ℤ) • middleAccumulator num den 2 Q R + lastRow num den Q R =
      finalNumCoefficient num • Q + finalDenCoefficient den • R := by
    calc
      _ = (prefixCoefficient num 2 : ℤ) • Q +
          ((prefixCoefficient den 2 : ℤ) + 3) • R := by
        simp only [lastRow, middleRow, middleAccumulator, zsmul_add,
          add_zsmul, sub_zsmul, mul_zsmul]
        abel
      _ = ((num : ℤ) • Q + (den : ℤ) • R) +
          (finalNumCoefficient num • Q + finalDenCoefficient den • R) := by
        rw [prefixCoefficient_lowbit num, prefixCoefficient_lowbit den]
        simp only [finalNumCoefficient, finalDenCoefficient, add_zsmul, sub_zsmul]
        abel
      _ = _ := by rw [hrel, zero_add]
  rw [he]
  exact finalCombination_nonzero hq num den hn0 hn hd hc hrel

end ZolanaVE.P256.Completeness
