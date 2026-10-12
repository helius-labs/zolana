import VerifiableEncryption.Curve.Parameters

/-!
Structurally recursive arithmetic for the two concrete curve certificates.
The binary power has one recursive call per exponent bit. Fermat's theorem
proves that its inverse is exactly the ordinary base-field inverse; this
changes only the arithmetic checker representation, not its mathematics.
-/

namespace ZolanaVE.ParameterCertificates.CurveOrderArithmetic

open ZolanaVE.P256

def fpPow : ℕ → ℕ → Fp → Fp
  | 0, _, _ => 1
  | fuel + 1, exponent, base =>
    let half := fpPow fuel (exponent / 2) base
    let square := half * half
    if exponent % 2 = 0 then square else square * base

theorem fpPow_eq (fuel exponent : ℕ) (base : Fp) (bound : exponent < 2 ^ fuel) :
    fpPow fuel exponent base = base ^ exponent := by
  induction fuel generalizing exponent with
  | zero =>
    have he : exponent = 0 := by simpa using bound
    subst exponent
    simp [fpPow]
  | succ fuel ih =>
    have halfBound : exponent / 2 < 2 ^ fuel := by
      rw [pow_succ] at bound
      omega
    have half := ih (exponent / 2) halfBound
    rcases Nat.mod_two_eq_zero_or_one exponent with heven | hodd
    · have hsum : exponent / 2 + exponent / 2 = exponent := by
        have h := Nat.mod_add_div exponent 2
        omega
      simp only [fpPow, if_pos heven, half]
      rw [← pow_add, hsum]
    · have hsum : exponent / 2 + exponent / 2 + 1 = exponent := by
        have h := Nat.mod_add_div exponent 2
        omega
      have hne : exponent % 2 ≠ 0 := by omega
      simp only [fpPow, if_neg hne, half]
      rw [← pow_add, ← pow_succ, hsum]

def fpInverse (value : Fp) : Fp :=
  if value = 0 then 0 else fpPow 256 (p - 2) value

theorem fpInverse_eq (value : Fp) : fpInverse value = value⁻¹ := by
  by_cases hz : value = 0
  · subst value
    simp [fpInverse]
  ·
    have bound : p - 2 < 2 ^ 256 := by decide +kernel
    have fermat : value ^ p = value := by
      simpa only [ZMod.card] using (FiniteField.pow_card value)
    have exponent : p - 2 + 1 + 1 = p := by decide +kernel
    have doubleProduct : (value ^ (p - 2) * value) * value = value :=
      (congrArg (fun z : Fp => z * value) (pow_succ value (p - 2)).symm).trans
        ((pow_succ value (p - 2 + 1)).symm.trans
          ((congrArg (fun e : ℕ => value ^ e) exponent).trans fermat))
    have product : value ^ (p - 2) * value = 1 :=
      mul_right_cancel₀ hz (doubleProduct.trans (one_mul value).symm)
    exact (if_neg hz).trans ((fpPow_eq 256 (p - 2) value bound).trans
      (inv_eq_of_mul_eq_one_left product).symm)

end ZolanaVE.ParameterCertificates.CurveOrderArithmetic
