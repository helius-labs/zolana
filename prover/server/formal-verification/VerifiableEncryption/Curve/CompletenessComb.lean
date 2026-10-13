import VerifiableEncryption.Curve.Completeness
import VerifiableEncryption.Curve.CombBase
import VerifiableEncryption.Curve.CombConstants
import VerifiableEncryption.Field.CompletenessCarry

/-!
Constructive fixed-base components. In particular recodingCheck_complete
constructs the actual extracted scalar-recoding arithmetic check, including
its shifted quotient and carry witnesses. It does not assume that check.
-/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field

set_option maxRecDepth 100000
open scoped BigOperators

def boolNative (b : Bool) : F := if b then 1 else 0

def index4 (b0 b1 : Bool) : Fin 4 :=
  ⟨(if b0 then 1 else 0) + 2 * (if b1 then 1 else 0),
    by cases b0 <;> cases b1 <;> decide⟩

def index32 (b0 b1 b2 b3 b4 : Bool) : Fin 32 :=
  ⟨(if b0 then 1 else 0) + 2 * (if b1 then 1 else 0) +
    4 * (if b2 then 1 else 0) + 8 * (if b3 then 1 else 0) + 16 * (if b4 then 1 else 0),
    by cases b0 <;> cases b1 <;> cases b2 <;> cases b3 <;> cases b4 <;> decide⟩

/-- The actual extracted two-bit comb selector has witnesses for every bit
pair and every constant table. No row lookup or selected-point existence is
assumed: all native intermediates are their displayed arithmetic values. -/
theorem combSelect4_complete (TX TY : List.Vector (List.Vector F 8) 4) (b0 b1 : Bool)
    (k : List.Vector (List.Vector F 8) 2 → Prop)
    (hk : k ((TX.get (index4 b0 b1)) ::ᵥ (TY.get (index4 b0 b1)) ::ᵥ List.Vector.nil)) :
    CombSelect_8_4_8_4_2_h80fdf981 TX TY
      (boolNative b0 ::ᵥ boolNative b1 ::ᵥ List.Vector.nil) k := by
  have hbit0 : (boolNative b0 ::ᵥ boolNative b1 ::ᵥ List.Vector.nil).get 0 = boolNative b0 := rfl
  have hbit1 : (boolNative b0 ::ᵥ boolNative b1 ::ᵥ List.Vector.nil).get 1 = boolNative b1 := rfl
  cases b0 <;> cases b1
  all_goals
    unfold CombSelect_8_4_8_4_2_h80fdf981
    simp only [hbit0, hbit1]
    simpa only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
      GatesDef.add, GatesDef.mul, GatesDef.sub, exists_eq_left,
      boolNative, index4, Bool.false_eq_true, ↓reduceIte,
      mul_one, mul_zero, one_mul, zero_mul, sub_zero, sub_self,
      add_zero, zero_add, vec8_eta] using hk

/-- The packed-y output of the production five-bit comb selector. -/
def selected32 (TX : List.Vector (List.Vector F 8) 32)
    (TY : List.Vector (List.Vector F 3) 32) (i : Fin 32) :
    List.Vector (List.Vector F 8) 2 :=
  (TX.get i) ::ᵥ
    vec![(TY.get i).get 0, (0 : F), (0 : F), (TY.get i).get 1,
      (0 : F), (0 : F), (TY.get i).get 2, (0 : F)] ::ᵥ List.Vector.nil

/-- Witness construction for all thirty-two production comb selections,
including the actual packed y layout consumed by the chain. -/
theorem combSelect32_complete (TX : List.Vector (List.Vector F 8) 32)
    (TY : List.Vector (List.Vector F 3) 32) (b0 b1 b2 b3 b4 : Bool)
    (k : List.Vector (List.Vector F 8) 2 → Prop)
    (hk : k (selected32 TX TY (index32 b0 b1 b2 b3 b4))) :
    CombSelect_8_32_3_32_5_h2261d38e TX TY
      vec![boolNative b0, boolNative b1, boolNative b2, boolNative b3, boolNative b4] k := by
  have hbit0 : vec![boolNative b0, boolNative b1, boolNative b2, boolNative b3, boolNative b4].get 0 = boolNative b0 := rfl
  have hbit1 : vec![boolNative b0, boolNative b1, boolNative b2, boolNative b3, boolNative b4].get 1 = boolNative b1 := rfl
  have hbit2 : vec![boolNative b0, boolNative b1, boolNative b2, boolNative b3, boolNative b4].get 2 = boolNative b2 := rfl
  have hbit3 : vec![boolNative b0, boolNative b1, boolNative b2, boolNative b3, boolNative b4].get 3 = boolNative b3 := rfl
  have hbit4 : vec![boolNative b0, boolNative b1, boolNative b2, boolNative b3, boolNative b4].get 4 = boolNative b4 := rfl
  cases b0 <;> cases b1 <;> cases b2 <;> cases b3 <;> cases b4
  all_goals
    unfold CombSelect_8_32_3_32_5_h2261d38e
    simp only [hbit0, hbit1, hbit2, hbit3, hbit4]
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
      GatesDef.add, GatesDef.mul, GatesDef.sub, exists_eq_left,
      boolNative, Bool.false_eq_true, ↓reduceIte,
      mul_one, mul_zero, one_mul, zero_mul, sub_zero, sub_self, add_zero, zero_add]
    unfold CombSelect_8_32_3_32_5_h2261d38e_p1
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
      GatesDef.add, GatesDef.mul, GatesDef.sub, exists_eq_left,
      mul_one, mul_zero, one_mul, zero_mul, sub_zero, sub_self, add_zero, zero_add]
    unfold CombSelect_8_32_3_32_5_h2261d38e_p2
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
      GatesDef.add, GatesDef.mul, GatesDef.sub, exists_eq_left,
      mul_one, mul_zero, one_mul, zero_mul, sub_zero, sub_self, add_zero, zero_add]
    unfold CombSelect_8_32_3_32_5_h2261d38e_p3
    simpa only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
      GatesDef.add, GatesDef.mul, GatesDef.sub, exists_eq_left,
      boolNative, index32, selected32, Bool.false_eq_true, ↓reduceIte,
      mul_one, mul_zero, one_mul, zero_mul, sub_zero, sub_self,
      add_zero, zero_add, vec8_eta] using hk

def tail8 (x : Fin 8 → ℤ) : ℤ :=
  x 1 + 2 ^ 32 * x 2 + 2 ^ 64 * x 3 + 2 ^ 96 * x 4 +
    2 ^ 128 * x 5 + 2 ^ 160 * x 6 + 2 ^ 192 * x 7

theorem rec8_split_low (x : Fin 8 → ℤ) : rec8 x = x 0 + 2 ^ 32 * tail8 x := by
  unfold rec8 tail8
  ring

/-- The production recoding certificate has sufficient carry capacity;
this is a closed numerical property, not an assumed operation-success fact. -/
theorem recodingCarry_capacity :
    CarryCapacity (ZolanaVE.EmcurveChecks.cert_hcd1dd84c.residualBound ZolanaVE.EmcurveChecks.basis)
      8 1 ZolanaVE.EmcurveChecks.cert_hcd1dd84c.groups 0 none := by
  change CarryCapacity
    (ZolanaVE.EmcurveChecks.cert_hcd1dd84c.residualBound ZolanaVE.EmcurveChecks.basis)
    8 1 [⟨0, 1, 3, 20520227687253066844553443099509678173442728246946192144187700041656053926509⟩]
    0 none
  apply CarryCapacity.cons
  · rfl
  · norm_num
  · norm_num
  · norm_num
  · decide +kernel
  · decide +kernel
  · exact CarryCapacity.nil _

def recodingInput (r s : Fin 8 → ℤ) (parity : ℕ) : List.Vector F 25 :=
  vec![(r 0 : F), (r 1 : F), (r 2 : F), (r 3 : F), (r 4 : F), (r 5 : F), (r 6 : F), (r 7 : F),
    (parity : F), (s 0 : F), (s 1 : F), (s 2 : F), (s 3 : F), (s 4 : F), (s 5 : F), (s 6 : F), (s 7 : F),
    (60611247 : F), (205927741 : F), (1491624315 : F), (1125713234 : F),
    (0 : F), (0 : F), (4294967295 : F), (0 : F)]

/-- The actual extracted fixed-base recoding check. The integer hypotheses
are limb bounds and the scalar recoding identity, not satisfying constraints.
The quotient and low carry are constructed by division here. -/
theorem recodingCheck_complete (hr : RangeComplete)
    (r s : Fin 8 → ℤ) (parity : ℕ) (q : ℤ)
    (hr0 : 0 ≤ r 0 ∧ r 0 < 2 ^ 32)
    (hs0 : 0 ≤ s 0 ∧ s 0 < 2 ^ 32)
    (hparity : parity = 0 ∨ parity = 1) (hq : q = 0 ∨ q = 1)
    (hrec : 2 * rec8 r + parity - rec8 s - rec8 twoPowLimbs = q * n) :
    CheckPolynomial_25_hcd1dd84c (recodingInput r s parity) := by
  let C : ℤ := rec8 twoPowLimbs
  let D : ℤ := 2 * r 0 + parity - s 0 - 60611247 - q * 4234356049
  have hC : C = 60611247 + 2 ^ 32 * (C / 2 ^ 32) := by
    decide +kernel
  have hn : (n : ℤ) = 4234356049 + 2 ^ 32 * ((n : ℤ) / 2 ^ 32) := by
    decide +kernel
  have hD : (2 : ℤ) ^ 32 ∣ D := by
    refine ⟨-(2 * tail8 r - tail8 s - C / 2 ^ 32 - q * ((n : ℤ) / 2 ^ 32)), ?_⟩
    rw [rec8_split_low r, rec8_split_low s] at hrec
    change 2 * (r 0 + 2 ^ 32 * tail8 r) + parity -
      (s 0 + 2 ^ 32 * tail8 s) - C = q * n at hrec
    rw [hC, hn] at hrec
    dsimp [D]
    norm_num [C, rec8, twoPowLimbs, Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod] at hrec ⊢
    linear_combination hrec
  let carry : ℤ := D / 2 ^ 32
  have hcarry : carry * 2 ^ 32 = D := Int.ediv_mul_cancel hD
  have hcarryBounds : -8 ≤ carry ∧ carry < 8 := by
    have hp : 0 ≤ (parity : ℤ) ∧ (parity : ℤ) ≤ 1 := by
      rcases hparity with rfl | rfl <;> norm_num
    have hqBounds : 0 ≤ q ∧ q ≤ 1 := by
      rcases hq with rfl | rfl <;> norm_num
    dsimp [D] at hcarry
    norm_num at hr0 hs0 hcarry
    omega
  have hqRange : RangeCheck 2 ((q + 1 : ℤ) : F) := by
    rcases hq with rfl | rfl
    · simpa using hr 2 1 (by norm_num) (by norm_num) (by norm_num)
    · simpa using hr 2 2 (by norm_num) (by norm_num) (by norm_num)
  have hcRange : RangeCheck 4 ((carry + 8 : ℤ) : F) := by
    have hcNonneg : 0 ≤ carry + 8 := by omega
    have hcLt : (carry + 8).toNat < 2 ^ 4 := by norm_num; omega
    have hcCast : (((carry + 8).toNat : ℕ) : F) = ((carry + 8 : ℤ) : F) := by
      rw [← Int.cast_natCast, Int.toNat_of_nonneg hcNonneg]
    rw [← hcCast]
    exact hr 4 _ (by norm_num) (by norm_num) hcLt
  have hInv : ((2 ^ 32 : ℤ) : F) * K_406 = 1 := by decide +kernel
  have hCarryNative : ((D : ℤ) : F) * K_406 = (carry : F) := by
    rw [← hcarry, Int.cast_mul, mul_assoc, hInv, mul_one]
  unfold CheckPolynomial_25_hcd1dd84c
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, GatesDef.eq, exists_eq_left]
  refine ⟨((q + 1 : ℤ) : F) ::ᵥ List.Vector.nil, hqRange, ?_, ?_, trivial⟩
  · have hrecF := congrArg (fun z : ℤ => (z : F)) hrec
    have hK1235 : K_1235 = (n : F) := by decide +kernel
    have hK18 : K_18 = (-1 : F) := by decide +kernel
    have hK179 : K_179 = -(2 : F) ^ 32 := by decide +kernel
    have hK180 : K_180 = -(2 : F) ^ 64 := by decide +kernel
    have hK181 : K_181 = -(2 : F) ^ 96 := by decide +kernel
    have hK182 : K_182 = -(2 : F) ^ 128 := by decide +kernel
    have hK183 : K_183 = -(2 : F) ^ 160 := by decide +kernel
    have hK184 : K_184 = -(2 : F) ^ 192 := by decide +kernel
    have hK185 : K_185 = -(2 : F) ^ 224 := by decide +kernel
    have hNsum : K_399 + K_400 + K_401 + K_402 + K_403 + K_404 + K_405 = -(n : F) := by
      decide +kernel
    rw [hK1235, hK18, hK179, hK180, hK181, hK182, hK183, hK184, hK185]
    norm_num [recodingInput, rec8, twoPowLimbs, List.Vector.get, List.Vector.head,
      Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod,
      K_1236, K_1237, K_1238, K_1239, K_1240, K_1241] at hrecF ⊢
    push_cast at hrecF ⊢
    linear_combination hrecF + ((q : F) + 1) * hNsum
  · convert hcRange using 1
    have hDN : ((D : ℤ) : F) = 4234356049 + (r 0 : F) * 2 + (parity : F) * 1 +
        (s 0 : F) * K_18 + (60611247 : F) * K_18 +
        (0 + ((q + 1 : ℤ) : F) * 1) * K_399 := by
      dsimp [D]
      have hK18 : K_18 = (-1 : F) := by decide +kernel
      have hK399 : K_399 = (-4234356049 : F) := by decide +kernel
      rw [hK18, hK399]
      push_cast
      ring
    change (4234356049 + (r 0 : F) * 2 + (parity : F) * 1 +
      (s 0 : F) * K_18 + (60611247 : F) * K_18 +
      (0 + ((q + 1 : ℤ) : F) * 1) * K_399 + 0) * K_406 + 8 =
        ((carry + 8 : ℤ) : F)
    rw [← hDN, add_zero, hCarryNative]
    push_cast
    ring

/-- Affine witnesses for the final unified addition. The exposed local
noninverse condition is discharged by combFinal_noninverse for valid secret
inputs. This handles its doubling case instead of assuming distinct x. -/
theorem completeAddAffine_exists {xp yp xq yq : Fp}
    (hP : OnCurve xp yp) (hQ : OnCurve xq yq) (hne : mkPoint hP ≠ -mkPoint hQ) :
    ∃ sameX : Bool, ∃ l xs ys : Fp,
      (if sameX then (1 : Fp) else 0) * (xq - xp) = 0 ∧
      (if sameX then (1 : Fp) else 0) * (yq - yp) = 0 ∧
      l * (xq - xp) + 2 * l * (if sameX then 1 else 0) * yp -
        3 * (if sameX then 1 else 0) * xp ^ 2 +
        3 * (if sameX then 1 else 0) - (yq - yp) = 0 ∧
      xs = l ^ 2 - xp - xq ∧ ys = l * (xp - xs) - yp ∧
      ∃ hS : OnCurve xs ys, mkPoint hP + mkPoint hQ = mkPoint hS := by
  by_cases hx : xp = xq
  · have he : mkPoint hP = mkPoint hQ :=
      (eq_or_eq_neg_of_x_eq hP hQ hx).resolve_right hne
    have hy := (mkPoint_inj.mp he).2
    obtain ⟨l, xs, ys, hl, hxs, hys, hS, hsum⟩ := affineDouble_exists hP
    refine ⟨true, l, xs, ys, ?_, ?_, ?_, ?_, hys, hS, ?_⟩
    · simp [hx]
    · simp [hy]
    · simp only [if_true]
      rw [← hx, ← hy]
      linear_combination hl
    · rw [← hx]
      linear_combination hxs
    · rw [← he, ← two_nsmul]
      exact hsum
  · obtain ⟨l, xs, ys, hl, hxs, hys, hS, hsum⟩ := affineAdd_exists hP hQ hx
    refine ⟨false, l, xs, ys, by simp, by simp, ?_, hxs, hys, hS, hsum⟩
    simp only [Bool.false_eq_true, if_false]
    linear_combination hl

end ZolanaVE.P256.Completeness
