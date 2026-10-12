import VerifiableEncryption.Curve.Bits
import VerifiableEncryption.Curve.CompletenessLadderChords

/-!
The actual 259 hinted bits: sign, 129 numerator bits, 129 denominator bits.
Their boolean gates and reconstructed integer chunks are constructed directly.
The four-bit lookup selector is connected to the mathematical prefix row.
No successful hint or row lookup is assumed in these statements.
-/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field
open scoped BigOperators

def ladderBits (sign : Bool) (num den : ℕ) : List.Vector F 259 :=
  List.Vector.ofFn fun i => Bool.toZMod (N := Order)
    (if i.val = 0 then sign else if i.val < 130 then num.testBit (i.val - 1)
      else den.testBit (i.val - 130))

private theorem bool_native_val (b : Bool) :
    (((Bool.toZMod (N := Order) b).val : ℕ) : ℤ) = b.toNat := by
  cases b <;> simp [Bool.toZMod, ZMod.val_one]

theorem ladderBits_bitI (sign : Bool) (num den j : ℕ) (hj : j < 259) :
    bitI (ladderBits sign num den) j =
      if j = 0 then (sign.toNat : ℤ)
      else if j < 130 then ((num.testBit (j - 1)).toNat : ℤ)
      else ((den.testBit (j - 130)).toNat : ℤ) := by
  unfold bitI
  rw [← vget_getD' (ladderBits sign num den) j hj]
  simp only [ladderBits, List.Vector.get_ofFn]
  split_ifs <;> exact bool_native_val _

theorem ladderBits_boolean (sign : Bool) (num den : ℕ) (i : Fin 259) :
    GatesDef.is_bool ((ladderBits sign num den).get i) := by
  simp only [ladderBits, List.Vector.get_ofFn]
  generalize hb : (if i.val = 0 then sign else if i.val < 130 then num.testBit (i.val - 1)
    else den.testBit (i.val - 130)) = b
  cases b <;> simp [Bool.toZMod, GatesDef.is_bool]

theorem ladderBits_all (sign : Bool) (num den : ℕ) : AllBits (ladderBits sign num den) := by
  intro j hj
  rw [← vget_getD' _ j hj]
  exact ladderBits_boolean sign num den ⟨j, hj⟩

theorem ladderBits_num (sign : Bool) (num den j : ℕ) (hj : j < 129) :
    bitI (ladderBits sign num den) (1 + j) = ((num.testBit j).toNat : ℤ) := by
  rw [ladderBits_bitI sign num den (1 + j) (by omega)]
  simp only [if_neg (show 1 + j ≠ 0 by omega), if_pos (show 1 + j < 130 by omega),
    show 1 + j - 1 = j by omega]

theorem ladderBits_den (sign : Bool) (num den j : ℕ) (hj : j < 129) :
    bitI (ladderBits sign num den) (130 + j) = ((den.testBit j).toNat : ℤ) := by
  rw [ladderBits_bitI sign num den (130 + j) (by omega)]
  simp only [if_neg (show 130 + j ≠ 0 by omega), if_neg (show ¬130 + j < 130 by omega),
    show 130 + j - 130 = j by omega]

theorem testBit_sum (value width : ℕ) :
    (∑ j ∈ Finset.range width, 2 ^ j * (value.testBit j).toNat) = value % 2 ^ width := by
  induction width with
  | zero => simp only [Finset.range_zero, Finset.sum_empty, pow_zero, Nat.mod_one]
  | succ width ih =>
    rw [Finset.sum_range_succ, ih, Nat.toNat_testBit, pow_succ]
    have h := Nat.div_add_mod (value % (2 ^ width * 2)) (2 ^ width)
    rw [Nat.mod_mul_right_div_self,
      Nat.mod_mod_of_dvd value (dvd_mul_right (2 ^ width) 2)] at h
    simpa only [Nat.mul_comm, Nat.add_comm] using h

theorem ladderBits_num_chunk (sign : Bool) (num den : ℕ) (hn : num < 2 ^ 129) :
    chunk (ladderBits sign num den) 1 129 = num := by
  unfold chunk
  have h := testBit_sum num 129
  rw [Nat.mod_eq_of_lt hn] at h
  have he : (∑ j ∈ Finset.range 129, (2 : ℤ) ^ j * bitI (ladderBits sign num den) (1 + j)) =
      ∑ j ∈ Finset.range 129, (2 : ℤ) ^ j * ((num.testBit j).toNat : ℤ) := by
    apply Finset.sum_congr rfl
    intro j hj
    rw [ladderBits_num sign num den j (Finset.mem_range.mp hj)]
  rw [he]
  exact_mod_cast h

theorem ladderBits_den_chunk (sign : Bool) (num den : ℕ) (hd : den < 2 ^ 129) :
    chunk (ladderBits sign num den) 130 129 = den := by
  unfold chunk
  have h := testBit_sum den 129
  rw [Nat.mod_eq_of_lt hd] at h
  have he : (∑ j ∈ Finset.range 129, (2 : ℤ) ^ j * bitI (ladderBits sign num den) (130 + j)) =
      ∑ j ∈ Finset.range 129, (2 : ℤ) ^ j * ((den.testBit j).toNat : ℤ) := by
    apply Finset.sum_congr rfl
    intro j hj
    rw [ladderBits_den sign num den j (Finset.mem_range.mp hj)]
  rw [he]
  exact_mod_cast h

theorem ladderBoolRun_complete (sign : Bool) (num den : ℕ) :
    ∀ (j count : ℕ) (R : Prop), j + count ≤ 259 → R → BoolRun (ladderBits sign num den) j count R
  | j, 0, R, hb, hr => hr
  | j, count + 1, R, hb, hr => by
    have hj : j < 259 := by omega
    simp only [BoolRun, dif_pos hj]
    exact ⟨ladderBits_boolean sign num den ⟨j, hj⟩,
      ladderBoolRun_complete sign num den (j + 1) count R (by omega) hr⟩

theorem twoBit_word (value k : ℕ) :
    value / 2 ^ k % 4 = (value.testBit k).toNat + 2 * (value.testBit (k + 1)).toNat := by
  rw [Nat.toNat_testBit, Nat.toNat_testBit, pow_succ, ← Nat.div_div_eq_div_mul]
  have h := Nat.div_add_mod (value / 2 ^ k % 4) 2
  have hq := Nat.mod_mul_right_div_self (value / 2 ^ k) 2 2
  norm_num only [Nat.reduceMul] at hq
  rw [hq, Nat.mod_mod_of_dvd (value / 2 ^ k) (by decide : 2 ∣ 4)] at h
  simpa only [Nat.mul_comm, Nat.add_comm] using h.symm

def ladderSelector (num den i : ℕ) : ℕ :=
  (num.testBit i).toNat + 2 * (den.testBit i).toNat +
    4 * (num.testBit (i - 1)).toNat + 8 * (den.testBit (i - 1)).toNat

theorem ladderSelector_lt (num den i : ℕ) : ladderSelector num den i < 16 := by
  have h1 : (num.testBit i).toNat ≤ 1 := by cases num.testBit i <;> decide
  have h2 : (den.testBit i).toNat ≤ 1 := by cases den.testBit i <;> decide
  have h3 : (num.testBit (i - 1)).toNat ≤ 1 := by cases num.testBit (i - 1) <;> decide
  have h4 : (den.testBit (i - 1)).toNat ≤ 1 := by cases den.testBit (i - 1) <;> decide
  unfold ladderSelector
  omega

theorem ladderSelector_digits (num den i : ℕ) (hi : 0 < i) :
    Ladder.digQ (ladderSelector num den i) = 2 * ((num / 2 ^ (i - 1) % 4 : ℕ) : ℤ) - 3 ∧
    Ladder.digR (ladderSelector num den i) = 2 * ((den / 2 ^ (i - 1) % 4 : ℕ) : ℤ) - 3 := by
  rw [twoBit_word, twoBit_word, show i - 1 + 1 = i by omega]
  cases h1 : num.testBit i <;> cases h2 : den.testBit i <;>
    cases h3 : num.testBit (i - 1) <;> cases h4 : den.testBit (i - 1) <;>
    norm_num [ladderSelector, Ladder.digQ, Ladder.digR, h1, h2, h3, h4]

theorem ladderSelector_row (num den i : ℕ) (hi : 0 < i) (Q R : P) :
    Ladder.rowPoint (ladderSelector num den i) Q R = middleRow num den (2 ^ (i - 1)) Q R := by
  rw [Ladder.row_point Q R _ (ladderSelector_lt num den i), middleRow_coefficients]
  obtain ⟨hq, hr⟩ := ladderSelector_digits num den i hi
  rw [hq, hr]

end ZolanaVE.P256.Completeness
