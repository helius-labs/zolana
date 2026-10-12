import VerifiableEncryption.Curve.CompletenessLadderBits

/-! Construct native binary chunks and the positive-denominator guard used
by ScalarMulChecked p2/p3 from the mathematical signed decomposition. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field
open scoped BigOperators

def ladderBitSlice (g : List.Vector F 259) (a w : ℕ) (hw : a + w ≤ 259) : List.Vector F w :=
  List.Vector.ofFn (fun j => g.get ⟨a + j.val, by omega⟩)

theorem allBits_getNativeBool {n : ℕ} (g : List.Vector F n) (hb : AllBits g) (j : Fin n) :
    GatesDef.is_bool (g.get j) := by
  have he := hb j.val j.isLt
  rw [← vget_getD' g j.val j.isLt] at he
  exact he

def nativeBitSum (g : List.Vector F 259) (start : ℕ) : (count : ℕ) → start + count ≤ 259 → F
  | 0, _ => 0
  | count + 1, hb => nativeBitSum g start count (by omega) + g.get ⟨start + count, by omega⟩

theorem nativeBitSum_eq (g : List.Vector F 259) (start count : ℕ) (hb : start + count ≤ 259) :
    nativeBitSum g start count hb = ∑ j : Fin count, g.get ⟨start + j.val, by omega⟩ := by
  induction count with
  | zero => simp [nativeBitSum]
  | succ count ih =>
    rw [nativeBitSum, Fin.sum_univ_castSucc, ih (by omega)]
    rfl

theorem ladderBitSlice_fromBinary (g : List.Vector F 259) (hb : AllBits g)
    (a w : ℕ) (hw : a + w ≤ 259) :
    GatesDef.from_binary (ladderBitSlice g a w hw) ((chunk g a w : ℤ) : F) := by
  constructor
  · rw [ladderBitSlice, recover_ofFn, chunk_cast hb hw]
    apply Finset.sum_congr rfl
    intro j hj
    rw [vget_getD']
  · intro value hv
    change value ∈ (ladderBitSlice g a w hw).toList at hv
    rw [ladderBitSlice, List.Vector.toList_ofFn] at hv
    obtain ⟨j, rfl⟩ := (List.mem_ofFn _ _).mp hv
    have he := hb (a + j.val) (by omega)
    rw [← vget_getD' g (a + j.val) (by omega), is_bool_is_bit] at he
    exact he

theorem testBit_shift_sum (value a w : ℕ) :
    (∑ j ∈ Finset.range w, 2 ^ j * ((value.testBit (a + j)).toNat : ℕ)) =
      value / 2 ^ a % 2 ^ w := by
  have he := testBit_sum (value / 2 ^ a) w
  have hb : ∀ j, ((value / 2 ^ a).testBit j).toNat = (value.testBit (a + j)).toNat := by
    intro j
    rw [Nat.toNat_testBit, Nat.toNat_testBit, Nat.div_div_eq_div_mul, pow_add]
  simpa only [hb] using he

theorem ladderBits_word (sign : Bool) (num den a w : ℕ) (hn : a + w ≤ 129) :
    chunk (ladderBits sign num den) (1 + a) w = ((num / 2 ^ a % 2 ^ w : ℕ) : ℤ) := by
  have he := congrArg (fun v : ℕ => (v : ℤ)) (testBit_shift_sum num a w)
  simp only [Nat.cast_sum, Nat.cast_mul, Nat.cast_pow, Nat.cast_ofNat] at he
  unfold chunk
  calc
    _ = ∑ j ∈ Finset.range w, (2 : ℤ) ^ j * ((num.testBit (a + j)).toNat : ℤ) := by
      apply Finset.sum_congr rfl
      intro j hj
      rw [show 1 + a + j = 1 + (a + j) by omega,
        ladderBits_num sign num den (a + j) (by have := Finset.mem_range.mp hj; omega)]
    _ = _ := he

theorem ladderBits_den_word (sign : Bool) (num den a w : ℕ) (hn : a + w ≤ 129) :
    chunk (ladderBits sign num den) (130 + a) w = ((den / 2 ^ a % 2 ^ w : ℕ) : ℤ) := by
  have he := congrArg (fun v : ℕ => (v : ℤ)) (testBit_shift_sum den a w)
  simp only [Nat.cast_sum, Nat.cast_mul, Nat.cast_pow, Nat.cast_ofNat] at he
  unfold chunk
  calc
    _ = ∑ j ∈ Finset.range w, (2 : ℤ) ^ j * ((den.testBit (a + j)).toNat : ℤ) := by
      apply Finset.sum_congr rfl
      intro j hj
      rw [show 130 + a + j = 130 + (a + j) by omega,
        ladderBits_den sign num den (a + j) (by have := Finset.mem_range.mp hj; omega)]
    _ = _ := he

def ladderDenSum (sign : Bool) (num den : ℕ) : F :=
  ∑ j : Fin 129, (ladderBits sign num den).get ⟨130 + j.val, by omega⟩

theorem ladderDenSum_nonzero (sign : Bool) (num den : ℕ) (hd0 : 0 < den) (hd : den < 2 ^ 129) :
    ladderDenSum sign num den ≠ 0 := by
  let g := ladderBits sign num den
  let total : ℤ := ∑ j ∈ Finset.range 129, bitI g (130 + j)
  have hbit : ∀ j < 129, bitI g (130 + j) = 0 ∨ bitI g (130 + j) = 1 := by
    intro j hj
    exact (bitI_of_bool (ladderBits_all sign num den (130 + j) (by omega))).1
  have hnonneg : ∀ j ∈ Finset.range 129, 0 ≤ bitI g (130 + j) := by
    intro j hj
    rcases hbit j (Finset.mem_range.mp hj) with he | he <;> simp [he]
  have hbound : total ≤ 129 := by
    calc
      total ≤ ∑ j ∈ Finset.range 129, (1 : ℤ) := by
        apply Finset.sum_le_sum
        intro j hj
        rcases hbit j (Finset.mem_range.mp hj) with he | he <;> simp [he]
      _ = 129 := by simp
  have htotal0 : 0 ≤ total := Finset.sum_nonneg hnonneg
  have hpos : 0 < total := by
    by_contra hp
    have ht : total = 0 := by omega
    have hz := (Finset.sum_eq_zero_iff_of_nonneg hnonneg).mp ht
    have hc : chunk g 130 129 = 0 := by
      unfold chunk
      apply Finset.sum_eq_zero
      intro j hj
      rw [hz j hj, mul_zero]
    have hd' := ladderBits_den_chunk sign num den hd
    change chunk g 130 129 = (den : ℤ) at hd'
    omega
  have hcast : (total : F) = ladderDenSum sign num den := by
    dsimp [total, ladderDenSum]
    push_cast
    rw [Finset.sum_range]
    apply Finset.sum_congr rfl
    intro j hj
    exact ((bitI_of_bool (ladderBits_all sign num den (130 + j.val) (by omega))).2).trans
      (vget_getD' g (130 + j.val) (by omega)).symm
  intro hz
  have hzero : total = 0 := int_eq_zero_of_cast (hcast.trans hz) (by
    rw [abs_of_pos hpos]
    exact lt_of_le_of_lt hbound (by norm_num [Order]))
  omega

end ZolanaVE.P256.Completeness
