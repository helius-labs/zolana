import VerifiableEncryption.Curve.CombChain
import VerifiableEncryption.Curve.LadderEnd

/-!
Scalar-level facts of the fixed-base comb: the recoded scalar's limbs and
windows, the signed window digits, and the final sum.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks ZolanaVE.P256.Comb

theorem bit_get {len : ℕ} {g : List.Vector F len} (hb : AllBits g) (i : Fin len) : GatesDef.is_bool (g.get i) := by
  rw [vget_getD]; exact hb i i.2

/-- The recoded scalar's eight 32-bit limbs, bits `1..256`. -/
def rcInts {len : ℕ} (g : List.Vector F len) (l : Fin 8) : ℤ := chunk g (1 + 32 * l.val) 32

theorem rec8_rcInts {len : ℕ} (g : List.Vector F len) : rec8 (rcInts g) = chunk g 1 256 := by
  have e1 := chunk_split g 1 32 224
  have e2 := chunk_split g 33 32 192
  have e3 := chunk_split g 65 32 160
  have e4 := chunk_split g 97 32 128
  have e5 := chunk_split g 129 32 96
  have e6 := chunk_split g 161 32 64
  have e7 := chunk_split g 193 32 32
  simp only [Nat.reduceAdd] at e1 e2 e3 e4 e5 e6 e7
  rw [e1, e2, e3, e4, e5, e6, e7]
  simp only [rec8, rcInts, Fin.isValue, Fin.coe_ofNat_eq_mod, Nat.reduceMod, Fin.val_zero, Nat.reduceMul,
    Nat.reduceAdd, mul_zero, add_zero]
  ring

theorem rcInts_fits {len : ℕ} {g : List.Vector F len} (hb : AllBits g) (hn : 257 ≤ len) : Fits (rcInts g) reducedC := by
  apply fits_uni
  · intro l
    have := chunk_bounds hb (a := 1 + 32 * l.val) (w := 32) (by have := l.2; omega)
    simp only [rcInts]
    constructor <;> linarith [this.1, this.2]
  · rw [rec8_rcInts]
    have := chunk_bounds hb (a := 1) (w := 256) (by omega)
    constructor <;> linarith [this.1, this.2]

/-- The signed digit of window `u`: `2r_u - 31` for the five bits of window `u`. -/
def digOf {len : ℕ} (g : List.Vector F len) (u : ℕ) : ℤ := if u < 51 then 2 * chunk g (1 + 5 * u) 5 - 31 else 1

theorem digOf_bound {len : ℕ} {g : List.Vector F len} (hb : AllBits g) (hn : 257 ≤ len) (u : ℕ) :
    |digOf g u| ≤ 31 ∧ 1 ≤ |digOf g u| := by
  unfold digOf
  split_ifs with hu
  · have := chunk_bounds hb (a := 1 + 5 * u) (w := 5) (by omega)
    have h31 : (2 : ℤ) ^ 5 - 1 = 31 := by norm_num
    rw [h31] at this
    constructor
    · rw [abs_le]; constructor <;> linarith [this.1, this.2]
    · rw [le_abs]; omega
  · norm_num

theorem win_dig {len : ℕ} {g : List.Vector F len} {t i : ℕ} (ht : t < 51) (hi : (i : ℤ) = chunk g (1 + 5 * t) 5) :
    (2 * (i : ℤ) + 1 - 32) = digOf g t := by
  simp only [digOf, ht, if_true, hi]; ring

theorem comb_acc_step {len : ℕ} {g : List.Vector F len} (hb : AllBits g) (hn : 257 ≤ len) {t : ℕ} (ht : t ≤ 50)
    {A W : P} (hA : A = (∑ u ∈ Finset.range t, digOf g u * 2 ^ (5 * u)) • G)
    (hW : W = (digOf g t * 2 ^ (5 * t)) • G) :
    (A ≠ W ∧ A ≠ -W) ∧ A + W = (∑ u ∈ Finset.range (t + 1), digOf g u * 2 ^ (5 * u)) • G := by
  subst hA hW
  refine ⟨chain_x_distinct t ht (digOf g) (fun u => (digOf_bound hb hn u).1) (digOf g t)
    (digOf_bound hb hn t).2 (digOf_bound hb hn t).1, ?_⟩
  rw [Finset.sum_range_succ, add_zsmul]

theorem chunk_windows {len : ℕ} (g : List.Vector F len) :
    ∀ m, chunk g 1 (5 * m) = ∑ t ∈ Finset.range m, chunk g (1 + 5 * t) 5 * 2 ^ (5 * t) := by
  intro m
  induction m with
  | zero => simp [chunk]
  | succ m ih =>
    rw [show 5 * (m + 1) = 5 * m + 5 by ring, chunk_split, ih, Finset.sum_range_succ,
      show 1 + 5 * m = 1 + 5 * m by rfl]
    ring

/-- The top window's scalar from its selector `top + 2π`. -/
theorem top_val {len : ℕ} {g : List.Vector F len} (hb : AllBits g) (hn : 257 ≤ len) {i : ℕ} (hi4 : i < 4)
    (h : g.toList.getD 256 0 + g.toList.getD 0 0 * 2 = ((i : ℕ) : F)) :
    topScalar i = (2 * bitI g 256 - 1) * 2 ^ 255 - (1 - bitI g 0) := by
  obtain ⟨v0, h0, b0, g0⟩ := bit01 hb (a := 256) (by omega)
  obtain ⟨v1, h1, b1, g1⟩ := bit01 hb (a := 0) (by omega)
  rw [← vget_getD' g 256 (by omega), ← vget_getD' g 0 (by omega), g0, g1] at h
  have h' : ((v0 + v1 * 2 : ℕ) : F) = ((i : ℕ) : F) := by push_cast; exact h
  have hv := natCast_inj (lt_order_of_le (by omega)) (lt_order_of_le (by omega)) h'
  rw [b0, b1, ← hv]
  unfold topScalar
  interval_cases v0 <;> interval_cases v1 <;> norm_num

/-- The comb's result: the accumulated windows plus the top window is `s·G`
when the recoding constraint holds. -/
theorem comb_final {len : ℕ} {g : List.Vector F len} {s : ℤ}
    (hrec : 2 * chunk g 1 256 + bitI g 0 ≡ s + 2 ^ 256 [ZMOD n]) {A T : P}
    (hA : A = (∑ u ∈ Finset.range 51, digOf g u * 2 ^ (5 * u)) • G)
    (hT : T = ((2 * bitI g 256 - 1) * 2 ^ 255 - (1 - bitI g 0)) • G) : A + T = s • G := by
  have hc : chunk g 1 256 = ∑ t ∈ Finset.range 51, chunk g (1 + 5 * t) 5 * 2 ^ (5 * t) + bitI g 256 * 2 ^ 255 := by
    rw [show (256 : ℕ) = 5 * 51 + 1 by rfl, chunk_split, chunk_windows]
    simp [chunk]
    ring
  rw [hc] at hrec
  apply comb_result (fun t => chunk g (1 + 5 * t) 5) hrec
  rw [hA, hT, ← Finset.sum_smul]
  have hsum : ∑ u ∈ Finset.range 51, digOf g u * 2 ^ (5 * u) =
      ∑ t ∈ Finset.range 51, (2 * chunk g (1 + 5 * t) 5 - 31) * 2 ^ (5 * t) := by
    apply Finset.sum_congr rfl
    intro u hu
    simp only [Finset.mem_range] at hu
    simp [digOf, hu]
  rw [hsum]

end ZolanaVE.P256
