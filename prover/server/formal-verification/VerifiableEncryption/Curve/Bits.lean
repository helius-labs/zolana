import VerifiableEncryption.Curve.Select

/-!
Hinted bits: `api.AssertIsBoolean`, `api.FromBinary` chunks and the
129-bit integers of `scalarFromBits`.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field

/-- The integer a native value stands for, as a bit. -/
def bitI {n : ℕ} (g : List.Vector F n) (j : ℕ) : ℤ := ((g.toList.getD j 0).val : ℤ)

theorem bitI_of_bool {n : ℕ} {g : List.Vector F n} {j : ℕ} (h : GatesDef.is_bool (g.toList.getD j 0)) :
    (bitI g j = 0 ∨ bitI g j = 1) ∧ ((bitI g j : ℤ) : F) = g.toList.getD j 0 := by
  unfold bitI
  refine ⟨?_, by simp⟩
  unfold GatesDef.is_bool at h
  rcases mul_eq_zero.mp h with h | h
  · right
    have : g.toList.getD j 0 = 1 := by linear_combination -h
    rw [this, ZMod.val_one]; norm_num
  · left
    rw [h, ZMod.val_zero]; norm_num

theorem recover_ofFn {d : ℕ} (f : Fin d → F) :
    recover_binary_zmod' (List.Vector.ofFn f) = ∑ j : Fin d, 2 ^ j.val * f j := by
  induction d with
  | zero => simp [recover_binary_zmod']
  | succ d ih =>
    simp only [recover_binary_zmod']
    rw [List.Vector.head_ofFn, List.Vector.tail_ofFn, ih, Fin.sum_univ_succ, Finset.mul_sum]
    congr 1
    · simp
    · apply Finset.sum_congr rfl; intro j _; simp [Fin.val_succ, pow_succ]; ring

/-- Bits `a, …, a+w-1` of a hinted vector, read little-endian. -/
def chunk {n : ℕ} (g : List.Vector F n) (a w : ℕ) : ℤ := ∑ j ∈ Finset.range w, 2 ^ j * bitI g (a + j)

/-- All bits of a hinted vector are boolean. -/
def AllBits {n : ℕ} (g : List.Vector F n) : Prop := ∀ j < n, GatesDef.is_bool (g.toList.getD j 0)

theorem chunk_bounds {n : ℕ} {g : List.Vector F n} (hb : AllBits g) {a w : ℕ} (hw : a + w ≤ n) :
    0 ≤ chunk g a w ∧ chunk g a w ≤ 2 ^ w - 1 := by
  induction w with
  | zero => simp [chunk]
  | succ w ih =>
    obtain ⟨h0, h1⟩ := ih (by omega)
    have hbit := (bitI_of_bool (hb (a + w) (by omega))).1
    unfold chunk at *
    rw [Finset.sum_range_succ, pow_succ]
    have hp : (0 : ℤ) < 2 ^ w := by positivity
    rcases hbit with hz | ho
    · rw [hz]; constructor <;> nlinarith
    · rw [ho]; constructor <;> nlinarith

theorem chunk_split {n : ℕ} (g : List.Vector F n) (a w1 w2 : ℕ) :
    chunk g a (w1 + w2) = chunk g a w1 + 2 ^ w1 * chunk g (a + w1) w2 := by
  unfold chunk
  rw [Finset.sum_range_add, Finset.mul_sum]
  congr 1
  apply Finset.sum_congr rfl
  intro j _
  rw [pow_add, show a + (w1 + j) = a + w1 + j by ring]
  ring

theorem chunk_cast {n : ℕ} {g : List.Vector F n} (hb : AllBits g) {a w : ℕ} (hw : a + w ≤ n) :
    ((chunk g a w : ℤ) : F) = ∑ j : Fin w, 2 ^ j.val * g.toList.getD (a + j) 0 := by
  unfold chunk
  push_cast
  rw [Finset.sum_range (fun j => (2 : F) ^ j * ((bitI g (a + j) : ℤ) : F))]
  apply Finset.sum_congr rfl
  intro j _
  rw [(bitI_of_bool (hb (a + j) (by omega))).2]

theorem vget_getD' {n : ℕ} (g : List.Vector F n) (i : ℕ) (h : i < n) :
    g.get ⟨i, h⟩ = g.toList.getD i 0 :=
  vget_getD g ⟨i, h⟩

/-- `api.FromBinary` of a run of hinted bits. -/
theorem fromBinary_chunk {n : ℕ} {g : List.Vector F n} (hb : AllBits g) {a w : ℕ} (hw : a + w ≤ n)
    {v : List.Vector F w} (hv : v = List.Vector.ofFn fun j : Fin w => g.get ⟨a + j, by omega⟩) {out : F}
    (h : GatesDef.from_binary v out) : out = ((chunk g a w : ℤ) : F) := by
  rw [chunk_cast hb hw, ← h.1, hv, recover_ofFn]
  apply Finset.sum_congr rfl
  intro j _
  rw [vget_getD']

/-- A run of `m` boolean assertions on hinted values starting at index `j`,
followed by `R`, in the shape the extractor emits. -/
def BoolRun {n : ℕ} (g : List.Vector F n) : ℕ → ℕ → Prop → Prop
  | _, 0, R => R
  | j, m + 1, R => (if hj : j < n then Gates.is_bool (g.get ⟨j, hj⟩) else False) ∧ BoolRun g (j + 1) m R

theorem boolRun_split {n : ℕ} {g : List.Vector F n} :
    ∀ {j m : ℕ} {R : Prop}, BoolRun g j m R →
      (∀ i, j ≤ i → i < j + m → GatesDef.is_bool (g.toList.getD i 0)) ∧ R
  | _, 0, _, h => ⟨fun i h1 h2 => by omega, h⟩
  | j, m + 1, R, ⟨hb, h⟩ => by
    obtain ⟨hs, hR⟩ := boolRun_split h
    refine ⟨fun i h1 h2 => ?_, hR⟩
    rcases Nat.eq_or_lt_of_le h1 with rfl | hlt
    · split_ifs at hb with hj
      · rw [← vget_getD']; exact hb
    · exact hs i hlt (by omega)

/-- Limbs of `scalarFromBits` over 129 bits starting at `a`: four 32-bit
chunks and one bit. -/
def limbs129 {n : ℕ} (g : List.Vector F n) (a : ℕ) (k : Fin 5) : ℤ :=
  [chunk g a 32, chunk g (a + 32) 32, chunk g (a + 64) 32, chunk g (a + 96) 32, chunk g (a + 128) 1].getD k 0

theorem rec5_limbs129 {n : ℕ} (g : List.Vector F n) (a : ℕ) : rec5 (limbs129 g a) = chunk g a 129 := by
  have e1 := chunk_split g a 32 97
  have e2 := chunk_split g (a + 32) 32 65
  have e3 := chunk_split g (a + 64) 32 33
  have e4 := chunk_split g (a + 96) 32 1
  simp only [show a + 32 + 32 = a + 64 by ring, show a + 64 + 32 = a + 96 by ring,
    show a + 96 + 32 = a + 128 by ring] at e2 e3 e4
  rw [show (129 : ℕ) = 32 + 97 by rfl, e1, show (97 : ℕ) = 32 + 65 by rfl, e2, show (65 : ℕ) = 32 + 33 by rfl,
    e3, show (33 : ℕ) = 32 + 1 by rfl, e4]
  simp only [rec5, limbs129, Fin.coe_ofNat_eq_mod, Nat.reduceMod, Fin.val_zero, List.getD_cons_succ,
    List.getD_cons_zero]
  ring

def numC : ElemC := ⟨[0, 0, 0, 0, 0], [2 ^ 32 - 1, 2 ^ 32 - 1, 2 ^ 32 - 1, 2 ^ 32 - 1, 1], 0, 2 ^ 129 - 1⟩

def sdC : ElemC :=
  ⟨[-(2 ^ 32 - 1), -(2 ^ 32 - 1), -(2 ^ 32 - 1), -(2 ^ 32 - 1), -1], [2 ^ 32 - 1, 2 ^ 32 - 1, 2 ^ 32 - 1, 2 ^ 32 - 1, 1],
    -(2 ^ 129 - 1), 2 ^ 129 - 1⟩

theorem limbs129_fits {n : ℕ} {g : List.Vector F n} (hb : AllBits g) {a : ℕ} (ha : a + 129 ≤ n) :
    Fits5 (limbs129 g a) numC := by
  have c0 := chunk_bounds hb (a := a) (w := 32) (by omega)
  have c1 := chunk_bounds hb (a := a + 32) (w := 32) (by omega)
  have c2 := chunk_bounds hb (a := a + 64) (w := 32) (by omega)
  have c3 := chunk_bounds hb (a := a + 96) (w := 32) (by omega)
  have c4 := chunk_bounds hb (a := a + 128) (w := 1) (by omega)
  have cv := chunk_bounds hb (a := a) (w := 129) (by omega)
  refine ⟨rfl, rfl, fun k => ?_, ?_, ?_⟩
  · fin_cases k <;> simp [numC, limbs129] <;> omega
  · rw [rec5_limbs129]; simp [numC]; omega
  · rw [rec5_limbs129]; simp [numC]; omega

theorem signed_fits {n : ℕ} {g : List.Vector F n} (hb : AllBits g) {a : ℕ} (ha : a + 129 ≤ n) {s : ℤ}
    (hs : s = 1 ∨ s = -1) : Fits5 (fun k => s * limbs129 g a k) sdC := by
  have c0 := chunk_bounds hb (a := a) (w := 32) (by omega)
  have c1 := chunk_bounds hb (a := a + 32) (w := 32) (by omega)
  have c2 := chunk_bounds hb (a := a + 64) (w := 32) (by omega)
  have c3 := chunk_bounds hb (a := a + 96) (w := 32) (by omega)
  have c4 := chunk_bounds hb (a := a + 128) (w := 1) (by omega)
  have cv := chunk_bounds hb (a := a) (w := 129) (by omega)
  have hr : rec5 (fun k => s * limbs129 g a k) = s * chunk g a 129 := by
    rw [← rec5_limbs129]; simp only [rec5]; ring
  refine ⟨rfl, rfl, fun k => ?_, ?_, ?_⟩
  · rcases hs with rfl | rfl <;> fin_cases k <;> simp [sdC, limbs129] <;> omega
  · rw [hr]; rcases hs with rfl | rfl <;> simp [sdC] <;> omega
  · rw [hr]; rcases hs with rfl | rfl <;> simp [sdC] <;> omega

theorem den_pos {n : ℕ} {g : List.Vector F n} (hb : AllBits g) {a w : ℕ} (ha : a + w ≤ n)
    (hne : ∑ j ∈ Finset.range w, g.toList.getD (a + j) 0 ≠ 0) : 1 ≤ chunk g a w := by
  have hcast : ∑ j ∈ Finset.range w, g.toList.getD (a + j) 0 =
      ((∑ j ∈ Finset.range w, bitI g (a + j) : ℤ) : F) := by
    push_cast
    apply Finset.sum_congr rfl
    intro j hj
    rw [(bitI_of_bool (hb (a + j) (by simp at hj; omega))).2]
  rw [hcast] at hne
  have hnn : ∀ j ∈ Finset.range w, 0 ≤ bitI g (a + j) := fun j _ => by unfold bitI; positivity
  have hle : ∀ j ∈ Finset.range w, bitI g (a + j) ≤ 1 := by
    intro j hj
    rcases (bitI_of_bool (hb (a + j) (by simp at hj; omega))).1 with h | h <;> simp [h]
  have hsum0 : 0 ≤ ∑ j ∈ Finset.range w, bitI g (a + j) := Finset.sum_nonneg hnn
  have hsumw : ∑ j ∈ Finset.range w, bitI g (a + j) ≤ w := by
    calc ∑ j ∈ Finset.range w, bitI g (a + j) ≤ ∑ j ∈ Finset.range w, (1 : ℤ) := Finset.sum_le_sum hle
      _ = w := by simp
  have hne' : ∑ j ∈ Finset.range w, bitI g (a + j) ≠ 0 := by
    intro h0; apply hne; rw [h0]; simp
  have hge : 1 ≤ ∑ j ∈ Finset.range w, bitI g (a + j) := by omega
  calc (1 : ℤ) ≤ ∑ j ∈ Finset.range w, bitI g (a + j) := hge
    _ ≤ chunk g a w := by
      unfold chunk
      apply Finset.sum_le_sum
      intro j hj
      have h0 := hnn j hj
      have hp : (1 : ℤ) ≤ 2 ^ j := one_le_pow₀ (by norm_num)
      nlinarith

theorem signed_limb {σ : ℤ} {c q s : F} (hσ : ((σ : ℤ) : F) = s) (h : q = c - s * (c - (0 + c * -1))) :
    q = ((1 - 2 * σ : ℤ) : F) * c := by
  rw [h, ← hσ]; push_cast; ring

end ZolanaVE.P256
