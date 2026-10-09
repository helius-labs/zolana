import VerifiableEncryption.Curve.GroupLaw
import VerifiableEncryption.CombTables

/-!
Fixed-base comb tables.

`combCert` checks the generated tables with relations between adjacent
entries only: chord additions and one doubling per window, cross-multiplied
so the kernel evaluates no inverse and no scalar multiplication. All
arithmetic is on `ℕ` residues so `decide +kernel` runs on GMP-backed `Nat`
operations.
-/

namespace ZolanaVE.P256.Comb

open ZolanaVE.CombTables

def onCurveB (e : ℕ × ℕ) : Bool :=
  decide (e.1 < p) && decide (e.2 < p) && e.2 ^ 2 % p == (e.1 ^ 3 + (p - 3) * e.1 + b) % p

/-- `S = P + Q` by the chord constraints of `curve.add`, with `xP ≠ xQ`. -/
def chordRel (P Q S : ℕ × ℕ) : Bool :=
  P.1 != Q.1 &&
  (S.1 + P.1 + Q.1) * (Q.1 + p - P.1) ^ 2 % p == (Q.2 + p - P.2) ^ 2 % p &&
  ((Q.2 + p - P.2) * (S.1 + p - P.1) + (S.2 + P.2) * (Q.1 + p - P.1)) % p == 0 % p

/-- `S = 2P`, with the tangent slope `(3x² - 3)/(2y)` cleared of its
denominator. -/
def doubleRel (P S : ℕ × ℕ) : Bool :=
  let num := 3 * P.1 ^ 2 + (p - 3)
  (S.1 * 4 * P.2 ^ 2 + 8 * P.1 * P.2 ^ 2) % p == num ^ 2 % p &&
  (S.2 + P.2) * 2 * P.2 % p == num * (P.1 + p - S.1) % p

/-- `N = -P` for points with nonzero `y`. -/
def negRel (P N : ℕ × ℕ) : Bool := N.1 == P.1 && N.2 + P.2 == p

def entry (t j : ℕ) : ℕ × ℕ := (windows.getD t []).getD j (0, 0)
def stepAt (t : ℕ) : ℕ × ℕ := steps.getD t (0, 0)
def topAt (j : ℕ) : ℕ × ℕ := topEven.getD j (0, 0)
def negG : ℕ × ℕ := (Gx, p - Gy)

/-- Selector count of window `t`: 5-bit windows, then one 1-bit top window. -/
def width (t : ℕ) : ℕ := if t < 51 then 32 else 2

def cLen : Bool :=
  windows.length == 52 && topEven.length == 2 && steps.length == 51 &&
  (List.range 52).all fun t => (windows.getD t []).length == width t

def cOn : Bool :=
  ((List.range 52).all fun t => (List.range (width t)).all fun j => onCurveB (entry t j)) &&
  ((List.range 51).all fun t => onCurveB (stepAt t)) &&
  ((List.range 2).all fun j => onCurveB (topAt j)) &&
  onCurveB negG

def cBase : Bool := entry 0 16 == (Gx, Gy)

def cDouble : Bool := (List.range 51).all fun t => doubleRel (entry t 16) (stepAt t)

def cOdd : Bool :=
  (List.range 51).all fun t => (List.range 15).all fun m =>
    chordRel (entry t (16 + m)) (stepAt t) (entry t (17 + m))

def cNeg : Bool :=
  (List.range 51).all fun t => (List.range 16).all fun m =>
    negRel (entry t (16 + m)) (entry t (15 - m))

def cNext : Bool :=
  (List.range 51).all fun t =>
    chordRel (entry t 31) (entry t 16) (entry (t + 1) (if t + 1 < 51 then 16 else 1))

def cTop : Bool :=
  negRel (entry 51 1) (entry 51 0) &&
  (List.range 2).all fun j => chordRel (entry 51 j) negG (topAt j)

def combCert : Bool := cLen && cOn && cBase && cDouble && cOdd && cNeg && cNext && cTop

theorem combCert_true : combCert = true := by decide +kernel

/-! ### From residues to points -/

theorem cast_eq_of_mod {A B : ℕ} (h : (A % p == B % p) = true) : (A : Fp) = (B : Fp) :=
  (ZMod.natCast_eq_natCast_iff' A B p).mpr (beq_iff_eq.mp h)

theorem cast_sub {a c : ℕ} (hc : c < p) : ((a + p - c : ℕ) : Fp) = (a : Fp) - (c : Fp) := by
  rw [Nat.cast_sub (by omega), Nat.cast_add, ZMod.natCast_self, add_zero]

theorem onCurveB_lt {e : ℕ × ℕ} (h : onCurveB e = true) : e.1 < p ∧ e.2 < p := by
  simp only [onCurveB, Bool.and_eq_true, decide_eq_true_eq] at h
  exact ⟨h.1.1, h.1.2⟩

theorem onCurveB_sound {e : ℕ × ℕ} (h : onCurveB e = true) : OnCurve (e.1 : Fp) (e.2 : Fp) := by
  simp only [onCurveB, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at h
  exact onCurve_of_nat h.2

def toPt (e : ℕ × ℕ) (h : onCurveB e = true) : P := mkPoint (onCurveB_sound h)

theorem natCast_ne {a c : ℕ} (ha : a < p) (hc : c < p) (h : a ≠ c) : (a : Fp) ≠ (c : Fp) := by
  intro he
  rw [ZMod.natCast_eq_natCast_iff', Nat.mod_eq_of_lt ha, Nat.mod_eq_of_lt hc] at he
  exact h he

theorem chordRel_sound {P Q S : ℕ × ℕ} (hP : onCurveB P = true) (hQ : onCurveB Q = true)
    (hS : onCurveB S = true) (h : chordRel P Q S = true) :
    toPt P hP + toPt Q hQ = toPt S hS := by
  simp only [chordRel, Bool.and_eq_true, bne_iff_ne, ne_eq] at h
  obtain ⟨⟨hx, h1⟩, h2⟩ := h
  have lP := onCurveB_lt hP
  have lQ := onCurveB_lt hQ
  have lS := onCurveB_lt hS
  have h1' := cast_eq_of_mod h1
  have h2' := cast_eq_of_mod h2
  push_cast [cast_sub lP.1, cast_sub lP.2] at h1' h2'
  obtain ⟨hS', he⟩ := chord_add (onCurveB_sound hP) (onCurveB_sound hQ)
    (natCast_ne lP.1 lQ.1 hx) (xs := (S.1 : Fp)) (ys := (S.2 : Fp))
    (by linear_combination h1') (by linear_combination h2')
  exact he

theorem doubleRel_sound {P S : ℕ × ℕ} (hP : onCurveB P = true) (hS : onCurveB S = true)
    (h : doubleRel P S = true) : 2 • toPt P hP = toPt S hS := by
  simp only [doubleRel, Bool.and_eq_true] at h
  obtain ⟨h1, h2⟩ := h
  have lS := onCurveB_lt hS
  have h1' := cast_eq_of_mod h1
  have h2' := cast_eq_of_mod h2
  push_cast [cast_sub lS.1, natCast_p_sub_three] at h1' h2'
  have hon := onCurveB_sound hP
  have hy : (P.2 : Fp) ≠ 0 := y_ne_zero_of_onCurve hon
  have h2y : (2 : Fp) * P.2 ≠ 0 := mul_ne_zero two_ne_zero_Fp hy
  obtain ⟨l, hl⟩ : ∃ l : Fp, l * (2 * P.2) = 3 * (P.1 : Fp) ^ 2 - 3 :=
    ⟨_, div_mul_cancel₀ _ h2y⟩
  have h4 : (4 : Fp) * (P.2 : Fp) ^ 2 ≠ 0 := by
    have : (4 : Fp) * (P.2 : Fp) ^ 2 = (2 * P.2) ^ 2 := by ring
    rw [this]
    exact pow_ne_zero 2 h2y
  obtain ⟨hD, he⟩ := tangent_double hon (l := l) (xd := (S.1 : Fp)) (yd := (S.2 : Fp))
    (by linear_combination hl)
    (by
      rw [← sub_eq_zero]
      apply cancel_of_mul h4
      linear_combination h1' - (3 * (P.1 : Fp) ^ 2 - 3 + l * (2 * P.2)) * hl)
    (by
      rw [← sub_eq_zero]
      apply cancel_of_mul h2y
      linear_combination h2' - ((P.1 : Fp) - S.1) * hl)
  exact he

theorem negRel_sound {P N : ℕ × ℕ} (hP : onCurveB P = true) (hN : onCurveB N = true)
    (h : negRel P N = true) : toPt N hN = -toPt P hP := by
  simp only [negRel, Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨hx, hy⟩ := h
  obtain ⟨hn, hneg⟩ := neg_mkPoint (onCurveB_sound hP)
  unfold toPt
  rw [hneg, mkPoint_inj]
  refine ⟨by rw [hx], ?_⟩
  have : ((N.2 + P.2 : ℕ) : Fp) = (p : Fp) := by rw [hy]
  push_cast [ZMod.natCast_self] at this
  linear_combination this

/-! ### Unpacking the certificate -/

theorem cert_parts : cLen = true ∧ cOn = true ∧ cBase = true ∧ cDouble = true ∧ cOdd = true ∧
    cNeg = true ∧ cNext = true ∧ cTop = true := by
  have h := combCert_true
  simp only [combCert, Bool.and_eq_true] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, h7⟩, h8⟩ := h
  exact ⟨h1, h2, h3, h4, h5, h6, h7, h8⟩

theorem all_range {n : ℕ} {f : ℕ → Bool} (h : (List.range n).all f = true) {i : ℕ}
    (hi : i < n) : f i = true :=
  List.all_eq_true.mp h i (List.mem_range.mpr hi)

theorem entry_on {t j : ℕ} (ht : t < 52) (hj : j < width t) : onCurveB (entry t j) = true := by
  have h := cert_parts.2.1
  simp only [cOn, Bool.and_eq_true] at h
  exact all_range (all_range h.1.1.1 ht) hj

theorem step_on {t : ℕ} (ht : t < 51) : onCurveB (stepAt t) = true := by
  have h := cert_parts.2.1
  simp only [cOn, Bool.and_eq_true] at h
  exact all_range h.1.1.2 ht

theorem top_on {j : ℕ} (hj : j < 2) : onCurveB (topAt j) = true := by
  have h := cert_parts.2.1
  simp only [cOn, Bool.and_eq_true] at h
  exact all_range h.1.2 hj

theorem negG_on : onCurveB negG = true := by
  have h := cert_parts.2.1
  simp only [cOn, Bool.and_eq_true] at h
  exact h.2

theorem width_lt {t : ℕ} (ht : t < 51) : width t = 32 := by simp [width, ht]

theorem width_top : width 51 = 2 := by simp [width]

theorem toPt_congr {e e' : ℕ × ℕ} (h : e = e') (he : onCurveB e = true) (he' : onCurveB e' = true) :
    toPt e he = toPt e' he' := by
  subst h
  rfl

theorem toPt_G (h : onCurveB (Gx, Gy) = true) : toPt (Gx, Gy) h = G := rfl

theorem toPt_negG : toPt negG negG_on = -G := by
  have hG : onCurveB (Gx, Gy) = true := by
    rw [← (beq_iff_eq.mp cert_parts.2.2.1)]
    exact entry_on (by norm_num) (by simp [width])
  apply negRel_sound hG negG_on
  simp only [negRel, negG, Bool.and_eq_true, beq_iff_eq, true_and]
  have := (onCurveB_lt hG).2
  simp only at this
  omega

/-! ### Window points -/

open Classical in
/-- The point a residue pair names, or `0` off the curve; free of proof
arguments so table indices can be rewritten. -/
noncomputable def pt (e : ℕ × ℕ) : P := if h : onCurveB e = true then toPt e h else 0

theorem pt_eq {e : ℕ × ℕ} (h : onCurveB e = true) : pt e = toPt e h := by
  simp [pt, h]

theorem chord_pt {P Q S : ℕ × ℕ} (hP : onCurveB P = true) (hQ : onCurveB Q = true)
    (hS : onCurveB S = true) (h : chordRel P Q S = true) : pt P + pt Q = pt S := by
  rw [pt_eq hP, pt_eq hQ, pt_eq hS]
  exact chordRel_sound hP hQ hS h

theorem double_pt {P S : ℕ × ℕ} (hP : onCurveB P = true) (hS : onCurveB S = true)
    (h : doubleRel P S = true) : 2 • pt P = pt S := by
  rw [pt_eq hP, pt_eq hS]
  exact doubleRel_sound hP hS h

theorem neg_pt {P N : ℕ × ℕ} (hP : onCurveB P = true) (hN : onCurveB N = true)
    (h : negRel P N = true) : pt N = -pt P := by
  rw [pt_eq hP, pt_eq hN]
  exact negRel_sound hP hN h

/-- `2^(5t)·G`, the base of window `t`. -/
noncomputable def base (t : ℕ) : P := ((2 : ℤ) ^ (5 * t)) • G

theorem on_lt {t j : ℕ} (ht : t < 51) (hj : j < 32) : onCurveB (entry t j) = true :=
  entry_on (by omega) (by rw [width_lt ht]; exact hj)

theorem odd_points {t : ℕ} (ht : t < 51) (hb : pt (entry t 16) = base t) :
    ∀ m, m < 16 → pt (entry t (16 + m)) = ((2 * m + 1 : ℤ)) • base t := by
  have hstep : pt (stepAt t) = (2 : ℤ) • base t := by
    have h := all_range (cert_parts.2.2.2.1) ht
    rw [← double_pt (on_lt ht (by norm_num)) (step_on ht) h, hb, two_zsmul, two_nsmul]
  intro m
  induction m with
  | zero => intro _; simpa using hb
  | succ k ih =>
    intro hk
    have h := all_range (all_range cert_parts.2.2.2.2.1 ht) (show k < 15 by omega)
    have hc := chord_pt (on_lt ht (by omega)) (step_on ht) (on_lt ht (by omega)) h
    rw [show 16 + (k + 1) = 17 + k by omega, ← hc, ih (by omega), hstep, ← add_zsmul]
    congr 1

theorem base_points : ∀ t, t < 52 → pt (entry t (if t < 51 then 16 else 1)) = base t := by
  intro t
  induction t with
  | zero =>
    intro _
    have h := beq_iff_eq.mp cert_parts.2.2.1
    have hG : onCurveB (Gx, Gy) = true := by rw [← h]; exact on_lt (by norm_num) (by norm_num)
    simp only [show (0 : ℕ) < 51 by norm_num, if_true]
    rw [h, pt_eq hG, toPt_G]
    simp [base]
  | succ k ih =>
    intro hk
    have hk51 : k < 51 := by omega
    have hb := ih (by omega)
    simp only [hk51, if_true] at hb
    have hodd := odd_points hk51 hb 15 (by norm_num)
    have h := all_range cert_parts.2.2.2.2.2.2.1 hk51
    have hc := chord_pt (on_lt hk51 (by norm_num)) (on_lt hk51 (by norm_num))
      (entry_on hk (by unfold width; split_ifs <;> norm_num)) h
    rw [← hc, hodd, hb, ← add_one_zsmul]
    unfold base
    rw [smul_smul]
    congr 1
    rw [show 5 * (k + 1) = 5 * k + 5 by ring, pow_add]
    norm_num
    ring

/-- Every comb table entry is the signed odd multiple its selector names:
`windows[t][j] = (2j + 1 - 2^w)·2^(5t)·G` with `w = 5` below the top
window and `w = 1` in it. -/
theorem window_pt (t j : ℕ) (ht : t < 52) (hj : j < width t) :
    pt (entry t j) = ((2 * j + 1 - (width t : ℤ)) * 2 ^ (5 * t)) • G := by
  rw [← smul_smul]
  change _ = (2 * (j : ℤ) + 1 - (width t : ℤ)) • base t
  by_cases hlt : t < 51
  · have hb := base_points t ht
    simp only [hlt, if_true] at hb
    rw [width_lt hlt] at hj ⊢
    by_cases hj16 : 16 ≤ j
    · obtain ⟨m, rfl⟩ : ∃ m, j = 16 + m := ⟨j - 16, by omega⟩
      rw [odd_points hlt hb m (by omega)]
      congr 1
      push_cast
      ring
    · have hn := all_range (all_range cert_parts.2.2.2.2.2.1 hlt) (show 15 - j < 16 by omega)
      rw [show 15 - (15 - j) = j by omega] at hn
      rw [neg_pt (on_lt hlt (by omega)) (on_lt hlt hj) hn,
        odd_points hlt hb (15 - j) (by omega), ← neg_zsmul]
      congr 1
      push_cast [Nat.cast_sub (show j ≤ 15 by omega)]
      ring
  · have h51 : t = 51 := by omega
    subst h51
    have hb := base_points 51 ht
    simp only [show ¬ (51 < 51) by norm_num, if_false] at hb
    rw [width_top] at hj ⊢
    interval_cases j
    · have hn := ((Bool.and_eq_true _ _).mp cert_parts.2.2.2.2.2.2.2).1
      rw [neg_pt (entry_on ht (by rw [width_top]; norm_num))
        (entry_on ht (by rw [width_top]; norm_num)) hn, hb]
      simp
    · rw [hb]
      simp

theorem window_point (t j : ℕ) (ht : t < 52) (hj : j < width t) :
    toPt (entry t j) (entry_on ht hj) = ((2 * j + 1 - (width t : ℤ)) * 2 ^ (5 * t)) • G := by
  rw [← pt_eq, window_pt t j ht hj]

/-- The parity-folded top window: `topEven[j] = windows[51][j] - G`. -/
theorem topEven_point (j : ℕ) (hj : j < 2) :
    toPt (topAt j) (top_on hj) = ((2 * j - 1 : ℤ) * 2 ^ 255 - 1) • G := by
  have h := all_range ((Bool.and_eq_true _ _).mp cert_parts.2.2.2.2.2.2.2).2 hj
  have hon := entry_on (t := 51) (j := j) (by norm_num) (by rw [width_top]; exact hj)
  have hc := chord_pt hon negG_on (top_on hj) h
  rw [← pt_eq, ← hc, window_pt 51 j (by norm_num) (by rw [width_top]; exact hj),
    pt_eq negG_on, toPt_negG, width_top]
  rw [sub_zsmul, one_zsmul, sub_eq_add_neg]
  congr 2
  push_cast
  ring

/-! ### Scalar recoding and the addition chain -/

theorem n_pos : (0 : ℤ) < n := by
  have : (0 : ℕ) < n := by decide +kernel
  exact_mod_cast this

theorem two_pow_255_lt_n : (2 : ℤ) ^ 255 < n := by
  have : 2 ^ 255 < n := by decide +kernel
  exact_mod_cast this

/-- `G` has order exactly `n`: equal multiples have congruent scalars. -/
theorem zsmul_G_eq {a c : ℤ} (h : a • G = c • G) : a ≡ c [ZMOD n] := by
  have hk : (a - c) • G = 0 := by simp [sub_zsmul, h]
  by_contra hne
  have hmod : (a - c) % n ≠ 0 := by
    intro h0
    apply hne
    rw [Int.modEq_iff_dvd, ← neg_sub]
    exact dvd_neg.mpr (Int.dvd_of_emod_eq_zero h0)
  have hpos : 0 < (a - c) % n := lt_of_le_of_ne (Int.emod_nonneg _ n_pos.ne') (Ne.symm hmod)
  have hlt : (a - c) % n < n := Int.emod_lt_of_pos _ n_pos
  rw [zsmul_mod] at hk
  have hnat : ((a - c) % n) = (((a - c) % n).toNat : ℤ) := (Int.toNat_of_nonneg hpos.le).symm
  rw [hnat, natCast_zsmul] at hk
  have hcop : Nat.Coprime ((a - c) % n).toNat n := Nat.Coprime.symm
    (Nat.coprime_of_lt_prime (by omega) (by omega) Assumptions.p256_order_prime)
  exact mkPoint_ne_zero G_onCurve (smul_eq_zero_of_coprime hcop hk)

theorem zsmul_G_inj {a c : ℤ} (hlt : |a - c| < n) (h : a • G = c • G) : a = c := by
  have hm := zsmul_G_eq h
  have hd : (n : ℤ) ∣ a - c := (Int.ModEq.dvd hm.symm)
  exact sub_eq_zero.mp (Int.eq_zero_of_abs_lt_dvd hd hlt)

theorem window_sum_bound (dig : ℕ → ℤ) (hd : ∀ u, |dig u| ≤ 31) :
    ∀ t, |∑ u ∈ Finset.range t, dig u * 2 ^ (5 * u)| ≤ 2 ^ (5 * t) - 1 := by
  intro t
  induction t with
  | zero => simp
  | succ t ih =>
    rw [Finset.sum_range_succ]
    have h1 := abs_add (∑ u ∈ Finset.range t, dig u * 2 ^ (5 * u)) (dig t * 2 ^ (5 * t))
    have h2 : |dig t * 2 ^ (5 * t)| ≤ 31 * 2 ^ (5 * t) := by
      rw [abs_mul, abs_of_pos (by positivity : (0 : ℤ) < 2 ^ (5 * t))]
      exact mul_le_mul_of_nonneg_right (hd t) (by positivity)
    have h3 : (2 : ℤ) ^ (5 * (t + 1)) = 32 * 2 ^ (5 * t) := by
      rw [show 5 * (t + 1) = 5 * t + 5 by ring, pow_add]; norm_num; ring
    rw [h3]
    linarith

/-- The comb's chain additions carry no distinct-x guard, so soundness
needs the partial sum of windows `0..t-1` never to share an x-coordinate
with window `t`. It cannot: the scalars differ by less than `n` and are
never equal or opposite. -/
theorem chain_x_distinct (t : ℕ) (ht : t ≤ 50) (dig : ℕ → ℤ) (hd : ∀ u, |dig u| ≤ 31) (d : ℤ)
    (hd1 : 1 ≤ |d|) (hd31 : |d| ≤ 31) :
    (∑ u ∈ Finset.range t, dig u * 2 ^ (5 * u)) • G ≠ (d * 2 ^ (5 * t)) • G ∧
      (∑ u ∈ Finset.range t, dig u * 2 ^ (5 * u)) • G ≠ -((d * 2 ^ (5 * t)) • G) := by
  set a := ∑ u ∈ Finset.range t, dig u * 2 ^ (5 * u)
  have ha := window_sum_bound dig hd t
  have hpow : (0 : ℤ) < 2 ^ (5 * t) := by positivity
  have hc : |d * 2 ^ (5 * t)| = |d| * 2 ^ (5 * t) := by rw [abs_mul, abs_of_pos hpow]
  have hc1 : 2 ^ (5 * t) ≤ |d * 2 ^ (5 * t)| := by rw [hc]; nlinarith
  have hc31 : |d * 2 ^ (5 * t)| ≤ 31 * 2 ^ (5 * t) := by rw [hc]; nlinarith
  have hbig : (2 : ℤ) ^ (5 * t) * 32 ≤ 2 ^ 255 := by
    rw [show (2 : ℤ) ^ (5 * t) * 32 = 2 ^ (5 * t + 5) by rw [pow_add]; norm_num]
    exact pow_le_pow_right₀ (by norm_num) (by omega)
  have hn := two_pow_255_lt_n
  constructor
  · intro h
    have heq := zsmul_G_inj (by
      have := abs_sub a (d * 2 ^ (5 * t))
      linarith) h
    have : |a| = |d * 2 ^ (5 * t)| := by rw [heq]
    linarith
  · intro h
    rw [← neg_zsmul] at h
    have heq := zsmul_G_inj (by
      have := abs_sub a (-(d * 2 ^ (5 * t)))
      rw [abs_neg] at this
      linarith) h
    have : |a| = |d * 2 ^ (5 * t)| := by rw [heq, abs_neg]
    linarith

theorem geom_31 (m : ℕ) : ∑ t ∈ Finset.range m, (31 : ℤ) * 2 ^ (5 * t) = 2 ^ (5 * m) - 1 := by
  induction m with
  | zero => simp
  | succ m ih =>
    rw [Finset.sum_range_succ, ih, show 5 * (m + 1) = 5 * m + 5 by ring, pow_add]
    ring

/-- The signed-window recoding: digits `2r_t - 31` on 51 five-bit windows, a
top digit `2·top - 1` at `2^255`, and the parity fold `-(1 - π)` sum to
`2r + π - 2^256`. -/
theorem recode_identity (rt : ℕ → ℤ) (top π : ℤ) :
    ∑ t ∈ Finset.range 51, (2 * rt t - 31) * 2 ^ (5 * t) + (2 * top - 1) * 2 ^ 255 - (1 - π) =
      2 * (∑ t ∈ Finset.range 51, rt t * 2 ^ (5 * t) + top * 2 ^ 255) + π - 2 ^ 256 := by
  have hsplit : ∑ t ∈ Finset.range 51, (2 * rt t - 31) * (2 : ℤ) ^ (5 * t) =
      2 * ∑ t ∈ Finset.range 51, rt t * 2 ^ (5 * t) - ∑ t ∈ Finset.range 51, (31 : ℤ) * 2 ^ (5 * t) := by
    rw [Finset.mul_sum, ← Finset.sum_sub_distrib]
    exact Finset.sum_congr rfl fun t _ => by ring
  rw [hsplit, geom_31]
  norm_num
  ring

/-- Group-level soundness of `scalarMulBase`: once the selected window points
are the table multiples and the chain sums them, the result is `s·G`
whenever the recoding constraint `2r + π ≡ s + 2^256 (mod n)` holds. -/
theorem comb_result {s top π : ℤ} (rt : ℕ → ℤ)
    (hrec : 2 * (∑ t ∈ Finset.range 51, rt t * 2 ^ (5 * t) + top * 2 ^ 255) + π ≡
      s + 2 ^ 256 [ZMOD n]) {E : P}
    (hE : E = ∑ t ∈ Finset.range 51, ((2 * rt t - 31) * 2 ^ (5 * t)) • G +
      ((2 * top - 1) * 2 ^ 255 - (1 - π)) • G) : E = s • G := by
  rw [hE, ← Finset.sum_smul, ← add_zsmul]
  apply zsmul_congr
  have hid := recode_identity rt top π
  rw [add_sub_assoc] at hid
  rw [hid]
  have := Int.ModEq.sub_right (2 ^ 256) hrec
  simpa using this

end ZolanaVE.P256.Comb
