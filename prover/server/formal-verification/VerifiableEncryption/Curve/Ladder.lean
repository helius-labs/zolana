import VerifiableEncryption.Curve.Guards

/-!
Group-level parts of the variable-base ladder (`scalarMulChecked`).

Everything here is independent of the extracted constraint system: the joint
table's slot points, the scalar recoding identity behind the quadruple-and-add
chain, and the final chain `num·Q + den·R = 0 ⇒ R = s·Q`. The per-step
statements against the extracted `RowLookup` and `QuadrupleAndAddLazy` defs
are stated once `Circuit.lean` exists.
-/

namespace ZolanaVE.P256.Ladder

/-! ### Slot table -/

/-- The eight slots of `scalarMulLadder` in table order, with `Q` the ladder
input and `R` the sign-corrected product. -/
noncomputable def slotPoint (s : ℕ) (Q R : P) : P :=
  match s with
  | 0 => 3 • Q + 3 • R
  | 1 => Q - 3 • R
  | 2 => 3 • Q - R
  | 3 => Q + R
  | 4 => Q + 3 • R
  | 5 => 3 • Q - 3 • R
  | 6 => Q - R
  | _ => 3 • Q + R

/-- Row `idx` of the packed lookup table: slot `idx` (mirrored above 8), with
the y-coordinate negated on even rows. -/
noncomputable def rowPoint (idx : ℕ) (Q R : P) : P :=
  let slot := slotPoint (if idx < 8 then idx else 15 - idx) Q R
  if idx % 2 = 0 then -slot else slot

def digQ (idx : ℕ) : ℤ := 2 * (2 * (idx % 2 : ℕ) + (idx / 4 % 2 : ℕ)) - 3
def digR (idx : ℕ) : ℤ := 2 * (2 * (idx / 2 % 2 : ℕ) + (idx / 8 % 2 : ℕ)) - 3

/-- Each table row is `digQ·Q + digR·R` with the selector
`idx = n_i + 2·d_i + 4·n_{i-1} + 8·d_{i-1}`. -/
theorem row_point (Q R : P) : ∀ idx, idx < 16 → rowPoint idx Q R = digQ idx • Q + digR idx • R := by
  intro idx hidx
  interval_cases idx <;>
    simp only [rowPoint, slotPoint, digQ, digR] <;> norm_num <;> abel

theorem three_ne_n : (3 : ℕ) ≠ n := by decide +kernel

theorem three_coprime : Nat.Coprime 3 n :=
  (Nat.coprime_primes (by norm_num) Assumptions.p256_order_prime).mpr three_ne_n

theorem three_smul_eq_zero {X : P} (h : 3 • X = 0) : X = 0 :=
  smul_eq_zero_of_coprime three_coprime h

/-- The exceptional cases the ladder's three distinct-x guards exclude:
`x(R) ≠ x(Q)`, `x(R) ≠ x(3Q)` and `x(3R) ≠ x(Q)` give the six inequalities.
Under them every slot is a finite point, so every table row has affine
coordinates. -/
theorem slots_nonzero {Q R : P} (h1 : R ≠ Q) (h2 : R ≠ -Q) (h3 : R ≠ 3 • Q) (h4 : R ≠ -(3 • Q))
    (h5 : 3 • R ≠ Q) (h6 : 3 • R ≠ -Q) : ∀ s, s < 8 → slotPoint s Q R ≠ 0 := by
  intro s hs
  interval_cases s <;> simp only [slotPoint] <;> intro h
  · rw [← nsmul_add] at h
    exact h2 (eq_neg_of_add_eq_zero_right (three_smul_eq_zero h))
  · exact h5 (sub_eq_zero.mp h).symm
  · exact h3 (sub_eq_zero.mp h).symm
  · exact h2 (eq_neg_of_add_eq_zero_right h)
  · exact h6 (eq_neg_of_add_eq_zero_right h)
  · rw [← nsmul_sub] at h
    exact h1 (sub_eq_zero.mp (three_smul_eq_zero h)).symm
  · exact h1 (sub_eq_zero.mp h).symm
  · exact h4 (eq_neg_of_add_eq_zero_right h)

theorem rows_nonzero {Q R : P} (h1 : R ≠ Q) (h2 : R ≠ -Q) (h3 : R ≠ 3 • Q) (h4 : R ≠ -(3 • Q))
    (h5 : 3 • R ≠ Q) (h6 : 3 • R ≠ -Q) : ∀ idx, idx < 16 → rowPoint idx Q R ≠ 0 := by
  intro idx hidx
  have hs := slots_nonzero h1 h2 h3 h4 h5 h6 (if idx < 8 then idx else 15 - idx)
    (by split_ifs <;> omega)
  simp only [rowPoint]
  split_ifs <;> simp_all

/-! ### Quadruple-and-add recoding -/

/-- The accumulator recurrence `acc ← 4·acc + d` over a digit list, most
significant first. -/
def quadFold (a : ℤ) : List ℤ → ℤ
  | [] => a
  | d :: ds => quadFold (4 * a + d) ds

/-- The same recurrence on points. -/
noncomputable def quadFoldP (A : P) : List P → P
  | [] => A
  | T :: Ts => quadFoldP (4 • A + T) Ts

def base4 : List ℤ → ℤ
  | [] => 0
  | d :: ds => d * 4 ^ ds.length + base4 ds

theorem quadFold_eq (a : ℤ) (ds : List ℤ) : quadFold a ds = a * 4 ^ ds.length + base4 ds := by
  induction ds generalizing a with
  | nil => simp [quadFold, base4]
  | cons d ds ih =>
    simp only [quadFold, base4, ih, List.length_cons, pow_succ]
    ring

/-- A point accumulator that starts and steps on `span{Q, R}` stays on it,
with the integer recurrence on each coordinate. -/
theorem quadFoldP_lin (Q R : P) (x y : ℤ) (ds es : List ℤ) (hlen : ds.length = es.length) :
    quadFoldP (x • Q + y • R) (List.zipWith (fun d e => d • Q + e • R) ds es) =
      quadFold x ds • Q + quadFold y es • R := by
  induction ds generalizing es x y with
  | nil =>
    cases es with
    | nil => simp [quadFoldP, quadFold]
    | cons _ _ => simp at hlen
  | cons d ds ih =>
    cases es with
    | nil => simp at hlen
    | cons e es =>
      simp only [List.zipWith_cons_cons, quadFoldP, quadFold]
      rw [← ih (4 * x + d) (4 * y + e) es (by simpa using hlen)]
      congr 1
      rw [add_zsmul, add_zsmul, ← smul_smul, ← smul_smul, nsmul_add]
      abel

theorem base4_range (f : ℕ → ℤ) (m : ℕ) :
    base4 ((List.range m).reverse.map f) = ∑ j ∈ Finset.range m, f j * 4 ^ j := by
  induction m with
  | zero => simp [base4]
  | succ m ih =>
    rw [List.range_succ, List.reverse_append, List.reverse_singleton, List.singleton_append,
      List.map_cons, base4, ih, Finset.sum_range_succ, List.length_map, List.length_reverse,
      List.length_range]
    ring

theorem geom_three (m : ℕ) : ∑ j ∈ Finset.range m, (3 : ℤ) * 4 ^ j = 4 ^ m - 1 := by
  induction m with
  | zero => simp
  | succ m ih =>
    rw [Finset.sum_range_succ, ih, pow_succ]
    ring

theorem bits_pairs (b : ℕ → ℤ) (m : ℕ) :
    ∑ k ∈ Finset.range (2 * m + 1), b k * 2 ^ k =
      b 0 + ∑ j ∈ Finset.range m, (2 * b (2 * j + 1) + 4 * b (2 * j + 2)) * 4 ^ j := by
  induction m with
  | zero => simp
  | succ m ih =>
    rw [show 2 * (m + 1) + 1 = 2 * m + 1 + 1 + 1 by ring, Finset.sum_range_succ,
      Finset.sum_range_succ, ih, Finset.sum_range_succ]
    have e1 : (2 : ℤ) ^ (2 * m + 1) = 2 * 4 ^ m := by
      rw [pow_succ, pow_mul]; norm_num; ring
    have e2 : (2 : ℤ) ^ (2 * m + 1 + 1) = 4 * 4 ^ m := by
      rw [pow_succ, e1]; ring
    rw [e1, e2, show 2 * m + 1 + 1 = 2 * m + 2 by ring]
    ring

/-- Ladder digits for one scalar: pair `j` holds bits `2j+2` and `2j+1`, most
significant pair first, as in the loop `i = 128, 126, ..., 2`. -/
def digits (b : ℕ → ℤ) (extra : ℤ) : List ℤ :=
  (List.range 64).reverse.map fun j => 2 * (2 * b (2 * j + 2) + b (2 * j + 1)) - 3 +
    if j = 0 then extra else 0

theorem digits_length (b : ℕ → ℤ) (extra : ℤ) : (digits b extra).length = 64 := by
  simp [digits]

/-- The recoding identity: starting from `acc = Q + R`, the 64
quadruple-and-add steps plus the low-bit corrections `(b₀ - 1)` produce the
129-bit values; the product side carries the `3R` of the last step. -/
theorem ladder_scalar_identity (b : ℕ → ℤ) (extra : ℤ) :
    quadFold 1 (digits b extra) + (b 0 - 1) = ∑ k ∈ Finset.range 129, b k * 2 ^ k + extra := by
  rw [quadFold_eq, digits_length, digits, base4_range, bits_pairs b 64]
  have hsplit : ∀ j ∈ Finset.range 64,
      (2 * (2 * b (2 * j + 2) + b (2 * j + 1)) - 3 + if j = 0 then extra else 0) * (4 : ℤ) ^ j =
        (2 * b (2 * j + 1) + 4 * b (2 * j + 2)) * 4 ^ j - 3 * 4 ^ j +
          (if j = 0 then extra else 0) := by
    intro j _
    split_ifs with h
    · subst h; ring
    · ring
  rw [Finset.sum_congr rfl hsplit, Finset.sum_add_distrib, Finset.sum_sub_distrib, geom_three,
    Finset.sum_ite_eq' (Finset.range 64) 0 (fun _ => extra)]
  simp only [Finset.mem_range, show (0 : ℕ) < 64 by norm_num, if_true]
  ring

/-! ### Closing the ladder -/

/-- The final ladder relation `acc = 3R` with `acc = num·Q + (den + 3)·R`. -/
theorem ladder_final {Q R : P} {num den : ℤ} (h : num • Q + (den + 3) • R = (3 : ℤ) • R) :
    num • Q + den • R = 0 := by
  have h' : (num • Q + den • R) + (3 : ℤ) • R = 0 + (3 : ℤ) • R := by
    rw [zero_add, add_assoc, ← add_zsmul]
    exact h
  exact add_right_cancel h'

theorem coprime_of_pos_lt {d : ℕ} (h0 : 0 < d) (hd : d < n) : Nat.Coprime d n :=
  Nat.Coprime.symm (Nat.coprime_of_lt_prime h0 hd Assumptions.p256_order_prime)

/-- The ladder's binding argument. The hints supply `num, den < 2^129` and a
sign `ε` with `s·(ε·den) + num ≡ 0 (mod n)`, `den ≥ 1`; the chain gives
`num·Q + den·(ε·Prod) = 0`; then `Prod = s·Q`. -/
theorem ladder_chain {Q Prod : P} {s num den ε : ℤ} (hε : ε = 1 ∨ ε = -1)
    (hden : 1 ≤ den ∧ den < n) (hdec : s * (ε * den) + num ≡ 0 [ZMOD n])
    (hrel : num • Q + den • (ε • Prod) = 0) : Prod = s • Q := by
  have hnum : num • Q = (-(s * (ε * den))) • Q := by
    apply zsmul_congr
    have := Int.ModEq.add_left (-(s * (ε * den))) hdec
    simpa using this
  rw [hnum, smul_smul, mul_comm den ε] at hrel
  have hzero : (ε * den) • (Prod - s • Q) = 0 := by
    calc (ε * den) • (Prod - s • Q) = (ε * den) • Prod - (s * (ε * den)) • Q := by
          rw [zsmul_sub, smul_smul, mul_comm (ε * den) s]
      _ = (-(s * (ε * den))) • Q + (ε * den) • Prod := by rw [neg_zsmul]; abel
      _ = 0 := hrel
  have hden' : den • (Prod - s • Q) = 0 := by
    rcases hε with rfl | rfl
    · simpa using hzero
    · rw [neg_one_mul, neg_zsmul, neg_eq_zero] at hzero
      exact hzero
  have hdn : den = (den.toNat : ℤ) := (Int.toNat_of_nonneg (by omega)).symm
  rw [hdn, natCast_zsmul] at hden'
  have hcop := coprime_of_pos_lt (d := den.toNat) (by omega) (by omega)
  exact sub_eq_zero.mp (smul_eq_zero_of_coprime hcop hden')

/-- `scalarMulChecked` on an exceptional residue runs the ladder on `2Q`
with the half scalar `h ≡ s/2`. -/
theorem half_scalar_double {Q : P} {s h : ℤ} (hh : h * 2 ≡ s [ZMOD n]) :
    h • ((2 : ℤ) • Q) = s • Q := by
  rw [smul_smul]
  exact zsmul_congr hh Q

/-- Soundness of the exceptional-residue selection: whichever branch the
selector bit takes, a ladder result `Out = s'·Q'` on the selected input is
`s·Q`. -/
theorem select_sound {Q Out : P} {s h : ℤ} (e : Bool) (hh : h * 2 ≡ s [ZMOD n])
    (hout : Out = (if e then h else s) • (if e then (2 : ℤ) • Q else Q)) : Out = s • Q := by
  cases e
  · simpa using hout
  · simpa [half_scalar_double hh] using hout

end ZolanaVE.P256.Ladder
