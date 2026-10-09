import VerifiableEncryption.Curve.GroupLaw

/-!
Exceptional-point guards of the emulated ladder and comb.

The native field is a parameter `ZMod q`: none of the guards needs `q`
prime or large, because each one only uses the direction "integer collision
implies native zero".
-/

namespace ZolanaVE.P256

open WeierstrassCurve.Affine

/-- Value of eight little-endian 32-bit limbs. -/
def limbValue {q : ℕ} (a : Fin 8 → ZMod q) : ℕ := ∑ i : Fin 8, (a i).val * 2 ^ (32 * i.val)

theorem limbs_eq_of_value_eq {q : ℕ} [NeZero q] {a c : Fin 8 → ZMod q}
    (ha : ∀ i, (a i).val < 2 ^ 32) (hc : ∀ i, (c i).val < 2 ^ 32)
    (h : limbValue a = limbValue c) : ∀ i, a i = c i := by
  unfold limbValue at h
  rw [Fin.sum_univ_eight, Fin.sum_univ_eight] at h
  simp only [show ((0 : Fin 8) : ℕ) = 0 from rfl, show ((1 : Fin 8) : ℕ) = 1 from rfl,
    show ((2 : Fin 8) : ℕ) = 2 from rfl, show ((3 : Fin 8) : ℕ) = 3 from rfl,
    show ((4 : Fin 8) : ℕ) = 4 from rfl, show ((5 : Fin 8) : ℕ) = 5 from rfl,
    show ((6 : Fin 8) : ℕ) = 6 from rfl, show ((7 : Fin 8) : ℕ) = 7 from rfl] at h
  have h0 := ha 0; have h1 := ha 1; have h2 := ha 2; have h3 := ha 3
  have h4 := ha 4; have h5 := ha 5; have h6 := ha 6; have h7 := ha 7
  have k0 := hc 0; have k1 := hc 1; have k2 := hc 2; have k3 := hc 3
  have k4 := hc 4; have k5 := hc 5; have k6 := hc 6; have k7 := hc 7
  norm_num at h h0 h1 h2 h3 h4 h5 h6 h7 k0 k1 k2 k3 k4 k5 k6 k7
  intro i
  apply ZMod.val_injective
  fin_cases i <;> simp <;> omega

/-- `curve.xDifferenceSquares` guard: both coordinates are canonical
(`AssertCanonical`), and the native sum of squared limb differences is
nonzero, so the P-256 coordinates differ. -/
theorem distinctX_guard {q : ℕ} [NeZero q] {a c : Fin 8 → ZMod q}
    (ha : ∀ i, (a i).val < 2 ^ 32) (hc : ∀ i, (c i).val < 2 ^ 32)
    (hva : limbValue a < p) (hvc : limbValue c < p)
    (h : ∑ i : Fin 8, (a i - c i) ^ 2 ≠ 0) :
    ((limbValue a : ℕ) : Fp) ≠ ((limbValue c : ℕ) : Fp) := by
  intro he
  apply h
  rw [ZMod.natCast_eq_natCast_iff', Nat.mod_eq_of_lt hva, Nat.mod_eq_of_lt hvc] at he
  have hl := limbs_eq_of_value_eq ha hc he
  simp [hl]

/-- `completeAdd`'s same-x flag: a boolean `s` with
`squares · inv = 1 - s`. A zero flag forces the squared-difference sum to
be nonzero. -/
theorem sameX_flag {q : ℕ} {s squares inv : ZMod q} (hinv : squares * inv = 1 - s)
    (h0 : s = 0) (hq : (1 : ZMod q) ≠ 0) : squares ≠ 0 := by
  intro hz
  rw [hz, zero_mul, h0, sub_zero] at hinv
  exact hq hinv.symm

/-- The distinct-slope factor `d·(d² - p²)` of `curve.assertDistinctSlope`. -/
def slopeFactor {R : Type*} [CommRing R] (d : R) : R := d * (d * d - (p : R) ^ 2)

theorem slopeFactor_cast {q : ℕ} (d : ℤ) : ((slopeFactor d : ℤ) : ZMod q) = slopeFactor (d : ZMod q) := by
  unfold slopeFactor
  push_cast
  ring

theorem slopeFactor_eq_zero_of_modEq {d : ℤ} (hd : |d| < 2 * p) (h : d ≡ 0 [ZMOD p]) :
    slopeFactor d = 0 := by
  obtain ⟨k, hk⟩ := Int.ModEq.dvd h.symm
  simp only [sub_zero] at hk
  have hp : (p : ℤ) = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff := rfl
  rw [hp] at hk hd
  rw [abs_lt] at hd
  have hk1 : -1 ≤ k ∧ k ≤ 1 := by constructor <;> omega
  unfold slopeFactor
  rw [hp, hk]
  rcases hk1 with ⟨hk1, hk2⟩
  interval_cases k <;> ring

/-- `curve.assertDistinctSlope`: with both integer values below `2^255` in
magnitude, a nonzero native product rules out `v ≡ ±h (mod p)`. -/
theorem distinctSlope_guard {q : ℕ} {v h : ℤ} (hv : |v| < 2 ^ 255) (hh : |h| < 2 ^ 255)
    (hne : slopeFactor ((v : ZMod q) - (h : ZMod q)) * slopeFactor ((v : ZMod q) + (h : ZMod q)) ≠ 0) :
    (v : Fp) ≠ (h : Fp) ∧ (v : Fp) ≠ -(h : Fp) := by
  have hp : (p : ℤ) = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff := rfl
  have hsub : |v - h| < 2 * p := by
    rw [hp]; rw [abs_lt] at hv hh ⊢; constructor <;> omega
  have hadd : |v + h| < 2 * p := by
    rw [hp]; rw [abs_lt] at hv hh ⊢; constructor <;> omega
  constructor
  · intro he
    apply hne
    have hm : v - h ≡ 0 [ZMOD p] := by
      have := (ZMod.intCast_eq_intCast_iff v h p).mp he
      exact Int.ModEq.sub_right h this |>.trans (by simp [Int.ModEq])
    have hz := slopeFactor_eq_zero_of_modEq hsub hm
    have hc := slopeFactor_cast (q := q) (v - h)
    rw [hz] at hc
    push_cast at hc
    rw [← hc, zero_mul]
  · intro he
    apply hne
    have hm : v + h ≡ 0 [ZMOD p] := by
      have he' : ((v + h : ℤ) : Fp) = ((0 : ℤ) : Fp) := by push_cast; rw [he]; ring
      exact (ZMod.intCast_eq_intCast_iff _ _ p).mp he'
    have hz := slopeFactor_eq_zero_of_modEq hadd hm
    have hc := slopeFactor_cast (q := q) (v + h)
    rw [hz] at hc
    push_cast at hc
    rw [← hc, mul_zero]

/-- The quartic of `curve.halfTangentSlope`, with `a = -3`. -/
def halfQuartic (X Y l : Fp) : Fp := l ^ 4 - 6 * X * l ^ 2 - 8 * Y * l - 3 * X ^ 2 + 12

theorem four_ne_zero_Fp : (4 : Fp) ≠ 0 := by
  have : (4 : Fp) = 2 * 2 := by norm_num
  rw [this]
  exact mul_ne_zero two_ne_zero_Fp two_ne_zero_Fp

/-- A root `l` of the halving quartic at `T` is the tangent slope at a
point `H` with `2H = T`. -/
theorem half_of_quartic {X Y l : Fp} (hT : OnCurve X Y) (hq : halfQuartic X Y l = 0) :
    ∃ (xH yH : Fp) (hH : OnCurve xH yH), yH ≠ 0 ∧ 2 * yH * l = 3 * xH ^ 2 - 3 ∧
      2 • mkPoint hH = mkPoint hT := by
  obtain ⟨xH, hX⟩ : ∃ xH, X = l ^ 2 - 2 * xH :=
    ⟨(l ^ 2 - X) / 2, by field_simp [two_ne_zero_Fp]⟩
  obtain ⟨yH, hY⟩ : ∃ yH, Y = l * (xH - X) - yH := ⟨l * (xH - X) - Y, by ring⟩
  subst hY
  subst hX
  unfold halfQuartic at hq
  unfold OnCurve at hT
  have hg4 : 4 * (2 * yH * l - (3 * xH ^ 2 - 3)) = 0 := by linear_combination hq
  have hg : 2 * yH * l = 3 * xH ^ 2 - 3 := by
    rw [← sub_eq_zero]
    exact (mul_eq_zero.mp hg4).resolve_left four_ne_zero_Fp
  have hH : OnCurve xH yH := by
    unfold OnCurve
    linear_combination hT - (l ^ 2 - 3 * xH) * hg
  refine ⟨xH, yH, hH, y_ne_zero_of_onCurve hH, hg, ?_⟩
  obtain ⟨hD, hDeq⟩ := tangent_double (xd := l ^ 2 - 2 * xH)
    (yd := l * (xH - (l ^ 2 - 2 * xH)) - yH) hH (by linear_combination hg) rfl rfl
  exact hDeq

theorem eq_or_eq_neg_of_x_eq {x₁ y₁ x₂ y₂ : Fp} (h₁ : OnCurve x₁ y₁) (h₂ : OnCurve x₂ y₂)
    (hx : x₁ = x₂) : mkPoint h₁ = mkPoint h₂ ∨ mkPoint h₁ = -mkPoint h₂ := by
  subst hx
  have hy : (y₁ - y₂) * (y₁ + y₂) = 0 := by
    unfold OnCurve at h₁ h₂
    linear_combination h₁ - h₂
  rcases mul_eq_zero.mp hy with h | h
  · left
    exact mkPoint_inj.mpr ⟨rfl, by linear_combination h⟩
  · right
    obtain ⟨h', he⟩ := neg_mkPoint h₂
    rw [he]
    exact mkPoint_inj.mpr ⟨rfl, by linear_combination h⟩

/-- The quadruple-and-add step guard: if the accumulator's tangent slope
`lA` differs from `±h`, where `h` is a half slope of the selected point
`T`, then `2·acc` and `T` have distinct x-coordinates. -/
theorem step_guard {xA yA lA xT yT h : Fp} (hA : OnCurve xA yA)
    (hlA : 2 * yA * lA = 3 * xA ^ 2 - 3) (hT : OnCurve xT yT) (hq : halfQuartic xT yT h = 0)
    (hne : lA ≠ h ∧ lA ≠ -h) :
    ∀ {xD yD : Fp} (hD : OnCurve xD yD), 2 • mkPoint hA = mkPoint hD → xD ≠ xT := by
  intro xD yD hD hDeq hx
  obtain ⟨xH, yH, hH, hyH, hlH, hHT⟩ := half_of_quartic hT hq
  have hyA := y_ne_zero_of_onCurve hA
  rcases eq_or_eq_neg_of_x_eq hD hT hx with he | he
  · have h2 : 2 • (mkPoint hA - mkPoint hH) = 0 := by
      rw [nsmul_sub, hDeq, hHT, he, sub_self]
    have hAH := sub_eq_zero.mp (no_two_torsion _ h2)
    obtain ⟨hxe, hye⟩ := mkPoint_inj.mp hAH
    apply hne.1
    have : 2 * yA * (lA - h) = 0 := by
      linear_combination hlA - hlH - 2 * h * hye + 3 * (xA + xH) * hxe
    have := (mul_eq_zero.mp this).resolve_left (mul_ne_zero two_ne_zero_Fp hyA)
    exact sub_eq_zero.mp this
  · have h2 : 2 • (mkPoint hA + mkPoint hH) = 0 := by
      rw [nsmul_add, hDeq, hHT, he, neg_add_cancel]
    have hAH := eq_neg_of_add_eq_zero_left (no_two_torsion _ h2)
    obtain ⟨hHn, hHneq⟩ := neg_mkPoint hH
    rw [hHneq] at hAH
    obtain ⟨hxe, hye⟩ := mkPoint_inj.mp hAH
    apply hne.2
    have : 2 * yA * (lA + h) = 0 := by
      linear_combination hlA - hlH + 2 * h * hye + 3 * (xA + xH) * hxe
    have := (mul_eq_zero.mp this).resolve_left (mul_ne_zero two_ne_zero_Fp hyA)
    exact eq_neg_of_add_eq_zero_left this

end ZolanaVE.P256
