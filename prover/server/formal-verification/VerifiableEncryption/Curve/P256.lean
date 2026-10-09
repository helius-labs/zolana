import VerifiableEncryption.Assumptions

namespace ZolanaVE.P256

open WeierstrassCurve.Affine

def Gx : ℕ := 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
def Gy : ℕ := 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

/-- The short Weierstrass equation of P-256 over `Fp`. -/
def OnCurve (x y : Fp) : Prop := y ^ 2 = x ^ 3 - 3 * x + (b : Fp)

theorem W_a₁ : W.a₁ = 0 := rfl
theorem W_a₂ : W.a₂ = 0 := rfl
theorem W_a₃ : W.a₃ = 0 := rfl
theorem W_a₄ : W.a₄ = -3 := rfl
theorem W_a₆ : W.a₆ = (b : Fp) := rfl

theorem equation_iff_onCurve (x y : Fp) : W.toAffine.Equation x y ↔ OnCurve x y := by
  rw [WeierstrassCurve.Affine.equation_iff]
  simp only [W_a₁, W_a₂, W_a₃, W_a₄, W_a₆, OnCurve]
  constructor <;> intro h <;> linear_combination h

theorem negY_eq (x y : Fp) : W.toAffine.negY x y = -y := by
  simp only [WeierstrassCurve.Affine.negY, W_a₁, W_a₃]
  ring

theorem p_ge_three : 3 ≤ p := by decide +kernel

theorem natCast_p_sub_three : ((p - 3 : ℕ) : Fp) = -3 := by
  rw [Nat.cast_sub p_ge_three, ZMod.natCast_self]
  simp

theorem Δ_eq : W.Δ = 1728 - 432 * (b : Fp) ^ 2 := by
  simp only [WeierstrassCurve.Δ, WeierstrassCurve.b₂, WeierstrassCurve.b₄, WeierstrassCurve.b₆,
    WeierstrassCurve.b₈, W_a₁, W_a₂, W_a₃, W_a₄, W_a₆]
  ring

theorem disc_mod : (432 * b ^ 2) % p ≠ 1728 % p := by decide +kernel

theorem Δ_ne_zero : W.Δ ≠ 0 := by
  rw [Δ_eq, sub_ne_zero]
  intro h
  apply disc_mod
  have h' : ((432 * b ^ 2 : ℕ) : Fp) = ((1728 : ℕ) : Fp) := by push_cast; exact h.symm
  exact (ZMod.natCast_eq_natCast_iff' _ _ _).mp h'

theorem nonsingular_of_onCurve {x y : Fp} (h : OnCurve x y) : W.toAffine.Nonsingular x y :=
  W.toAffine.nonsingular_of_Δ_ne_zero ((equation_iff_onCurve x y).mpr h) Δ_ne_zero

def mkPoint {x y : Fp} (h : OnCurve x y) : P := .some (nonsingular_of_onCurve h)

theorem onCurve_of_nat {x y : ℕ} (h : y ^ 2 % p = (x ^ 3 + (p - 3) * x + b) % p) :
    OnCurve (x : Fp) (y : Fp) := by
  have h' := (ZMod.natCast_eq_natCast_iff' _ _ _).mpr h
  push_cast [natCast_p_sub_three] at h'
  unfold OnCurve
  linear_combination h'

theorem G_onCurve_nat : Gy ^ 2 % p = (Gx ^ 3 + (p - 3) * Gx + b) % p := by decide +kernel

theorem G_onCurve : OnCurve (Gx : Fp) (Gy : Fp) := onCurve_of_nat G_onCurve_nat

def G : P := mkPoint G_onCurve

theorem some_inj {x₁ y₁ x₂ y₂ : Fp} {h₁ : W.toAffine.Nonsingular x₁ y₁}
    {h₂ : W.toAffine.Nonsingular x₂ y₂} :
    (Point.some h₁ : P) = Point.some h₂ ↔ x₁ = x₂ ∧ y₁ = y₂ := by
  constructor
  · intro h
    injection h with hx hy
    exact ⟨hx, hy⟩
  · rintro ⟨rfl, rfl⟩
    rfl

theorem mkPoint_inj {x₁ y₁ x₂ y₂ : Fp} {h₁ : OnCurve x₁ y₁} {h₂ : OnCurve x₂ y₂} :
    mkPoint h₁ = mkPoint h₂ ↔ x₁ = x₂ ∧ y₁ = y₂ := some_inj

theorem mkPoint_ne_zero {x y : Fp} (h : OnCurve x y) : mkPoint h ≠ 0 :=
  Point.some_ne_zero _

theorem neg_mkPoint {x y : Fp} (h : OnCurve x y) :
    ∃ h' : OnCurve x (-y), -mkPoint h = mkPoint h' := by
  refine ⟨by unfold OnCurve at h ⊢; linear_combination h, ?_⟩
  simp only [mkPoint, Point.neg_some]
  rw [some_inj]
  exact ⟨rfl, negY_eq x y⟩

theorem addOrderOf_dvd_n (Q : P) : addOrderOf Q ∣ n :=
  addOrderOf_dvd_of_nsmul_eq_zero (Assumptions.p256_point_order Q)

theorem smul_eq_zero_of_coprime {k : ℕ} {Q : P} (hk : Nat.Coprime k n) (h : k • Q = 0) :
    Q = 0 := by
  have h1 : addOrderOf Q ∣ k := addOrderOf_dvd_of_nsmul_eq_zero h
  have h2 : addOrderOf Q = 1 := by
    have h3 := Nat.dvd_gcd h1 (addOrderOf_dvd_n Q)
    rw [Nat.Coprime.gcd_eq_one hk] at h3
    exact Nat.dvd_one.mp h3
  exact AddMonoid.addOrderOf_eq_one_iff.mp h2

theorem n_odd : n % 2 = 1 := by decide +kernel

theorem no_two_torsion (Q : P) (h : 2 • Q = 0) : Q = 0 := by
  refine smul_eq_zero_of_coprime ?_ h
  rw [Nat.coprime_two_left]
  exact Nat.odd_iff.mpr n_odd

theorem y_ne_zero_of_nonsingular {x y : Fp} (h : W.toAffine.Nonsingular x y) : y ≠ 0 := by
  intro hy
  have h2 : (Point.some h : P) + Point.some h = 0 :=
    Point.add_self_of_Y_eq (by rw [negY_eq, hy, neg_zero])
  have := no_two_torsion (Point.some h : P) (by rw [two_nsmul]; exact h2)
  exact Point.some_ne_zero h this

theorem y_ne_zero_of_onCurve {x y : Fp} (h : OnCurve x y) : y ≠ 0 :=
  y_ne_zero_of_nonsingular (nonsingular_of_onCurve h)

theorem natCast_n_smul (Q : P) : (n : ℤ) • Q = 0 := by
  rw [natCast_zsmul]
  exact Assumptions.p256_point_order Q

theorem zsmul_mod (a : ℤ) (Q : P) : a • Q = (a % n) • Q := by
  conv_lhs => rw [← Int.emod_add_ediv a n]
  rw [add_zsmul, mul_comm, mul_zsmul, natCast_n_smul, zsmul_zero, add_zero]

theorem zsmul_congr {a c : ℤ} (h : a ≡ c [ZMOD n]) (Q : P) : a • Q = c • Q := by
  rw [zsmul_mod a, zsmul_mod c, h]

theorem nsmul_mod (k : ℕ) (Q : P) : k • Q = (k % n) • Q := by
  have := zsmul_mod (k : ℤ) Q
  rw [natCast_zsmul] at this
  rw [this, ← Int.natCast_mod, natCast_zsmul]

end ZolanaVE.P256
