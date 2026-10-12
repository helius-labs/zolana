import VerifiableEncryption.Curve.CompletenessAffine

/-!
Every finite P-256 table point has the half-tangent root used by production.
Its half is constructed from the independently proved odd group order. The
quartic follows directly from the tangent equation and doubling coordinates;
no successful hint or half-tangent polynomial witness is assumed.
-/

namespace ZolanaVE.P256.Completeness

def halfCoefficient : ℕ := (n + 1) / 2

theorem halfCoefficient_double : 2 * halfCoefficient = n + 1 := by decide +kernel

theorem point_half_double (T : P) : 2 • (halfCoefficient • T) = T := by
  rw [smul_smul, halfCoefficient_double, add_nsmul,
    Assumptions.p256_point_order, zero_add, one_nsmul]

/-- The actual quartic checked by `halfTangentSlopeConstrained`, where a=-3. -/
theorem half_tangent_exists {tx ty : Fp} (ht : OnCurve tx ty) :
    ∃ l : Fp, l ^ 4 - 6 * l ^ 2 * tx - 8 * l * ty - 3 * tx ^ 2 + 12 = 0 := by
  let U := halfCoefficient • mkPoint ht
  have hd : 2 • U = mkPoint ht := point_half_double (mkPoint ht)
  have hu : U ≠ 0 := by
    intro hz
    rw [hz, nsmul_zero] at hd
    exact mkPoint_ne_zero ht hd.symm
  obtain ⟨ux, uy, hon, he⟩ := affine_of_nonzero U hu
  let l : Fp := (3 * ux ^ 2 - 3) / (2 * uy)
  have hden : 2 * uy ≠ 0 := mul_ne_zero two_ne_zero_Fp (y_ne_zero_of_onCurve hon)
  have hl : 2 * l * uy = 3 * ux ^ 2 - 3 := by
    calc
      _ = l * (2 * uy) := by ring
      _ = _ := div_mul_cancel₀ _ hden
  obtain ⟨hdon, hdeq⟩ := tangent_double hon hl rfl rfl
  have hpoint : mkPoint hdon = mkPoint ht := by
    rw [← hdeq, he]
    exact hd
  have coordinates := mkPoint_inj.mp hpoint
  refine ⟨l, ?_⟩
  rw [← coordinates.1, ← coordinates.2]
  linear_combination 4 * hl

/-- Every quartic root reconstructs a rational half point. P-256 has no
nonidentity two-torsion, so both the half point and its tangent are unique. -/
theorem halfQuartic_root_unique {tx ty l₁ l₂ : Fp} (ht : OnCurve tx ty)
    (h₁ : halfQuartic tx ty l₁ = 0) (h₂ : halfQuartic tx ty l₂ = 0) : l₁ = l₂ := by
  obtain ⟨x₁, y₁, hp₁, hy₁, hl₁, hd₁⟩ := half_of_quartic ht h₁
  obtain ⟨x₂, y₂, hp₂, hy₂, hl₂, hd₂⟩ := half_of_quartic ht h₂
  have hz : 2 • (mkPoint hp₁ - mkPoint hp₂) = 0 := by
    rw [nsmul_sub, hd₁, hd₂, sub_self]
  have he := sub_eq_zero.mp (no_two_torsion _ hz)
  obtain ⟨rfl, rfl⟩ := mkPoint_inj.mp he
  have hm : (2 * y₁) * (l₁ - l₂) = 0 := by linear_combination hl₁ - hl₂
  exact sub_eq_zero.mp ((mul_eq_zero.mp hm).resolve_left (mul_ne_zero two_ne_zero_Fp hy₁))

end ZolanaVE.P256.Completeness
