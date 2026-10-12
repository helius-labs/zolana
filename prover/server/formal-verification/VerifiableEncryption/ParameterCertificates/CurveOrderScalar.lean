import VerifiableEncryption.ParameterCertificates.CurveOrderArithmetic

/-!
An ordinary mathematical affine-coordinate checker for a P-256 torsion point.
The checker uses binary scalar multiplication, not the circuit ladder or an
assumed group order. Every coordinate addition is related to Mathlib's point
addition before the closed kernel-check obligation is used.

This development has passed Lean kernel checking. Its parameter import
contains no curve-order assumption.
-/

namespace ZolanaVE.ParameterCertificates.CurveOrderScalar

open ZolanaVE.P256
open WeierstrassCurve.Affine
open ZolanaVE.ParameterCertificates.CurveOrderArithmetic

abbrev Coordinates := Option (Fp × Fp)

def rawSlope (x₁ x₂ y₁ y₂ : Fp) : Fp :=
  if x₁ = x₂ then
    if y₁ = W.toAffine.negY x₂ y₂ then 0
    else (3 * x₁ ^ 2 + 2 * W.a₂ * x₁ + W.a₄ - W.a₁ * y₁) *
      fpInverse (y₁ - W.toAffine.negY x₁ y₁)
  else (y₁ - y₂) * fpInverse (x₁ - x₂)

theorem rawSlope_eq (x₁ x₂ y₁ y₂ : Fp) :
    rawSlope x₁ x₂ y₁ y₂ = W.toAffine.slope x₁ x₂ y₁ y₂ := by
  by_cases hx : x₁ = x₂ <;>
    by_cases hy : y₁ = W.toAffine.negY x₂ y₂ <;>
    simp [rawSlope, fpInverse_eq, div_eq_mul_inv, WeierstrassCurve.Affine.slope, hx, hy]

def rawAdd : Coordinates → Coordinates → Coordinates
  | none, right => right
  | left, none => left
  | some (x₁, y₁), some (x₂, y₂) =>
    if x₁ = x₂ ∧ y₁ = W.toAffine.negY x₂ y₂ then none
    else
      let slope := rawSlope x₁ x₂ y₁ y₂
      some (W.toAffine.addX x₁ x₂ slope, W.toAffine.addY x₁ x₂ y₁ slope)

def Represents : Coordinates → P → Prop
  | none, point => point = 0
  | some (x, y), point => ∃ h : W.toAffine.Nonsingular x y, point = Point.some h

theorem rawAdd_sound {left right : Coordinates} {L R : P}
    (hl : Represents left L) (hr : Represents right R) :
    Represents (rawAdd left right) (L + R) := by
  cases left with
  | none =>
    change L = 0 at hl
    subst L
    simpa [rawAdd] using hr
  | some left =>
    cases right with
    | none =>
      change R = 0 at hr
      subst R
      simpa [rawAdd] using hl
    | some right =>
      rcases left with ⟨x₁, y₁⟩
      rcases right with ⟨x₂, y₂⟩
      rcases hl with ⟨h₁, rfl⟩
      rcases hr with ⟨h₂, rfl⟩
      by_cases hxy : x₁ = x₂ ∧ y₁ = W.toAffine.negY x₂ y₂
      · simp only [rawAdd, if_pos hxy, Represents]
        exact Point.add_of_Y_eq hxy.1 hxy.2
      · have safe : x₁ = x₂ → y₁ ≠ W.toAffine.negY x₂ y₂ :=
          fun hx hy => hxy ⟨hx, hy⟩
        simp only [rawAdd, if_neg hxy, rawSlope_eq, Represents]
        exact ⟨W.toAffine.nonsingular_add h₁ h₂ safe, Point.add_of_imp safe⟩

/-- One recursive call per scalar bit; the fuel bounds the scalar bit length. -/
def rawMul : ℕ → ℕ → Coordinates → Coordinates
  | 0, _, _ => none
  | fuel + 1, scalar, base =>
    let half := rawMul fuel (scalar / 2) base
    let twice := rawAdd half half
    if scalar % 2 = 0 then twice else rawAdd twice base

theorem rawMul_sound (fuel : ℕ) (scalar : ℕ) (base : Coordinates) (point : P)
    (hbase : Represents base point) (hbound : scalar < 2 ^ fuel) :
    Represents (rawMul fuel scalar base) (scalar • point) := by
  induction fuel generalizing scalar with
  | zero =>
    have hs : scalar = 0 := by simpa using hbound
    subst scalar
    simpa only [rawMul, Represents] using (zero_nsmul point)
  | succ fuel ih =>
    have halfBound : scalar / 2 < 2 ^ fuel := by
      rw [pow_succ] at hbound
      omega
    have half := ih (scalar / 2) halfBound
    have twice := rawAdd_sound half half
    rcases Nat.mod_two_eq_zero_or_one scalar with heven | hodd
    · have hsum : scalar / 2 + scalar / 2 = scalar := by
        have h := Nat.mod_add_div scalar 2
        omega
      rw [← add_nsmul, hsum] at twice
      simpa only [rawMul, if_pos heven] using twice
    · have hsum : scalar / 2 + scalar / 2 + 1 = scalar := by
        have h := Nat.mod_add_div scalar 2
        omega
      have result := rawAdd_sound twice hbase
      rw [← add_nsmul, ← succ_nsmul, hsum] at result
      have hne : scalar % 2 ≠ 0 := by omega
      simpa only [rawMul, if_neg hne] using result

def generatorX : ℕ := 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
def generatorY : ℕ := 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

theorem generator_nonsingular :
    W.toAffine.Nonsingular (generatorX : Fp) (generatorY : Fp) := by
  rw [WeierstrassCurve.Affine.nonsingular_iff]
  constructor
  · rw [WeierstrassCurve.Affine.equation_iff]
    change (generatorY : Fp) ^ 2 + 0 * (generatorX : Fp) * (generatorY : Fp) +
      0 * (generatorY : Fp) = (generatorX : Fp) ^ 3 + 0 * (generatorX : Fp) ^ 2 +
      (-3) * (generatorX : Fp) + (b : Fp)
    decide +kernel
  · right
    change (generatorY : Fp) ≠ -(generatorY : Fp) - 0 * (generatorX : Fp) - 0
    decide +kernel

def generator : P := Point.some generator_nonsingular
def rawGenerator : Coordinates := some ((generatorX : Fp), (generatorY : Fp))

theorem generator_nonzero : generator ≠ 0 := Point.some_ne_zero generator_nonsingular

/-- Closed arithmetic check, to be evaluated only when Lean validation is authorized. -/
theorem scalar_check : rawMul 256 n rawGenerator = none := by
  set_option maxRecDepth 100000 in
    decide +kernel

theorem nsmul_generator : n • generator = 0 := by
  have representation : Represents rawGenerator generator := ⟨generator_nonsingular, rfl⟩
  have bound : n < 2 ^ 256 := by decide +kernel
  exact (congrArg (fun coordinates : Coordinates => Represents coordinates (n • generator))
    scalar_check).mp (rawMul_sound 256 n rawGenerator generator representation bound)

end ZolanaVE.ParameterCertificates.CurveOrderScalar
