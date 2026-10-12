import VerifiableEncryption.ParameterCertificates.CurveOrderArithmetic

/-!
An independent no-root certificate for x^3 - 3x + b over the P-256 base field.
Binary powering takes place in the explicit three-coefficient representation
of Fp[X]/(X^3 - 3X + b). A small Euclidean step then rules out common roots of
the cubic and the reduced X^p-X. Checker soundness is ordinary field algebra;
the concrete checker result is an unexecuted kernel-decide proof obligation.

No existing two-torsion or point-order theorem is used. The parameter import
contains no curve-order assumption.

The independent elementary group-order strategy is also used in the primary
HOL Light source EC/nistp256.ml (NO_ROOTS_P256 and SIZE_P256_GROUP), inspected
at file SHA 2a7354e844611e4bde0c4585ad8efcd167e21396:
https://github.com/jrh13/hol-light/blob/master/EC/nistp256.ml.
Its theorems are not assumptions of this development; the checker below and
its algebraic correctness proof are written directly in Lean.
-/

namespace ZolanaVE.ParameterCertificates.CurveOrderCubic

open ZolanaVE.P256
open ZolanaVE.ParameterCertificates.CurveOrderArithmetic

structure Triple where
  c₀ : Fp
  c₁ : Fp
  c₂ : Fp
  deriving DecidableEq

def one : Triple := ⟨1, 0, 0⟩
def indeterminate : Triple := ⟨0, 1, 0⟩

def eval (a : Triple) (x : Fp) : Fp := a.c₀ + a.c₁ * x + a.c₂ * x ^ 2

/-- Reduce products using X^3 = 3X-b and X^4 = 3X^2-bX. -/
def mul (a d : Triple) : Triple :=
  ⟨a.c₀ * d.c₀ - (b : Fp) * (a.c₁ * d.c₂ + a.c₂ * d.c₁),
   a.c₀ * d.c₁ + a.c₁ * d.c₀ + 3 * (a.c₁ * d.c₂ + a.c₂ * d.c₁) -
     (b : Fp) * a.c₂ * d.c₂,
   a.c₀ * d.c₂ + a.c₁ * d.c₁ + a.c₂ * d.c₀ + 3 * a.c₂ * d.c₂⟩

theorem mul_eval {x : Fp} (root : x ^ 3 - 3 * x + (b : Fp) = 0)
    (a d : Triple) : eval (mul a d) x = eval a x * eval d x := by
  unfold mul eval
  linear_combination -(a.c₁ * d.c₂ + a.c₂ * d.c₁ + a.c₂ * d.c₂ * x) * root

def powMod : ℕ → ℕ → Triple → Triple
  | 0, _, _ => one
  | fuel + 1, exponent, base =>
    let half := powMod fuel (exponent / 2) base
    let square := mul half half
    if exponent % 2 = 0 then square else mul square base

theorem powMod_eval (fuel exponent : ℕ) (base : Triple) {x : Fp}
    (root : x ^ 3 - 3 * x + (b : Fp) = 0) (bound : exponent < 2 ^ fuel) :
    eval (powMod fuel exponent base) x = eval base x ^ exponent := by
  induction fuel generalizing exponent with
  | zero =>
    have he : exponent = 0 := by simpa using bound
    subst exponent
    simp [powMod, one, eval]
  | succ fuel ih =>
    have halfBound : exponent / 2 < 2 ^ fuel := by
      rw [pow_succ] at bound
      omega
    have half := ih (exponent / 2) halfBound
    rcases Nat.mod_two_eq_zero_or_one exponent with heven | hodd
    · have hsum : exponent / 2 + exponent / 2 = exponent := by
        have h := Nat.mod_add_div exponent 2
        omega
      simp only [powMod, if_pos heven, mul_eval root, half]
      rw [← pow_add, hsum]
    · have hsum : exponent / 2 + exponent / 2 + 1 = exponent := by
        have h := Nat.mod_add_div exponent 2
        omega
      have hne : exponent % 2 ≠ 0 := by omega
      simp only [powMod, if_neg hne, mul_eval root, half]
      rw [← pow_add, ← pow_succ, hsum]

def frobeniusRemainder : Triple :=
  let result := powMod 256 p indeterminate
  ⟨result.c₀, result.c₁ - 1, result.c₂⟩

theorem frobeniusRemainder_eval {x : Fp}
    (root : x ^ 3 - 3 * x + (b : Fp) = 0) : eval frobeniusRemainder x = 0 := by
  have bound : p < 2 ^ 256 := by decide +kernel
  have hp := powMod_eval 256 p indeterminate root bound
  have fermat : x ^ p = x := by
    simpa only [ZMod.card] using FiniteField.pow_card x
  have heval : eval indeterminate x = x := by simp [indeterminate, eval]
  rw [heval, fermat] at hp
  unfold frobeniusRemainder eval
  change (powMod 256 p indeterminate).c₀ +
    ((powMod 256 p indeterminate).c₁ - 1) * x +
    (powMod 256 p indeterminate).c₂ * x ^ 2 = 0
  unfold eval at hp
  linear_combination hp

def normalizedU (r : Triple) : Fp := r.c₁ * fpInverse r.c₂
def normalizedV (r : Triple) : Fp := r.c₀ * fpInverse r.c₂
def linearCoefficient (r : Triple) : Fp := normalizedU r ^ 2 - normalizedV r - 3
def linearConstant (r : Triple) : Fp := normalizedU r * normalizedV r + (b : Fp)
def candidate (r : Triple) : Fp := -linearConstant r * fpInverse (linearCoefficient r)

/--
The quadratic remainder is nondegenerate; reducing the cubic by it leaves a
nonconstant linear polynomial whose unique root is not a quadratic root.
This is a complete no-common-root certificate when the checker accepts.
-/
def NoCommonRootCheck (r : Triple) : Prop :=
  r.c₂ ≠ 0 ∧ linearCoefficient r ≠ 0 ∧
    candidate r ^ 2 + normalizedU r * candidate r + normalizedV r ≠ 0

instance (r : Triple) : Decidable (NoCommonRootCheck r) :=
  inferInstanceAs (Decidable (r.c₂ ≠ 0 ∧ linearCoefficient r ≠ 0 ∧
    candidate r ^ 2 + normalizedU r * candidate r + normalizedV r ≠ 0))

theorem NoCommonRootCheck_sound (r : Triple) (checked : NoCommonRootCheck r)
    {x : Fp} (cubic : x ^ 3 - 3 * x + (b : Fp) = 0) (quadratic : eval r x = 0) : False := by
  rcases checked with ⟨h₂, hl, hn⟩
  have normalized : x ^ 2 + normalizedU r * x + normalizedV r = 0 := by
    have divided := congrArg (fun z : Fp => z / r.c₂) quadratic
    change eval r x / r.c₂ = 0 / r.c₂ at divided
    have identity : eval r x / r.c₂ = x ^ 2 + normalizedU r * x + normalizedV r := by
      unfold eval normalizedU normalizedV
      rw [fpInverse_eq]
      field_simp [h₂] <;> ring
    rw [identity, zero_div] at divided
    exact divided
  have linear : linearCoefficient r * x + linearConstant r = 0 := by
    unfold linearCoefficient linearConstant
    linear_combination cubic + (normalizedU r - x) * normalized
  have unique : x = candidate r := by
    unfold candidate
    rw [fpInverse_eq, ← div_eq_mul_inv]
    apply (eq_div_iff hl).mpr
    linear_combination linear
  rw [unique] at normalized
  exact hn normalized

/-- Closed kernel arithmetic obligation; no evaluation has been run in this task. -/
theorem cubic_check : NoCommonRootCheck frobeniusRemainder := by
  set_option maxRecDepth 100000 in
    decide +kernel

theorem no_cubic_root (x : Fp) : x ^ 3 - 3 * x + (b : Fp) ≠ 0 := by
  intro root
  exact NoCommonRootCheck_sound frobeniusRemainder cubic_check root
    (frobeniusRemainder_eval root)

end ZolanaVE.ParameterCertificates.CurveOrderCubic
