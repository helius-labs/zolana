import VerifiableEncryption.Curve.Parameters
import VerifiableEncryption.ParameterCertificates.Cardinality
import VerifiableEncryption.ParameterCertificates.CurveOrderScalar
import VerifiableEncryption.ParameterCertificates.CurveOrderCubic

/-!
Concrete P-256 point-order argument. The concrete computation obligations are
primality, a nonidentity generator killed by n, and absence of roots of the
curve cubic. Each has an independent mathematical certificate predicate with
proved soundness. The counting argument uses neither the old point-order
axiom nor a Hasse-bound assumption.

The arithmetic certificates, counting argument, and all-point order theorem
have passed Lean kernel checking and an audit of their axiom dependencies.
-/

namespace ZolanaVE.ParameterCertificates.CurveOrder

open ZolanaVE.P256

def cubic (x : Fp) : Fp := x ^ 3 - 3 * x + (b : Fp)

theorem short_equation (x y : Fp) : W.toAffine.Equation x y ↔ y ^ 2 = cubic x := by
  rw [WeierstrassCurve.Affine.equation_iff]
  simp only [W, cubic]
  constructor <;> intro h <;> linear_combination h

theorem short_negY (x y : Fp) : W.toAffine.negY x y = -y := by
  simp [WeierstrassCurve.Affine.negY, W]

theorem two_ne_zero : (2 : Fp) ≠ 0 := by decide +kernel

theorem cardinality_bound : Nat.card P ≤ 2 * p + 1 := by
  exact (point_card_le W cubic short_equation).trans_eq
    (congrArg (fun size : ℕ => 2 * size + 1) (ZMod.card p))

/-- The cubic certificate excludes two-torsion independently of the order
argument, preventing a circular cardinality proof. -/
theorem no_two_torsion (Q : P) (h : 2 • Q = 0) : Q = 0 :=
  no_two_torsion_of_no_cubic_root W cubic short_equation short_negY two_ne_zero
    CurveOrderCubic.no_cubic_root Q h

theorem point_count : Nat.card P = n := by
  classical
  letI : Finite P := points_finite W
  letI : Fintype P := Fintype.ofFinite P
  have hsmall : Fintype.card P < 3 * n := by
    rw [← Nat.card_eq_fintype_card]
    exact lt_of_le_of_lt cardinality_bound (by decide +kernel)
  have hc := card_eq_prime_of_small_odd n CurveOrderScalar.generator
    CurveOrderScalar.nsmul_generator CurveOrderScalar.generator_nonzero
    hsmall no_two_torsion
  simpa only [Nat.card_eq_fintype_card] using hc

theorem point_order (Q : P) : n • Q = 0 := by
  rw [← point_count]
  exact card_nsmul_eq_zero'

end ZolanaVE.ParameterCertificates.CurveOrder
