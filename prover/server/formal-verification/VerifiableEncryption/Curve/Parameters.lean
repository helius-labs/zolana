import Mathlib
import VerifiableEncryption.ParameterCertificates.P256P
import VerifiableEncryption.ParameterCertificates.P256N

/-!
P-256 parameters, primality certificates and the mathematical point group.
This module contains no curve-order assumption. Independent coordinate and
polynomial certificates can be proved before importing the all-point order
theorem used by the circuit soundness development.
-/

namespace ZolanaVE.P256

def p : ℕ := 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
def n : ℕ := 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
def b : ℕ := 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

end ZolanaVE.P256

namespace ZolanaVE.Assumptions

open ZolanaVE.P256

/-- P-256 base-field primality from the recursive Lucas certificate. -/
theorem p256_prime : Nat.Prime p := ParameterCertificates.P256P.p256_prime

/-- P-256 scalar modulus primality from the recursive Lucas certificate. -/
theorem p256_order_prime : Nat.Prime n := ParameterCertificates.P256N.p256_order_prime

end ZolanaVE.Assumptions

namespace ZolanaVE.P256

instance fact_p_prime : Fact (Nat.Prime p) := ⟨Assumptions.p256_prime⟩
instance fact_n_prime : Fact (Nat.Prime n) := ⟨Assumptions.p256_order_prime⟩

abbrev Fp := ZMod p

def W : WeierstrassCurve Fp := { a₁ := 0, a₂ := 0, a₃ := 0, a₄ := -3, a₆ := (b : Fp) }

abbrev P := W.toAffine.Point

end ZolanaVE.P256
