import Mathlib

/-!
Every axiom of the `VerifiableEncryption` library lives in this file.

The P-256 parameters are defined here because the cofactor axiom is stated
over the curve's point group; `Curve/P256.lean` builds on these definitions.
-/

namespace ZolanaVE.P256

def p : ℕ := 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
def n : ℕ := 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
def b : ℕ := 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

end ZolanaVE.P256

namespace ZolanaVE.Assumptions

open ZolanaVE.P256

/-- The P-256 base field modulus is prime. A Pratt certificate is the upgrade
path; trial division is infeasible for the kernel. -/
axiom p256_prime : Nat.Prime p

/-- The P-256 group order is prime. -/
axiom p256_order_prime : Nat.Prime n

end ZolanaVE.Assumptions

namespace ZolanaVE.P256

instance fact_p_prime : Fact (Nat.Prime p) := ⟨Assumptions.p256_prime⟩
instance fact_n_prime : Fact (Nat.Prime n) := ⟨Assumptions.p256_order_prime⟩

abbrev Fp := ZMod p

def W : WeierstrassCurve Fp := { a₁ := 0, a₂ := 0, a₃ := 0, a₄ := -3, a₆ := (b : Fp) }

abbrev P := W.toAffine.Point

end ZolanaVE.P256

namespace ZolanaVE.Assumptions

open ZolanaVE.P256

/-- P-256 has cofactor 1: every rational point is killed by the prime order
`n`. This is the weakest form the ladder and comb proofs use; point counting
is out of reach in Mathlib at the pin. -/
axiom p256_point_order : ∀ Q : P, n • Q = 0

end ZolanaVE.Assumptions
