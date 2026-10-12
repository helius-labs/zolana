import VerifiableEncryption.Curve.Parameters
import VerifiableEncryption.ParameterCertificates.CurveOrder

/-!
The original public parameter theorem names are preserved. Primality has
recursive Lucas certificate proof source in Curve.Parameters. The all-point
order statement below follows from independent coordinate/polynomial
certificates and an elementary finite-group cardinality proof. No parameter
or curve-order axiom is declared here.

The concrete primality and curve-order developments have passed the pinned
Lean kernel checks; their axiom audits contain only standard logical axioms.
-/

namespace ZolanaVE.Assumptions

open ZolanaVE.P256

/-- Every rational P-256 point is killed by n, from the concrete point-count
development rather than a group-order assumption. -/
theorem p256_point_order (Q : P) : n • Q = 0 :=
  ParameterCertificates.CurveOrder.point_order Q

end ZolanaVE.Assumptions
