# P-256 group-order proof

The goal now includes an independent mathematical route to the all-point
order fact. This development contains no desired-order premise, new axiom,
`sorry`, native evaluation bypass or dependency on the old point-order fact.
After the user authorized Lean, the pinned Lean 4.16.0-rc2 builds passed for
the scalar certificate, cubic certificate, finite counting development and
concrete curve-order integration. The result proves both `Nat.card P = n`
and `n • Q = 0` for every P-256 point. No tests, circuit/witness runs or
generators were executed by this component.

## Certificates and counting argument

`ParameterCertificates/CurveOrderScalar.lean` implements ordinary affine
coordinate addition, including infinity and inverse points, and binary scalar
multiplication with an explicit bit-length bound. Its representation relation
connects every raw addition to Mathlib's nonsingular point group. A closed
kernel-decision obligation checks `rawMul 256 n rawGenerator = none`; its
soundness theorem then establishes a nonzero mathematical point killed by n.
The checker is independent of the extracted circuit and production hints.

`ParameterCertificates/CurveOrderArithmetic.lean` supplies structurally
recursive binary field powering and inversion. The inverse equals the
ordinary field inverse by the checked finite-field identity `x^p=x`, two
power-successor identities and nonzero cancellation, with a separate exact
zero branch. This avoids the stalled large-argument reduction of the direct
inverse representation. The parent independently reviewed this equivalence;
it changes checker representation, not the group-law semantics.

`ParameterCertificates/CurveOrderCubic.lean` implements arithmetic in the
three-coefficient representation of `Fp[X]/(X^3-3X+b)`. Multiplication and
binary powering have evaluation-soundness proofs at every cubic root.
Fermat's theorem shows any field root also kills the reduced `X^p-X`.
A quadratic-to-linear Euclidean certificate rules out a common root.
The concrete checker result passed ordinary `decide +kernel`. Its soundness
therefore establishes the actual cubic no-root statement, not a conditional
certificate premise.

`ParameterCertificates/Cardinality.lean` contains the independent finite
counting development. Encoding points by coordinates proves finiteness.
Each x-fiber has at most two y-values by the degree-two polynomial root bound,
so the whole point group has cardinality at most `2p+1`. The cubic no-root
certificate rules out nonzero two-torsion without invoking group order.
Cauchy's theorem then makes the finite group cardinality odd. A nonzero
point killed by prime n has exact order n, so n divides the cardinality.
The checked numerical inequality `2p+1 < 3n` leaves only the positive odd
multiple n. Lagrange's theorem kills every point by n.

`ParameterCertificates/CurveOrder.lean` combines these concrete inputs into
`point_count : Nat.card P = n` and `point_order : forall Q, n • Q = 0`.
The actual `Assumptions.p256_point_order` axiom is replaced by a theorem
reference to this derived statement. Curve definitions and the already-proved
primality theorem names moved to `Curve/Parameters.lean` to keep imports
acyclic. The old point-order assumption was removed, not moved.

This elementary route agrees with the mathematical strategy independently
formalized in the primary
[HOL Light P-256 development](https://github.com/jrh13/hol-light/blob/master/EC/nistp256.ml):
generator scalar multiplication, cubic no-root, and a simple finite-curve
cardinality bound. That external theorem is not imported as a Lean assumption.
The new proof source does not need a Hasse theorem or its assumption.

## Review and validation boundary

The parent reviewed both certificate soundness developments against pinned
Mathlib slope/addition definitions and the underlying arithmetic. A GPT-6.1
Sol agent independently reviewed the parent's counting/integration source.
It identified a missing Polynomial notation scope, which was corrected, and
found no remaining mathematical or circularity defect in that source review.
Pinned root-cardinality, Cauchy, additive-order, cardinality and divisibility
API signatures were inspected without executing Lean.

Actual successful targets are `Curve.Parameters`,
`ParameterCertificates.CurveOrderArithmetic`, `CurveOrderScalar`,
`CurveOrderCubic`, `Cardinality` and `CurveOrder`. In particular, both closed
arithmetic checks, `nsmul_generator`, `no_cubic_root`, `point_count` and
`point_order` passed. The closed checks use a local recursion limit of
100000 and the existing invocation's 65520 stack setting; no unchecked
native evaluator or tactic infrastructure was introduced. The scalar proof
avoids a linter's eager normalization of an inferred checker-result binder
by transporting its checked result directly. The final cardinality proof
transports `ZMod.card p` through `size ↦ 2*size+1` without enumerating the
enormous field.

The parent independently audited `point_count` and `point_order`: their
only axioms are `propext`, `Classical.choice` and `Quot.sound`. The old
point-order axiom is absent from the checked dependency closure. Final
successful logs are `/private/tmp/ecies-curve-order-lean-7.log` (arithmetic
and cubic), `-8.log` (scalar) and `-9.log` (curve-order integration).
Downstream circuit/completeness proof checks are separate ongoing work.
