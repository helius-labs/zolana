import VerifiableEncryption.Field.Layout
import VerifiableEncryption.Curve.LadderTable
import VerifiableEncryption.Aes.Lookups

/-!
The lookup-soundness hypotheses of the VE library, bundled. None of them is an
axiom: every top theorem takes a `LookupAssumptions` argument, so the
idealisation is visible in its statement. Each field is the soundness of one
production log-derivative lookup argument, idealised as "a satisfied opaque
lookup reads the table at its index". This universal per-witness property is
stronger than probabilistic cryptographic soundness; it is not obtained merely
by applying a root bound to one satisfying assignment:

* `range`: the custom emulated-field range checks (`RangeChecker.Check`, lookup
  layout with 11-bit pieces and tagged narrow ranges) bound a checked value
  below `2^b`.
* `rows`: the custom packed P-256 ladder table lookup returns the row at its index.
* `aes`: the spread-byte, substitution and chunk-parity AES lookups have their
  index in range and return the `AesTables.lean` row at that index; the tables
  are pinned to the Go lookup rows by `TestTableAccessorsMatchLookupRows`.

`Lookup/Algebra.lean` separates quotient constraints, denominator clearing,
degree bounds, and nonzero scalar residues. `Lookup/Challenge.lean` gives finite
probability bounds for fixed nonzero residuals with an explicit point-mass
bound; a uniform challenge is a separate distribution. `Lookup/Production.lean`
records the custom range/row denominators, native index binding and AES table
membership semantics. `Lookup/Kronecker.lean`, `Lookup/Multivariate.lean` and
`Lookup/GroupedSoundness.lean` derive nonzero invalid-query residuals for the
custom tagged-range and twelve-column row arguments using the source radix
caps, arbitrary table counts and actual repeated-query multiplicities. They
give probabilistic false-acceptance bounds for the raw quotient-constraint
model, including poles. None of these modules proves this bundle: the opaque
extraction trace bridge, full range-check semantic composition and production
commitment/hash distribution obligations remain open. Gnark callbacks use
powers of a common commitment; their distribution cap is proved from the root
cap. AES's MiMC-derived coefficient still needs its own cryptographic model.
`Lookup/MiMC.lean` and `Lookup/AesGraph.lean` now record that actual coefficient
recurrence and derive nonzero bivariate residuals and graph-zero acceptance.
`Lookup/Realization.lean` separates per-execution gate certificates, frozen/opened
snapshots, binding/realization/graph failure budgets, and callback union bounds.
Its actual MiMC graph probability premise is explicit and unproved; no
independent-uniform coefficient replacement is asserted. Good-event membership
only concerns the recorded execution, not the universal idealized bundle.
`Lookup/NativeGates.lean` and `Lookup/SourcePrograms.lean` now derive raw
certificates from satisfying frontend gate programs for the actual row/range
denominators and MiMC recurrence. `Lookup/ExecutionSemantics.lean` composes
those source programs with explicit local opaque-call anchors and complete
dense/sparse/wide range plans. The concrete extractor/backend still needs to
produce the program interpretations and anchors: its `Commit` and blueprint
methods remain unimplemented, and opaque extraction omits the gadget bodies.
`Lookup/IdealGraph.lean` proves the finite ideal-permutation graph budget
`(q+D)δ + D/(Order-q)` from a frozen nonzero degree-bounded polynomial and
cached/fresh response laws. The actual public-MiMC graph replacement advantage
is a separately named, unproved premise, not secret-key PRF security or
independent-uniform coefficient sampling. MiMC's round/permutation bijectivity
and exact univariate degree `5^110 > Order` are algebraic proofs.
`Lookup/DigestChallenge.lean` proves the distinct ideal 256-bit digest-word
reduction cap `6/2^256` and callback cap `6r/2^256`; reducing a uniform digest
is not silently treated as uniform Fr. Actual configured-hash output and
grinding distributions remain explicit cryptographic obligations.

The bundle lives here rather than in `Assumptions.lean` because its fields are
stated over definitions (`Field/Layout.lean`, `Curve/LadderTable.lean`,
`Aes/Lookups.lean`) that import `Assumptions.lean`. The remaining mathematical
parameter facts now have explicit certificate proof source: Lucas proofs for
the three primalities, and coordinate/polynomial certificates plus elementary
point counting for `p256_point_order`. No parameter axiom is introduced by
those developments; their pinned kernel checks and axiom audits have passed.
Concrete lookup backend realization and cryptographic premises remain separate
open obligations recorded in the strengthening report.

`Main.lean` no longer assumes concrete Poseidon injectivity or absence of zero
preimages. `FormalVerification/MerkleSecurity.lean` instead returns explicit
collisions or zero preimages for incorrect accepted claims. This VE library
needs no collision-resistance assumption; its hash conclusions use the
independent optimized specification through extracted permutation bridges.
-/

namespace ZolanaVE

variable [Fact (Nat.Prime Order)]

structure LookupAssumptions : Prop where
  range : Field.LookupSound RangeCheck 11
  rows : P256.RowLookupSound
  aes : Aes.AesLookupSem

end ZolanaVE
