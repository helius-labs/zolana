import VerifiableEncryption.Field.Layout
import VerifiableEncryption.Curve.LadderTable
import VerifiableEncryption.Aes.Lookups

/-!
The lookup-soundness hypotheses of the VE library, bundled. None of them is an
axiom: every top theorem takes a `LookupAssumptions` argument, so the
idealisation is visible in its statement. Each field is the soundness of one
gnark log-derivative lookup argument, idealised as "a satisfied lookup reads
the table at its index":

* `range`: the emulated-field range checks (`RangeChecker.Check`, lookup layout
  with 11-bit pieces) bound a checked value below `2^b`.
* `rows`: the packed P-256 ladder table lookup returns the row at its index.
* `aes`: the spread-byte, substitution and chunk-parity AES lookups have their
  index in range and return the `AesTables.lean` row at that index; the tables
  are pinned to the Go lookup rows by `TestTableAccessorsMatchLookupRows`.

The bundle lives here rather than in `Assumptions.lean` because its fields are
stated over definitions (`Field/Layout.lean`, `Curve/LadderTable.lean`,
`Aes/Lookups.lean`) that import `Assumptions.lean`. The axioms proper stay in
`Assumptions.lean` (`p256_prime`, `p256_order_prime`, `p256_point_order`) and
`FormalVerification/Lemmas.lean` (`bn254_Fr_prime`).

Recorded and deliberately not fixed: `Main.lean` of the Merkle library declares
`poseidon₂_collisionResistant` as an axiom although Poseidon over a finite field
has collisions, so that axiom is inconsistent. This library does not import
`Main.lean` and needs no collision resistance, only the determinism of the
extracted permutations (`Kdf/Poseidon.lean`).
-/

namespace ZolanaVE

variable [Fact (Nat.Prime Order)]

structure LookupAssumptions : Prop where
  range : Field.LookupSound RangeCheck 11
  rows : P256.RowLookupSound
  aes : Aes.AesLookupSem

end ZolanaVE
