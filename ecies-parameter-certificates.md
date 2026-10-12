# Parameter certificates — primality checked, curve order checking underway

Date: 2026-10-11. Following the user's authorization to run Lean, the pinned
Lean 4.16.0-rc2 environment successfully built `Lucas`, `BN254`, `P256P`, and
`P256N`. All three prime certificates now have kernel-checked proofs.
Dependent curve-order and circuit developments are being checked separately.

The primary literal-data sources are
[P256PrimeP.lean](https://raw.githubusercontent.com/KeyAIGit/ecdlp-lean-verification/main/Ecdlp/Proved/P256PrimeP.lean)
and [P256PrimeN.lean](https://raw.githubusercontent.com/KeyAIGit/ecdlp-lean-verification/main/Ecdlp/Proved/P256PrimeN.lean).
Only their integer factors, exponents, and Lucas witnesses were used. Their
native evaluation proof bodies and generator were not imported or executed.

`ParameterCertificates/Lucas.lean` provides an ordinary mathematical helper:
`lucasFromFactors N witness factors`. It reduces primality to an exact
product-of-prime-powers identity, prime proofs for every listed base, the full
modular power equality, and every proper-factor modular inequality. Its proof
uses Mathlib's existing `lucas_primality` and prime-divisor-of-product lemmas.
It imports only Mathlib, so it does not depend on the P-256 assumptions or
native-field primality. The factor list cannot bypass a missing prime divisor:
its product is required to equal N-1 exactly.

`ParameterCertificates/P256P.lean` contains the nine recursive p nodes,
ending with Lucas witness 6 for the exact decimal value of the existing
hexadecimal p. `P256N.lean` contains the ten recursive n nodes, ending with
witness 7 for the exact existing group-order integer. Small terminal primes
use `norm_num`; larger nodes depend on earlier Lucas nodes. Factor arithmetic
uses `norm_num`; modular equalities use `reduce_mod_char`, and normalized
proper-factor inequalities use kernel-checked `decide`.

The pinned Mathlib implementation was read at
`Mathlib/Tactic/ReduceModChar.lean` and `Mathlib/Tactic/NormNum/PowMod.lean`.
It constructs proof terms for modular powers by fast modular exponentiation.
This source uses that existing proof-producing tactic rather than adding an
evaluator, native-decide route, axiom, custom tactic, or build configuration.

The actual `Assumptions.p256_prime` and `Assumptions.p256_order_prime`
declarations have been changed from axioms to theorems referring to these
certificates. Their public names and the existing Fact instances are preserved.
The certificates passed; validation of all dependent modules and their axiom
guards remains underway.

The helper, all nineteen recursive P-256 nodes, and their decimal/hexadecimal
connections passed under the pinned toolchain. Remaining validation includes
dependent modules. An auxiliary `#print axioms` check confirmed that each
top-level prime certificate depends only on `propext`, `Classical.choice`, and
`Quot.sound`; no primality axiom or native evaluation axiom remains in them.
Resource use has not been
systematically measured. Elaboration failures were repaired in ordinary
checked proof source; no bypass was used.

Primality of n does not prove the curve has n rational points. The subsequent
independent development in [ecies-curve-order-strengthening.md](ecies-curve-order-strengthening.md)
adds scalar and cubic certificate source, finite-point counting, exact
cardinality n, and all-point annihilation. The actual `p256_point_order`
declaration now refers to that development instead of an axiom. Both closed
arithmetic checks, counting and integration passed Lean. The independent
axiom audit of `point_count` and `point_order` contains only `propext`,
`Classical.choice`, and `Quot.sound`. No extracted Go source
was changed, so these parameter changes do not stale circuit extraction.

Static arithmetic review uses exponent 2 for the factor 2 in the
187019741 predecessor: `187019741 - 1 = 2^2 * 5 * 9350987`. An exponent-1
variant would be incorrect. The literal product remains an explicit
`norm_num` obligation, now checked by Lean.

## BN254 native-field extension

`ParameterCertificates/BN254.lean` now adds a complete recursive proof-source
chain for BN254 Order, and `FormalVerification/Lemmas.lean` changes the actual
`bn254_Fr_prime` axiom to a theorem referring to it. This is likewise an
kernel-checked certificate replacement. Dependent axiom guards still require
their own checks.

The top witness 5 and three larger-node data are attributed to the primary
[CompPoly BN254 source](https://github.com/NethermindEth/CompPolyFri/blob/master/CompPoly/Fields/BN254.lean).
Missing predecessor factors were obtained from read-only FactorDB API data:

* [405928798](https://factordb.com/api?query=405928798): 2 * 11 * 3691 * 4999.
* [639533338](https://factordb.com/api?query=639533338): 2 * 229 * 853 * 1637.
* [12048837556](https://factordb.com/api?query=12048837556): 2^2 * 7^2 * 661 * 93001.
* [5156902474396](https://factordb.com/api?query=5156902474396): 2^2 * 107 * 12048837557.

No local factorization or generator was executed. These dataset values are
untrusted source literals: exact products, terminal prime facts, and modular
equations are all ordinary proof obligations. The four predecessor witnesses
are explicitly 22, 2, 2, and 2. An authorized auxiliary Lean calculation found
candidate 22 for the first predecessor; the final source independently proves
all its modular obligations in the kernel. No custom tactic, build
configuration, axiom or native-decide proof path was added.

No axiom guard files were changed by this component; the parent owns those.
The new import chain goes from the existing FormalVerification lemma module
to Mathlib-only parameter certificates and does not import P-256 assumptions
or depend on the native primality instance it constructs.
