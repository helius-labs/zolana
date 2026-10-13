# ECIES formal-verification strengthening — implementation and validation status

Branch: `jorrit/merge-std-ecies`. Starting commit:
`c255c6400c0c824cf46b42b6e1f48dfd03becff5`. Initial review: 2026-10-11.
Latest validation checkpoint: 2026-10-12.

**The active goal is unfinished.** Following the user's scope update, remaining
work focuses on P-256 completeness, concrete lookup arguments and mathematical
parameters; Poseidon and Merkle are outside the remaining goal. This change
contains newly kernel-checked foundations and unfinished proof source. Full
fixed-base P-256 multiplication now passes kernel checking; variable-base and
agreement completeness and the complete production lookup security/realization
reduction remain open.
The independent curve-order argument now has source through all-point
annihilation. Its primality, scalar, cubic, counting and integration components
have passed, with independent axiom audits. The refreshed P-256 soundness chain
also passes; downstream KDF, AES and envelope elaboration remains unvalidated.

## Initial recheck and scope

The checkout was already on the requested branch, at the exact commit reviewed
in [ecies-std-proof-review.md](ecies-std-proof-review.md). That report was read
before editing. Current source confirmed its conclusions: the extracted
40-byte contextual envelope already composed P-256, KDF and three AES-CTR
blocks; Poseidon was defined by extracted unique outputs; lookup semantics
were explicit ideal premises; three P-256 parameter axioms and BN254
primality remained; `Main.lean` installed global injectivity and no-zero
assumptions for Merkle Poseidon.

Three GPT-6.1 Sol agents contributed independent components. Work and Lean
checks now run serially, with one worker and one Lean process at a time, in
accordance with the user's resource constraint. The parent reviews
their source against the relevant extracted predicates and pinned dependency
declarations and requests corrections before integration. Agents separately
review the parent's arithmetic bridges and constraint repair. An agent also
reviewed the earlier Merkle reductions. The
`review-diff` skill was applied for source review. No zk-audit skill was used.

The native slope guard now has a constrained field-equation fallback in
production Go. An explicit formal wrapper retains the genuine standalone
guard. The user authorized the existing VE generators and their required Go
and circuit compilation; their outputs were generated in a temporary
directory, reviewed and integrated. The three middle-step Quad continuation
bodies changed, and three flagged field checks were added. All previous
extracted declarations remain present; their other bodies are unchanged.
The 9,626 existing constant literals retain their indices, with 485 new
literals appended to the extraction's constant data. Generated field/instance
module partitions moved; proof imports now collect the correct instances.

Production hints remain unchanged. Public P-256 and ladder functional
soundness interfaces retain their explicit lookup premises. Internal Quad
lemmas now expose native nonzero or the doubling-aware field equation,
which supplies the group-law guard in the formerly rejected case. The
refreshed P-256 soundness proofs have passed kernel checking. KDF, AES and
envelope elaboration remain unvalidated. Earlier
independent hash changes remain in place, with no further Poseidon/Merkle work.
CI, build configuration and custom tactic infrastructure were left unchanged.
Original review reports were preserved. No commits were made before the user
requested this checkpoint snapshot.

## Status against each original limitation

| Requested strengthening | Concrete source change | What remains |
| --- | --- | --- |
| Independent Poseidon | Frozen literal C/S/M/P tables, independent optimized permutation, round and complete schedule bridge proof source for arities 2/3/7/8; all four public VE hashes now use that specification. | Elaboration of bridges and downstream soundness; optimized-to-unoptimized HADES equivalence and its unoptimized parameter provenance. |
| P-256 completeness | Full circuit-API valid-input domain; full actual fixed-base multiplication witness theorem now kernel-checked, with all selectors, intermediate points, slopes, decompositions, quotients, carries, coordinate recovery and complete-addition tail constructed. Both Triple constructors, seven chord-Add variants, HalfTangent and all four Quad constructors pass against actual extracted predicates. The current full native scalar-core composition module also passes. Mathematical ladder decomposition, prefixes and chords pass. A concrete production-hint path fails the old native guard; its repair and refreshed extraction are integrated. | Scalar-core axiom audit and whole variable-base/agreement witness assembly, downstream envelope checks, and Go-hint correspondence. The composition lemmas retain primitive premises that the outer witness assembly must construct. Local Quad geometric premises must be discharged in the whole ladder. No universal circuit-unsatisfiability claim is established for the found input. |
| Concrete lookups | Denominator clearing at poles; grouped invalid-query nonzeroness with multiplicities and index binding; radix degree/probability bounds; actual MiMC graph model; staged commitment/challenge reductions; native gate-program semantics and local opaque-call anchors. | Mechanically justified frontend/backend and extraction-anchor realization; actual MiMC graph cryptographic bound. The production challenge distribution and commitment/hash security remain explicit assumptions. |
| Merkle assumption | Removed both global hash axioms and their instances; actual extracted acceptance/binding statements now return collisions or zero preimages; path and chain reductions identify compression inputs in the compared transcripts. | Elaboration and kernel checking. Computational hardness is a separate cryptographic claim, not proved by the deterministic reductions. |
| Parameter axioms | All three recursive prime certificates passed Lean and their axiom audit. Independent scalar/cubic certificates, finite-point counting, exact point count and all-point order also passed; their axiom audit contains only standard logical axioms. | Dependent circuit proofs and downstream axiom guards. No replacement curve-order assumption was introduced. |

## Independent Poseidon and preserved envelope composition

[Parameters.lean](prover/server/formal-verification/VerifiableEncryption/Kdf/Poseidon/Parameters.lean)
fixes the optimized tables from
[iden3 v0.0.17](https://github.com/iden3/go-iden3-crypto/blob/v0.0.17/poseidon/constants.go),
with the module digest and inspected file SHA256 recorded in source.
These literals are independent of the extracted `K_*` definitions.
[Specification.lean](prover/server/formal-verification/VerifiableEncryption/Kdf/Poseidon/Specification.lean)
fixes zero capacity, ordered field inputs, coordinate-zero output, the x^5
S-box, column-major matrices, sparse updates using the old head, eight full
rounds, and partial-round counts 57/56/64/63 for widths 3/4/8/9.

[Width3.lean](prover/server/formal-verification/VerifiableEncryption/Kdf/Poseidon/Width3.lean)
and [Layers.lean](prover/server/formal-verification/VerifiableEncryption/Kdf/Poseidon/Layers.lean)
relate the actual extracted round predicates and whole schedules to those
functions. The whole-schedule comparisons preserve vector-valued round
operations, so they do not expand all state coordinates recursively across
the partial rounds. Frozen constant slices and matrix/wiring comparisons
are obligations of those proofs: an implementation change cannot change the
reference values along with it.

The existing `Poseidon_2/3/7/8_rw` interfaces now use these bridges. Therefore
`KeySchedule_32_12_sound`, `envelope16_sound` and `envelopeMerge_sound` retain
their composition proofs while referring to independent hashes through
`Kdf.poseidon`. No desired encryption result was added as a premise.

This specification fixes the published optimized iden3 algorithm directly.
It does not derive that algorithm from separately fixed unoptimized HADES
constants. Replacing P/S with M while retaining optimized C is not a valid
reference construction. The transformation of round keys and sparse matrix
factorization still need an independent mathematical equivalence proof.
Parameter-generation security, collision resistance and Rust interoperability
are also distinct claims. See [the Poseidon component report](ecies-poseidon-strengthening.md).

## Completeness and hint correctness

[Completeness.lean](prover/server/formal-verification/VerifiableEncryption/Curve/Completeness.lean)
defines byte-bounded 32-byte scalars with nonzero residue modulo n, and
canonical on-curve 65-byte recipient points with prefix 4. This is the
mathematical domain of the Go circuit API; the Go parser accepts scalar
representatives at least n, whereas Rust typed private keys use canonical
scalars. The definition does not exclude exceptional ladder prefixes or
assume hint success. Zero-residue scalars are invalid private keys because
their products are infinity, which this affine output API cannot encode.

The new primitive constructors begin with the actual extracted predicates.
They supply quotient/remainder splits and 11-bit range pieces, compressed
packing outputs, and native guard witnesses under their exact local
obligations. `RangeComplete` is a visible completeness premise, separate from
lookup soundness. Geometric lemmas construct slopes and coordinates; separate
primitive constructors supply the emulated polynomial quotients and carries.
The checked fixed-base theorem composes both layers against the actual
extracted multiplication predicate.

The prior inverse-four eager-branch repair was rechecked in `emcurve/ladder.go`:
the discarded addend is selected before the guarded addition. That repair
does not discharge every eager operation. The full fixed-base constructor
now supplies its recoding, intermediate affine points, integer limbs, modular
quotients and carries. Mathematical ladder decomposition, slot/prefix and
denominator facts also pass, but they still need composition through all
actual variable-base operations and the whole agreement continuation. The
checked first, transition and ordinary Quad constructors include the repaired
eager native flag and fallback, with explicit local geometric premises. The
final Quad also passes against its reduced-SY, unflagged LastSlope constraints.
All four constructors have passed independent review and axiom audits. Whole
scalar-core composition now passes as a whole module, with its axiom audit
still pending. Variable-base/agreement witness assembly remains unfinished.

`nativeSlope_alias` first exposed an abstract obstruction to a naive converse
of the slope guard. The user subsequently authorized only the prepared offline
arithmetic search `/private/tmp/ecies-native-slope-counterexample.py`; that
script was run once. It found scalar 2 and the valid uncompressed recipient
`041bafbedd4beef1aa27c8c8443dae7bef8314ab20a58ddfe300f60f11da68cd409b335b71ccfff12ab40b94b0509a97f141549b23c5fa96564a562f8953623db6`.
The pinned rational-reconstruction source returns numerator 2 and denominator
1 without entering its loop. For that path, the initial accumulator is -Q and
the selected middle row is 3Q. The balanced tangent/half-tangent combination
equals BN254 Order exactly, so the native guard rejects it despite distinct
P-256 slopes and finite mathematical additions. The script did not run the
production hints or circuit. This is an independently evaluated arithmetic
and source-tracing counterexample to the expected hint path; alternative
nonprimitive decomposition witnesses have not been ruled out.

The reviewed constrained fallback is now integrated with refreshed extracted
predicates and bound certificates. `IsZero` fixes the native alias flag. A zero
product requires the P-256 `LastSlope` equation; a nonzero product retains the
old guard implication. The existing `quad_add_correct` theorem supports both
cases and rejects inverse-point collisions. Primitive mathematical witnesses
construct this field identity and the flag without requiring native residue
exclusions. The actual three middle-step soundness proofs and table steps have
been adapted in source. Extra constraint cost has not been measured.

Full multiplication/agreement witness assembly and Go-hint correspondence
remain unfinished. See
[the completeness report](ecies-p256-completeness.md).

## Lookup algebra and cryptographic boundary

[Algebra.lean](prover/server/formal-verification/VerifiableEncryption/Lookup/Algebra.lean)
uses the actual multiplicative quotient relation `q_i d_i(c)=w_i` and a zero
sum. It clears denominators using multiplication, including poles. Table
multiplicities are arbitrary committed field elements. Repeated scalar
poles are grouped; a positive invalid-query occurrence count below the field
characteristic cannot disappear as a field residue.

[Challenge.lean](prover/server/formal-verification/VerifiableEncryption/Lookup/Challenge.lean)
uses normalized finite rational distributions. If a fixed nonzero residual
has N factors of denominator degree at most D, and challenge point masses
are at most delta, acceptance has probability at most `(N-1) D delta`.
Denominator poles have the separate bound `N D delta`, when each denominator
polynomial is nonzero. A uniform root challenge has cap `1/|F|`; callback
power r has cap at most `r/|F|`, or `r delta` for a general root cap. This
does not make callbacks independent.

[Production.lean](prover/server/formal-verification/VerifiableEncryption/Lookup/Production.lean)
models the custom tagged-range challenge power, radix-256 P-256 row columns,
native index binding, and AES indexed tables with a coefficient derived
from MiMC of the callback value. A fixed pre-challenge batch is separated
from post-challenge quotient witnesses. True indexed membership gives the
existing deterministic table semantics; membership is not inferred from an
opaque extracted predicate without its deferred commitment constraints.

Concrete coefficient proofs give tagged-range degree at most `2^20` and
row degree at most `256^12`, and show both denominator polynomials are
nonzero because their X coefficient is one. Polynomial equality binds the
range tag/value and all twelve row columns plus the index. The specialized
pole budgets are `N D r delta`; equality of two distinct encoded tuples at
a challenge has bound `D r delta`, derived from a nonzero difference
polynomial. The subsequent grouped-tuple development establishes nonzeroness
of the full residual for invalid tagged/row queries.

`Kronecker.lean`, `Multivariate.lean` and `GroupedSoundness.lean` now derive
nonzero residuals for invalid tagged/row queries. Distinct indexed tuples
give independent linear denominator factors before compression. The support
cap prevents exponent carries under radix substitution. Grouping raw quotient
constraints works at poles, and an invalid tuple has a nonzero negative
occurrence-count residue regardless of claimed table counts. These proofs have
passed Lean checking; they derive nonzeroness rather than assume it.

These algebraic facts do not construct an unconditional `LookupAssumptions`
value. Production traces must still be related to the model. Commitment
binding/extraction, Fiat–Shamir/MiMC distribution,
adaptive transcript attempts and an overall callback failure budget remain
cryptographic obligations. See [the lookup report](ecies-lookup-strengthening.md).

## Merkle reductions

[Collision.lean](prover/server/formal-verification/FormalVerification/Collision.lean)
proves honest-path recovery for arbitrary compression functions and compares
candidate/authentic compression pairs along paths and hash chains. Root
agreement with an incorrect opening yields distinct inputs with equal
outputs at a recorded path level.

[MerkleSecurity.lean](prover/server/formal-verification/FormalVerification/MerkleSecurity.lean)
connects these reductions to the actual extracted inclusion and range batch
predicates, including reversed sibling ordering. Wrong occupied-range
endpoints yield a collision; an opening into an empty range slot yields an
explicit zero preimage. Different accepted public columns with the same
input hash also yield a collision.

`Main.lean` exports these reductions and retains deterministic input-hash
correctness. It no longer installs global injectivity or no-zero instances.
Older internal lemmas in `FormalVerification/Merkle.lean` still express
conditional injective-hash facts; the new public security proofs do not use
those premises. No unchanged global assumption was moved into a new premise.
The separate Merkle hash remains its concrete extracted deterministic hash;
the VE independent specification change concerns the KDF/envelope hashes.

## Parameter certificates and remaining mathematics

[Lucas.lean](prover/server/formal-verification/VerifiableEncryption/ParameterCertificates/Lucas.lean)
derives primality from an exact factor-product identity, recursively proved
factor primes, a full modular power equality and proper-factor inequalities.
It imports only Mathlib and uses the existing Lucas theorem.
[P256P.lean](prover/server/formal-verification/VerifiableEncryption/ParameterCertificates/P256P.lean)
and [P256N.lean](prover/server/formal-verification/VerifiableEncryption/ParameterCertificates/P256N.lean)
contain all nineteen recursive certificate nodes. Their literal data come
from the linked primary source in
[the parameter report](ecies-parameter-certificates.md), but upstream native
evaluation proofs were not imported. Modular arithmetic uses the pinned
Mathlib proof-producing `reduce_mod_char`; factor identities and terminal
prime proofs use `norm_num`.

[BN254.lean](prover/server/formal-verification/VerifiableEncryption/ParameterCertificates/BN254.lean)
adds the native-field certificate chain and replaces the actual
`bn254_Fr_prime` axiom through `FormalVerification/Lemmas.lean`. Published
large-node data and read-only predecessor factorizations are cited in the
parameter report. Four predecessor witnesses use complete standard-tactic
alternatives, each required to solve all numeric obligations; no successful
base is claimed before elaboration. These are untrusted input literals to
checked proof obligations, not trusted database primality assertions.

All three primality axioms have therefore been replaced by kernel-checked
recursive certificates. Their independent axiom audit contains only standard
logical axioms. Existing axiom guards retain exact
expected dependency lists, now containing Lean's standard logical axioms.

Primality of n alone does not establish curve order. The independent
development now described in
[the curve-order report](ecies-curve-order-strengthening.md) supplies a
coordinate scalar-multiplication certificate and cubic no-root certificate,
plus finite-point counting. At most two points lie over each x-coordinate;
absence of two-torsion makes the group cardinality odd; the prime-order
generator makes n divide it; and `2p+1 < 3n` forces that cardinality to n.
Lagrange's theorem then kills every point by n. The actual point-order axiom
has been replaced in source by this argument, not moved into another premise.
No Hasse assumption is needed. Both concrete arithmetic checks, the counting
argument and all-point order theorem passed Lean and their axiom audit.
Dependent circuit validation is tracked separately below.

## Independent source review and unperformed validation

The parent reviewed the agent changes against the extracted split/packing
and round definitions, pinned Mathlib Lucas/root/degree/fiber-sum lemmas,
and production API/challenge code. A material Poseidon expression-expansion
risk was corrected by preserving independent vector round layers. An
upstream certificate factor typo for 187019741 was corrected to
`2^2 * 5 * 9350987 = 187019740`, rather than assuming the downloaded source
was correct. The parent updated existing axiom-guard expectations to match
the source removal of primality axioms, without weakening the guards.

Textual diff/whitespace review and searches found no newly introduced
`sorry`, `admit`, axiom, native-decide route or unchecked bypass. This is a
source inspection result. The existing native-decide Merkle test-vector
declaration was not changed or executed.

**Authorized execution performed:** the single offline native-slope arithmetic
search; Go compilation of the generator binary; existing `extract-ve-circuit`
and `extract-ve-tables` commands into `/private/tmp/ecies-native-slope-extraction`,
including their circuit compilation and field-bound certificate generation.
Both generator commands completed successfully; they were refreshed after
adding the standalone formal guard. The source comparison covered declarations,
constant-index preservation and dependency imports. This is not kernel checking
or production witness execution.

The user subsequently authorized Lean execution. The pinned Lean toolchain
has successfully checked the Lucas helper, BN254 and both P-256 prime
certificates, both curve-order arithmetic certificates, finite-point counting,
the exact point count and all-point order theorem. Their axiom audits contain
only Lean's standard logical axioms. Generic folded/nonfolded witness
construction, concrete scalar-check capacities, all regenerated field soundness
modules, and the lookup algebra, challenge, radix specialization, multivariate,
ideal digest, production polynomial, MiMC and honest-witness modules also passed.
Checking of concrete extracted constructors and downstream soundness/security
modules is underway. Elaboration errors
are being corrected; these passing foundations do not establish full ECIES
completeness.

The repaired `QuadStep` and `LadderTable` soundness modules, every mathematical
ladder decomposition/selection/prefix/chord/final/half-tangent component, the
literal old-guard counterexample, balanced-limb and canonical constructors,
and thirteen integrated Quad/Triple/Add composition bridges now pass. Their
audited endpoints use only standard logical axioms. Generated assertion
constructor chunks 1–77, 79 and 82, Lazy chunks 1–26 and 32–59
(plus the separately checked chunk 61), and all three
scalar-modulus/half-product reverse bridges also pass. The remaining arithmetic chunks and
full fixed-base, variable-base and agreement witness assemblies are still
being checked or implemented. These composition results retain explicit
primitive premises; the outer constructors must construct those premises.

The existing fixed-base soundness theorem has also passed against the current
extraction and parameter certificates. The main/p1 variable-base prefix bridge
passed Lean and an axiom audit. Its primitive premises and exact p2 continuation
remain explicit. Native binary slices, shifted words, and the nonzero sum of
denominator bits have checked constructions from the mathematical decomposition.

The existing variable-base soundness theorem also passes. Fixed-base selector,
recoding, window-coordinate and 257-bit constructions pass, with six component
and soundness endpoints audited against only standard logical axioms. The
unified x/y and flag-product interfaces now use the checked generated primitive
constructors, preserving their explicit premises and actual extracted targets.
Coordinate and reduced-output helpers pass separately. The signed twelve-column
rows, sixteen-row mirroring, native slot permutation, and the geometric
noncollisions for all eight eager slot additions also pass. Full multiplication
and agreement assemblies remain open.

The full fixed-base window selection module subsequently passed Lean. On
2026-10-12 the user requested one active agent and one Lean process at a time.
All three subagents were interrupted, all owned checking jobs were closed, and
the process list confirmed no remaining Lean process. Remaining checks are
queued for sequential execution; interrupted checks have no passing result.

The first and second fixed-base slope reverse interfaces and their numerical
capacity interfaces subsequently passed against the already checked generated
primitives. The first Lazy-update witness/continuation interface also passed.
Their theorem premises and extracted targets are unchanged. Pure coordinate
and vector-layout helpers were moved to the checked coordinate module so these
steps can be validated without importing unfinished complete-addition proofs.

The standalone triple arithmetic-to-native assembly helper passed Lean with
the same five actual primitive premises and constructed balanced slope pieces.
The full ordinary geometric triple constructor subsequently passed after
factoring its arithmetic witnesses and vector layouts into checked lemmas.
The first comb-step geometric constructor remains unverified; stopped or quiet
checks are not counted as proofs.

The original public-key derivation and key-agreement soundness modules now also
pass against the current extraction. All seven actual affine-addition witness
constructors pass and their endpoints have standard-only axiom audits. They
construct canonical output coordinates, all 48 unsigned hint pieces, the
squared-difference Lazy value, and both field equations. Their local distinct-x
premises are supplied by the checked slot and prefix mathematics in the full
assembly, which remains unfinished.

The remaining p2–p9 scalar-core composition source has been independently
reviewed and generated. It keeps every individual primitive/range/guard premise,
constructs pure binary/select/lookup wires, and has exact next-input records.
Its kernel check and full continuation assembly remain pending; generation is
not evidence that these new statements are proved.

All nine folded-evaluation constructor chunks now pass, including ten actual
extracted primitives and their numerical quotient/carry capacity obligations.
Both directions audited for these primitives use only the standard logical
axioms. The explicit quotient, residual and carry evaluation equalities fixed
the failed generated proof without changing constraints or hiding obligations.

On 2026-10-12, serial parent review and checking completed
`CompletenessTripleX`, `CompletenessTripleY`, `CompletenessTripleArithmetic`,
and the full `triple_h2c0228bb_complete` endpoint. The latter constructs the
actual extracted `Triple_8_8_h2c0228bb` predicate for every finite reduced
input point, with `RangeComplete` explicit. Its tangent and return-slope
denominators follow from the checked geometric triple theorem; both balanced
slopes, the Lazy doubled x coordinate, and canonical x/y Eval outputs are
constructed. Six arithmetic/full endpoints have axiom audits containing only
`propext`, `Classical.choice`, and `Quot.sound`. Proving layout and value lemmas
with abstract elements before substituting constructed slopes avoids the long
checker expansion without changing a premise or circuit constraint. Logs:
`/private/tmp/ecies-triple-x-factored-9.log`,
`/private/tmp/ecies-triple-y-factored-1.log`,
`/private/tmp/ecies-triple-arithmetic-factored-7.log`,
`/private/tmp/ecies-triple-factored-2.log`, and
`/private/tmp/ecies-triple-factored-axioms.log`.
The selected-y Triple subsequently passed its full kernel check and five-endpoint
axiom audit. Parent source review confirmed the actual `selC` input bounds and
the selected `h8cfcaa46`, `h6a3ed603`, and `h70dd0288` predicates. A redundant
layout wrapper was removed; the selected-y helper and full endpoint then passed
parent checks again (`/private/tmp/ecies-triple-selected-y-parent.log` and
`/private/tmp/ecies-triple-selected-full-parent.log`). The selected endpoint
constructs every actual primitive witness and proves `3P`, with the same
`RangeComplete` premise and finite input domain. Its audit uses only the three
standard logical axioms (`/private/tmp/ecies-triple-selected-axioms.log`).
Four full Quad constructors, complete fixed-base and variable-base assemblies,
and key-agreement completeness still require work.
This is mathematical witness existence for both actual Triple components;
actual Go-hint correspondence has not been established.

The first fixed-base chain constructor now also passes Lean. Parent checking
found that the current generated 49-step composition module still needed its
finite-index identities converted to the literal native indices before
rewriting. The proof source and its renderer now emit explicit `change`
statements for all eight balanced slope limbs. The actual circuit, constants,
premises and conclusions are unchanged. All 49 later-step composition lemmas
then passed in the current module (`/private/tmp/ecies-chain-composition-main-3.log`).
The renderer change has not yet been verified by fresh generation.

`CompletenessCombFirstNative`, `CompletenessCombFirstArithmetic`, and the full
`combFirst_complete` theorem pass. They construct the actual four-element
slope assertion, bounded Lazy x-update, balanced slope pieces and first-step
native continuation, and prove the group sum. The chord denominator follows
from the explicit local point noncollision supplied by fixed-base prefix
mathematics. All 54 audited composition/first-step endpoints use only the
three standard logical axioms. Logs:
`/private/tmp/ecies-comb-first-native-2.log`,
`/private/tmp/ecies-comb-first-arithmetic-1.log`,
`/private/tmp/ecies-comb-first-full-1.log`, and
`/private/tmp/ecies-comb-first-chain-axioms.log`.
The second step subsequently passed its full check and parent review. Its
native and arithmetic constructors preserve the actual `hd0a2e1d5` predicate,
six-element `hd6f972c2` assertion, and `h33616364` Lazy bounds. The shared
`CombMath` slope equation was factored over abstract elements and checked.
An unused local compatibility wrapper was removed after confirming no callers;
the full theorem and remaining seven endpoints then passed parent checking
and standard-only axiom audit (`/private/tmp/ecies-comb-second-full-parent.log`,
`/private/tmp/ecies-comb-second-parent-axioms.log`). The original input bounds,
`RangeComplete`, local point noncollision, group relation, and extracted
continuation are unchanged. Remaining complete step constructors and full
multiplication assembly are still unverified; a pure composition lemma does
not construct its arithmetic premises.

`Field.CompletenessLazy.combLazy_complete` also passes Lean and a standard-only
axiom audit. It constructs a concrete native output using the checked first
Lazy witness, a checked actual-body equality for the chosen hash, and the
existing bound/congruence soundness theorem. It never assumes a satisfying
witness. This generic constructor is available for the remaining fixed-base
steps; their individual instantiations are not yet checked. Logs:
`/private/tmp/ecies-comb-lazy-generic-2.log` and
`/private/tmp/ecies-comb-lazy-generic-axioms.log`.

All forty-nine remaining complete fixed-base step constructors now pass Lean,
together with their actual per-hash Lazy witnesses. Parent review confirmed
the abstract matching/layout proofs and actual primitive targets, and verified
that all49 outer statement headers exactly match the earlier generated source.
The unchanged required assertion in chunk77 also passed. The103-endpoint audit
(49 complete steps,49 Lazy constructors,4 shared helpers and assertion77) uses
only the three standard logical axioms. This constructs the arithmetic premises
left explicit by the composition-only lemmas; full fixed-base multiplication
assembly remains unverified.

The parent compiled the already-authorized generator with `GOMAXPROCS=1` and
`go build -p 1`, then ran existing `extract-ve-tables` into
`/private/tmp/ecies-comb-reviewed-extraction-1`. Both corrected chain
composition source and complete comb-step source reproduce byte-for-byte.
All277 generated files initially matched; the only different module was
ScalarCore's previously reviewed ten nil-case proof repairs. Those exact
proof-only replacements were integrated. No statement, native wire, circuit,
table or certificate changed. The full ScalarCore module remains unvalidated.
Generator log: `/private/tmp/ecies-comb-reviewed-generator-1.log`.

The final fixed-base x reduction and implicit-y recovery interfaces now also
pass Lean and an eight-endpoint axiom audit using only standard logical axioms.
Their remainder/quotient/carry witnesses come from the already checked actual
generated primitives `h78194ae0` and `h0845ed76`. Public completeness premises
and extracted targets are unchanged; the obsolete unused cross-hash native
equality was removed. Logs: `/private/tmp/ecies-comb-reduce-parent-1.log`,
`/private/tmp/ecies-comb-recover-parent-2.log`, and
`/private/tmp/ecies-comb-final-fields-axioms.log`.
The full fixed-base assembly's stale second-step declaration reference was
corrected to the checked `combSecond_complete`; all48 remaining referenced
generated step declarations exist. This source fix does not establish the
full theorem. Tail composition and full multiplication checking remain required.

Complete addition now passes its full witness-existence theorem, including
the equal-point tangent case. Parent review confirmed the canonical guards,
same-x Boolean/inverse hint, all balanced range pieces, both flag assertions,
unified slope assertion, and both actual Eval outputs. Every primitive premise
is constructed by the outer `completeAdd_with_point_complete` theorem.
The original canonical-x/reduced-coordinate, finite and noninverse domain and
`RangeComplete` premise are unchanged. An unused weaker wrapper and unused
layout lemma were removed after confirming no callers. The layout and full
theorem then passed parent checks, and all nine remaining audited endpoints
use only standard logical axioms. Logs:
`/private/tmp/ecies-completeadd-layout-parent.log`,
`/private/tmp/ecies-completeadd-full-parent.log`, and
`/private/tmp/ecies-completeadd-parent-axioms.log`.
The fixed-base tail and full multiplication assembly subsequently passed.
`Curve.CompletenessScalarMulBase.scalarMulBase_complete` constructs canonical
coordinates with the group identity `S.value • G` and a satisfying continuation
for actual `ScalarMulBase_8_h3037b025`, for every reduced 256-bit scalar with
nonzero residue modulo n. `RangeComplete` is the explicit lookup-completeness
premise. There is no assumed successful operation, extra point exclusion or
narrower scalar interval. All intermediate noncollisions, final noninverse
geometry, fifty actual chain steps, x/y recovery and complete addition are
assembled in this checked endpoint.

Checking exposed duplicate `affine_of_nonzero` declarations in independent
fixed-base/ladder modules. Their equivalent coordinate witness was consolidated
in `CompletenessAffine`, with the fixed-base equality orientation adjusted;
the shared theorem and both callers passed again. The final recoding-input
equality was closed definitionally without changing wires or premises.
The full fixed-base theorem, shared affine helper, prefix coordinate theorem,
half-tangent theorem and tail pass axiom audits with only `propext`,
`Classical.choice`, and `Quot.sound`. Logs:
`/private/tmp/ecies-fixed-base-complete-parent-3.log`,
`/private/tmp/ecies-fixed-base-complete-axioms.log`,
`/private/tmp/ecies-affine-shared-parent.log`,
`/private/tmp/ecies-comb-bits-shared-affine.log`, and
`/private/tmp/ecies-half-tangent-shared-affine.log`.
This proves mathematical witness existence for fixed-base multiplication;
actual Go-hint correspondence and execution remain unestablished. Variable-base
and agreement completeness remain unfinished.

An independent GPT-6.1 Sol source review of the full fixed-base assembly found
no defect. Static traversal confirmed all fifty actual chain hashes in order,
all fifty-one windows/top/recoding constructions, and the exact final nested
wiring. The full reduced scalar interval is retained without truncation or
an S<n restriction, and the final group identity has the correct orientation.

The actual half-tangent constructor now also passes Lean for every finite
reduced input point, with `RangeComplete` explicit. Parent review confirmed
the mathematical half point/odd-order root, both balanced24-piece hints, actual
`Lazy_8_h158c056f`, `CheckPolynomial_40_h0930c075`, its quotient/carry witness,
and exact native return. The required unchanged Lazy62 leaf was checked.
All nine audited endpoints use only the three standard logical axioms; there
is no inverse-four exclusion or successful-operation premise. Logs:
`/private/tmp/ecies-half-required-lazy62-1.log`,
`/private/tmp/ecies-half-tangent-arithmetic-2.log`,
`/private/tmp/ecies-half-tangent-native-3.log`,
`/private/tmp/ecies-half-tangent-full-2.log`, and
`/private/tmp/ecies-half-tangent-axioms.log`.
The four full Quad constructors and complete variable-base/agreement assemblies
remain unverified.

**Unperformed and still unauthorized:** tests, proof-system or circuit/witness
execution, actual Go-hint execution, and runtime performance checks.
No local factor-generation script ran. Textual editing scripts and read-only
source/data downloads were used. Authorization covers the stated arithmetic
search and existing VE generators/required compilation only; this report does
not authorize tests or production witness execution. Lean checks are authorized
by the user's later instruction.
