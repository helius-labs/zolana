# P-256 constructive completeness — checked components and remaining assembly

Date: 2026-10-11. The current Go and extracted Lean sources were reread after
`ecies-std-proof-review.md`. The user subsequently authorized the arithmetic
search, existing generators and required compilation, and Lean checking.
Checked components include the full-domain primitive decomposition, selection,
prefix/chord/final-step obligations, half tangents, concrete guard counterexample,
balanced limbs, canonical predicates and initial native arithmetic constructors.
Later sections record exact module results. Full fixed-base multiplication now
passes kernel checking; variable-base and agreement constructors remain open.
Tests and actual Go-hint or
witness execution remain unperformed and unauthorized.

## Precise valid input domain

`Curve/Completeness.lean` defines `ValidSecretInput` and `ValidAgreementInput`.
The secret is exactly 32 big-endian bytes, each native value below 256, whose
integer has **nonzero residue modulo n**. It need not be less than n: the
production hint and modular equations reduce the input. In particular n+1 is
in the domain, while zero and n are excluded as invalid secret keys.

The recipient is exactly 65 byte values, with prefix 4, canonical 32-byte x
and y below p, satisfying the P-256 equation. This is a finite curve point;
there is no infinity encoding in this API. No ladder exception exclusion,
nonzero slope/denominator check, hint-success assumption, or satisfying-witness
assumption is part of the input domain. `parseScalar` only checks bytes; the
nonzero residue requirement is the mathematical valid-secret domain, not a
claim that `AgreeKey` performs an explicit scalar-nonzero check.

## Initial constructive source milestone

The new module is separate from the existing soundness imports. It contains:

* An explicit `RangeComplete` premise for the production range table: bounded
  integer casts have range-table membership for widths at most 11. This is
  completeness, independent of existing lookup soundness/security assumptions.
* Explicit division/remainder witnesses and 11-bit decomposition pieces for
  the **actual extracted** `SplitLowBits_1_8`, `SplitLowBits_1_32`,
  `SplitLowBits_8_32`, and `SplitLowBits_16_32` predicates. Their statements
  preserve arbitrary continuations and do not assume the target predicates.
* A witness constructor for the **actual extracted** `CompressedPacking`
  predicate, using those splits and the production coordinate weights. Its
  output is an explicit native limb formula; canonical whole-coordinate
  interpretation remains the caller's responsibility.
* Constructors assembling the **actual extracted** distinct-x and
  distinct-slope guards. Distinct-x still requires its component canonical
  checks and the nonzero sum of squares; distinct-slope requires the exact
  native product to be nonzero. These are compositional local constructors,
  not universal ladder completeness statements.
* Mathematical affine doubling/addition witness constructors, including the
  division denominators. Doubling derives denominator nonvanishing from
  P-256's absence of two-torsion. Addition exposes the local distinct-x
  obligation. These mathematical statements do not construct the extracted
  emulated-field polynomial witnesses.

At this initial milestone there was no `ScalarMulBase`, `ScalarMulChecked`, or
`AgreeKey` completeness theorem, and this component had not changed Go
constraints or hints. Later sections record the additional source, the reviewed
constraint repair and regeneration, and the completed kernel checks. The current
full multiplication and agreement assembly status is stated at the top.

## Why the native slope obligation cannot be silently discharged

`assertDistinctSlopeConstrained` evaluates
`factor(lambda-half) * factor(lambda+half) != 0` **modulo BN254 Order**, with
`factor(d)=d*(d*d-p*p)`. Existing `distinctSlope_guard` only proves the
soundness direction from this native guard to inequality modulo p.

The new `nativeSlope_alias` statement gives a concrete algebraic obstruction
to reversing that implication: take integer lambda=Order and half=0. Their
P-256 residues differ because 0 < Order < p, but the native guard is zero.
This is **not** a concrete recipient/scalar counterexample. It does not prove
that these slopes arise in an actual ladder or that no alternate bounded
representatives can satisfy the constraints. It does prove that merely
establishing unequal P-256 slopes is inadequate for a completeness proof.
No speculative circuit fix was made.

## Remaining witness obligations

1. Fixed base: assemble the actual scalar-multiplication predicate from the
   constructed recoding bits/check, comb selections, balanced slope witnesses,
   and fifty lazy updates. Intermediate prefix finiteness and final inverse
   exclusion are now mathematical source proofs. Remaining exact slope-check
   bridges/capacities and the final y/output checks must be integrated into
   the actual existential/continuation sequence.
2. Variable base: prove a bounded, nonzero-denominator signed rational
   decomposition exists for every selected scalar. A primitive reduced pair
   is useful for prefix noncollision arguments, but decomposition/hint
   correctness must be proved separately. Derive the six residue-selection
   cases and all slot nonzero/distinct-x facts from the original input domain.
3. Ladder prefixes: build every accumulator, chord slope, second slope, and
   half-tangent root; prove all local division obligations and **native**
   slope factors nonzero, including the last branch without a half slope.
   All eagerly evaluated operations must be satisfied, including selected
   and discarded branches. The inverse-four repair selects R as the eager
   discarded addend when numerator bit zero is 1; the remaining branch and
   primitive decomposition reasoning still need a complete derivation.
4. Arithmetic: instantiate the new integer-witness constructors and static
   capacity proofs for all remaining concrete checks, and add exact reverse
   bridges where only soundness mirrors previously existed. The unified
   addition x check now has its constructed remainder/quotient/carry and
   actual extracted reverse bridge. The generic construction does not itself
   instantiate every production curve operation.
5. Lookup: add explicit production row-lookup completeness for dynamically
   built ladder rows. The production fixed-base comb uses native polynomial
   selectors; both actual selectors now have completeness constructors.
   Range completeness alone does not prove the commitment argument secure.
6. Agreement: assemble byte parsing, curve checks, scalar reduction,
   variable/fixed-base multiplication, canonical coordinates, parity,
   public/shared packing, and all actual `AgreeKey` existential binders.
7. Go hints: independently relate rational reconstruction, elliptic scalar
   multiplication, balancing, polynomial quotient/carry hints and split
   hints to the constructive witnesses. Witness existence alone never
   establishes that production hints return those witnesses.

These are open mathematical/source obligations, not omitted validation steps
that can be resolved by running tests. Existing P-256 parameter assumptions
are owned by the separate parameter work; this module adds no axioms, sorry,
admit, substitute multiplication predicates, or all-operations-succeed premise.

## Further fixed-base and arithmetic construction

All following results remain **unelaborated source candidates**. No tests,
Lean/circuit execution, builds, arithmetic evaluation, factoring or generators
ran. Read-only textual comparison of generated native definitions was used;
it did not execute those definitions.

`CompletenessComb.lean` constructs both actual comb selectors, including the
eight-limb x / packed-y output layout. `recodingCheck_complete` constructs the
actual `CheckPolynomial_25_hcd1dd84c` two-bit shifted quotient and four-bit
shifted carry from the integer scalar identity. `CompletenessBits.lean`
constructs the parity and 256 recoded bits using the existing ProvenZk
`Fin.toBitsLE` inverse, the actual `Gates.from_binary` witnesses, and
`scalarRecoding_complete` starting from an arbitrary reduced scalar element.
The quotient is `1-floor(S/n)`, so noncanonical 32-byte scalars are covered.
It also constructs mathematical canonical coordinates for every nonempty
comb prefix and proves final inverse-point exclusion for every nonzero secret
residue. Its final unified affine-addition witnesses cover doubling as well
as distinct-x addition.

`CompletenessLimbs.lean` constructs a bounded integer/limb representation of
every mathematical P-256 slope. Its representative is
`((slope.val+balanceOffset) mod p)-balanceOffset`, following the production
BalanceHint offset/reduction algorithm. All 24 actual 11/11/10-bit range pieces
and their native limb identities are constructed. This is witness existence;
it does not execute or formally verify the Go hint implementation.

`Field/CompletenessCarry.lean` constructs every grouped carry from exact
integer prefix division. `CarryCapacity` is an input-independent numerical
property of the certificate, needed because existing lifting/soundness checks
alone do not certify sufficient carry width. `CompletenessRange.lean`
constructs all small/wide production range pieces from the explicit small
table completeness premise, including exact piece counts and recomposed
integer limbs. `CompletenessCheck.lean` builds the existing generic
`CheckPolynomial.circuit`, preserving the native equation and top check.
`CompletenessEval.lean` then derives its input-dependent remainder, quotient,
integer residual, native polynomial forms and all integer limbs from bounded
inputs: `R=E mod m`, `K=E/m`. Eval needs only static quotient/carry capacities;
AssertZero additionally needs the mathematical zero congruence, rather than
successful hints or a satisfying-check premise.

`CompletenessLazy.lean` constructs the actual first lazy x-update directly
from its functional gates, before using existing soundness to attach integer
bounds/congruence. Read-only source comparison found all fifty fixed-base
lazy native bodies identical after hash renaming; explicit `rfl` links retain
every actual extracted predicate name. Their different bound certificates
still have to be applied to the correct input elements during full assembly.

The exact reverse bridge in `CompletenessBridgeOutput.lean` preserves the
24 remainder pieces, 36-bit quotient check, 37-bit carry check, and arbitrary
continuation of actual `CheckPolynomial_24_h42186a27`. Closed static quotient
and carry capacity source proofs in `CompletenessUnifiedX.lean`, together
with the generic construction, give `unifiedX_complete` from bounded inputs
and explicit small-table completeness. This is an actual arithmetic-subgadget
constructor; it is not yet full `ScalarMulBase`, `ScalarMulChecked` or
`AgreeKey` completeness.

## Variable-base ladder mathematics added

The new `CompletenessLadderDecomposition.lean` uses the pinned Mathlib
Dirichlet approximation theorem to construct a primitive signed residual
pair for **every integer scalar with nonzero residue modulo n**. The reduced
rational approximation has denominator at most 2^128; its residual numerator
is nonzero, below 2^129 in absolute value, and coprime to that denominator.
The proof uses primality of n and the denominator bound, not hint-success or
an assumed satisfying witness. `ladder_decomposition` converts this into the
actual Boolean sign convention and positive 129-bit numerator/denominator.
The natural-number wrapper covers noncanonical 32-byte inputs directly.

`CompletenessLadderSelection.lean` proves that halving any of the six
exceptional residues exits that set, keeps the selected scalar nonzero,
keeps the doubled recipient finite, and preserves the original product.
Scalar faithfulness on every nonzero P-256 point derives all six initial
collision exclusions and finiteness of all eight slots. The low-bit
correction proof covers the eagerly evaluated discarded sum: when numerator
is odd its addend R is x-distinct from both 3R and 4R; when numerator is even,
primitivity forces denominator odd, so the only addend/target pair is Q/3R,
already separated by the exceptional-residue argument. This includes the
inverse-four repair, rather than reasoning only about selected branches.

`CompletenessLadderPrefixes.lean` gives the actual radix-four mathematical
coefficient recurrence `2*floor(value/divisor)+1`, with the initial and final
low-bit identities. For suffix divisors at least four, the primitive
numerator/denominator determinant is nonzero. Cancellation yields the sharp
bound `|determinant| ≤ numerator + denominator < n`, so modular cancellation
cannot kill these prefix accumulators. The pair (1,1) is excluded by the
already derived R≠−Q condition. This is a mathematical prefix-finiteness
result, not a completeness theorem for the extracted bit-run predicate.

`CompletenessLadderChords.lean` adds the middle-step group noncollisions.
For suffix divisors at least four, both `2A+T` and `2A-T` have nonzero
primitive determinants. The coefficient of `2A-T` needs only a finite
check for numerator/denominator values at most five; larger values are
excluded by strict coefficient bounds. Prefix cancellation bounds the
determinants by at most seven times numerator plus denominator, still below
n. All selected mathematical rows are finite, and next-prefix finiteness
then excludes both collisions in the second chord addition. These are
denominator facts about the middle steps; they do not discharge the
stronger slope guards or the separate final step without a half slope.

`CompletenessLadderLast.lean` separately excludes both doubled-accumulator
collisions in the final step, where the row includes the extra 3R. The
primitive numerator/denominator and shifted coefficient bounds handle the
denominator-one and numerator-one cases explicitly, with determinant bounds
at most ten times their sum. This is a group noncollision statement; it
does not yet assemble the preceding guarded row-plus-3R operation, all final
affine intermediate witnesses, or the extracted final-step predicate.

`CompletenessLadderHalfTangent.lean` constructs the half of every finite
table point with scalar (n+1)/2, proves doubling recovers that point, and
constructs the half-point's ordinary tangent. Substitution of its doubling
coordinates proves the exact production quartic, with coefficient a=-3.
This supplies mathematical half-tangent root existence independently of
hint output. Its limb encoding and polynomial-certificate assembly belong
to the field witness component; root existence does not establish any
native distinct-slope exclusion.

`CompletenessLadderNative.lean` identifies the guard's exact six native
residue exclusions. It does not assert that every mathematical noncollision
produces a native nonzero factor. The bound/representative constructors in
the separate limb component still need to meet those native exclusions.
The separately authorized offline arithmetic search has now found an actual
valid recipient for scalar two whose primitive production hint path fails
the native guard. `CompletenessLadderCounterexample.lean` records the literal
Q/H coordinates and slopes, on-curve and Q=2H arithmetic obligations, exact
balancing formula, and extracted old-guard impossibility. A generic
half-quartic uniqueness theorem and interior balanced-representative bounds
exclude alternative slope/root encodings on that primitive path. Those Lean
obligations remain unelaborated. Neither Go hints nor a circuit was run.
The arithmetic finding does **not** establish universal unsatisfiability:
nonprimitive numerator/denominator witnesses are permitted by the constraints
and can change the selected middle rows.

`CompletenessLadderBits.lean` constructs the full 259-bit witness, proves all
Boolean gates and the numerator/denominator integer chunks, and connects the
actual four-bit row selector to the quotient-prefix row coefficients. It
does not assume a successful row lookup; concrete row lookup completeness
and polynomial witness assembly remain separate.

`CompletenessLadderRepair.lean` proves the proposed native-zero fallback's
mathematical disjunction and group soundness: a zero flag retains the old
native separation implication; a one flag supplies `LastSlope`. The flag
is explicitly the same integer zero/one in both fields. Its existence is
constructed from the native product and inverse whenever the ordinary
chord/curve equations hold. The extra `LastSlope` identity follows from
those equations for distinct-x points, so no native exclusion remains in
the constructive primitive path. Go/extraction integration is owned by
the parent task and requires refreshed bound-specific certificates.

Every new declaration is unelaborated source. Remaining variable-base work
includes final intermediate assembly, realizing the proved middle/final-step
group geometry and half-tangent roots as field/polynomial witnesses,
integrating refreshed repaired predicates, assembling all `ScalarMulChecked`
existentials, and proving production hint correspondence beyond the directly
traced scalar-two reconstruction case. This subagent ran no tests, builds,
Lean, circuit evaluation, generators or arithmetic search. The parent task
separately obtained authorization for the focused arithmetic search and
temporary circuit/certificate generation; those are distinct from Lean
validation or witness/circuit execution.

### Fixed-base actual first step and tail (source candidates)

The opaque small-table completeness contract now applies only to widths
2 through 11. `SmallCheck` constructs width-zero equality and width-one
Boolean witnesses directly. This changes no scalar or point input domain.

`CompletenessCombFirst.lean` constructs the actual first
`CombChainStep_8_8_8_8_8_8_8_h14296507`. It chooses a chord slope from the
two finite noncolliding points, constructs balanced 11/11/10 slope pieces,
supplies the actual `CheckPolynomial_32_hb838cae4` assertion through the
parent's concrete bridge/capacity theorem, and constructs the actual
`Lazy_24_h4ef94fb8` x update. The resulting bounded integer element,
`FirstRel`, and next finite group point are returned before arbitrary
continuation assembly. Its local noncollision premise must be discharged by
the existing comb-prefix mathematics in the eventual full scalar theorem.

`CompletenessCombReduce.lean` constructs the actual final
`CheckPolynomial_8_h78194ae0`: 24 remainder pieces, four quotient pieces
with widths 11/11/11/9, and four carry pieces with widths 11/11/11/10.
Its quotient/carry capacity obligations are closed proof-source declarations.
`CompletenessCombRecover.lean` constructs the actual final
`CheckPolynomial_24_h0845ed76` with the packed 96-bit y-input bounds in its
own certificate. All five native fragments are textually identical to the
unified-y check after replacing their hash names; the proof uses their
definitional equality and the existing exact unified-y reverse bridge.
This read-only text comparison did not execute Lean or circuit arithmetic.

`completeAdd_with_point_complete` in `CompletenessAdd.lean` now attaches
canonical integer coordinates below p and the finite curve/group-sum fact
to its actual `CompleteAdd_8_8_8_8_h3f5cf0cd` witness. It derives the output
cast identities from the explicitly selected remainders and
`foldedValue_congr`, without lookup soundness. The older existence interface
remains as a wrapper. `CompletenessCombTail.lean` assembles the actual final
x reduction, implicit-y recovery, and complete addition into one nested
continuation witness with canonical outputs and the resulting group point.
Its local implicit-accumulator curve fact and noninverse premise remain to
be discharged from the comb-prefix/final identities and valid secret scalar.

No validated complete extracted `ScalarMulBase` theorem is claimed. At this
stage the other 48 bound-specific chain steps and full continuation assembly
were still open; the later source-candidate status below supersedes that
implementation status without changing its validation status.
The generic primitive constructors, first step, and tail have no target
gadget-satisfiability premise. All new proof terms and numeric capacity
declarations remain unelaborated. This component ran no tests, builds, Lean,
circuit/witness evaluation, generators, or arithmetic search.

`CompletenessCombSecond.lean` now also constructs actual second chain
`CombChainStep_8_8_8_8_8_8_8_hd0a2e1d5`, including its own bounded
`Lazy_24_h33616364` witness and its six-input
`CheckPolynomial_48_hd6f972c2` assertion. Its chord slope uses the previous
implicit accumulator y-coordinate, and its `ChainRel` and finite group
sum are derived from those mathematical witnesses. Consequently 48 further
bound-specific chain constructors remain, rather than 49.

`CompletenessCombWindows.lean` constructs actual window and top selectors
before attaching their bounded table coordinates and group-point identities;
its top literal table coordinates are canonical below p.
`CompletenessCombSelection.lean` ties these witness constructors to the
chosen 257-bit recoding vector, proves each window's group scalar is the
actual `digOf` signed digit, and proves the top group's exact bit/parity
formula. `fromBinary_chunk_complete` constructs the actual from-binary
predicate for every bounded run of these bits, including Boolean gates.
The later full-assembly source candidate is described below.

`CompletenessCombMath.lean` supplies uniform chosen-slope mathematics for
the remaining literal chain constructors: the balanced slope's integer
assertion and a next finite group point for each independently constructed
lazy-x congruence. `combChain_slope_expr` converts the assertion into the
actual four-term certificate expression under literal term/modulus equalities.
It assumes neither an actual chain witness nor successful hint evaluation.

### Full fixed-base assembly candidate

`CompletenessScalarMulBase.lean` now contains handwritten
`scalarMulBase_complete` source targeting the actual
`ScalarMulBase_8_h3037b025` predicate. Its domain is every `ElemVal 8` with
`bnd = reducedC` and `value.toNat % n ≠ 0`. In particular it accepts the
noncanonical representatives above n permitted by the 32-byte production
API. The scalar width/nonnegativity follows from the element bounds; no
all-operations-success, selected-branch, denominator, or gadget-existence
premise is added to that domain.

The candidate constructs all 51 native window selectors and the top
selector from `combBits`; constructs 50 chain states, deriving every local
collision exclusion from `comb_acc_step`; constructs final reduction,
implicit-y recovery, and complete addition; and returns canonical output
integers below p with a finite group point equal to `S.value • G`.
The final complete-add noninverse condition follows from the original
nonzero scalar residue via `combFinal_noninverse`. The native continuation
source explicitly chooses all 257 bits and eight actual from-binary chunks,
supplies the actual recoding arithmetic check, and applies every selected
window, chain, and tail continuation in the production order. It does not
use lookup soundness to identify chosen coordinates.

The 49 ordinary later-step constructors are supplied by the parent's
authorized extension to the existing instance proof-source generator,
using the literal per-hash arithmetic capacities, bounded native lazy
witnesses, and exact emitted balance/primitive composition. At the time
this handwritten source was added, the new generated wrapper modules were
pending the parent's independent source review and generation/integration.
The full candidate's generated dependency and all new Lean terms therefore
still require integration and elaboration before completeness can be
claimed. No Lean, tests, circuit/hint execution, generator, or mathematical
evaluation was run by this component. Production Go hint correspondence
remains separate from mathematical witness existence.

### Variable-base arithmetic assembly inventory and new constructors

The central ordinary quad `QuadrupleAndAddLazy_8_8_8_8_haf2b5bed` uses
actual tangent assertion32 `h6485b116`, lazy double-x16 `h53928760`, lazy
double-y24 `h31bd1a61`, chord assertion32 `hdaa6ee4a`, repaired flag
assertion49 `ha68a8775`, lazy intermediate-x24 `hdbbbc800`, second-slope
assertion40 `h4960297a`, lazy output-x24 `h9c68f146`, and lazy output-y40
`hee995b41`. The three other bound-specific quad variants have the same
geometric sequence; the final variant uses an unconditional LastSlope
assertion48 `hae80c491`. Folded reverse bridges, literal capacities, and
native lazy constructors for these arities are being supplied by the
parent's authorized existing-generator extension. The native composition
must retain all three balanced 24-piece slope hints and the actual native
zero-indicator/fallback assertion.

Three `ScalarMulChecked` checks use the general nonfolded path rather than
the current folded constructor: scalar reduction8 `h57d6a69c`, scalar
half-product16 `h93312e5c`, and rational relation18 `hb0ad1306`. Another
independent component owns their integer quotient/remainder/carry witnesses.
The half-product has two carry groups; their witnesses cannot be collapsed
to the single-group folded pattern. The remaining table triple/add/half-root
and curve-coordinate primitives use folded assertions/evaluations or native
functional lazy updates. The six exceptional-scalar comparisons are sums
of eight squared 32-bit limb differences, so the existing integer
sum-of-squares bounds rule out native aliasing there.

`CompletenessQuadMath.lean` constructs all three slopes and all eight
`QuadAddCons` equations for finite A/T when the first chord and resulting
4A+T are nonexceptional. It also constructs LastSlope and the finite group
output. Its second denominator is derived from T being finite/nonzero and
4A+T being nonzero. `CompletenessQuadFinal.lean` derives that final-step
output-finiteness condition from the primitive numerator/denominator and
true decomposition relation: the low-bit coefficients have a nonzero
determinant bounded by `den + 4*num < n`. In the num-even case gcd forces
den odd and excludes `den = 3*num`; no secret-domain restriction is added.

`CompletenessHalfTangent.lean` constructs the actual
`HalfTangentSlope_8_8_h2c0228bb` predicate for every finite reduced point:
the mathematical half point supplies a quartic root, balanced pieces encode
it, actual lazy8 `h158c056f` supplies its square, and actual assertion40
`h0930c075` checks the quartic before an arbitrary continuation. The root
and native square are constructed, not assumed. Its generated primitive
dependencies were still pending integration when this source was added.

The ordinary/final actual quad pipelines, table triple/add assembly, all
64 ladder steps and final low-bit equality, and complete
`ScalarMulChecked`/production agreement assembly remain in progress. All
new source remains unelaborated; this component performed no executable
mathematical, Lean, circuit, hint, test, or generator validation.

The middle-quad soundness source now follows the regenerated native-zero
fallback. `QuadStep.lean` interprets each of the three actual flagged
49-limb polynomial certificates, using the same Boolean obtained from the
native `IsZero` gate as the bounded one-limb field flag. Its internal result
is `QuadAddCons` together with either the nonzero native product or
`LastSlope`; the previous unconditional nonzero conclusion would be false
for the repaired alias branch and has been removed. `LadderTable.lean`
uses the original distinct-slope argument in the first case and the
existing field-only chord argument in the second. All three public
`ladder_step_*` statements and the final nil-half-slope quad interface are
unchanged. Shared `bitElem` definitions moved unchanged from `CompleteAdd`
to `BitElem`, with an additional direct `IsZero` semantics lemma.

This adaptation has been reviewed against the generated constraint and
certificate source and passes a textual diff whitespace check. Its Lean
proof terms remain unelaborated: no Lean, tests, witness evaluation, or
generator was run by this component. The parent separately performed the
user-authorized Go compilation and existing extraction/certificate
generators. No complete variable-base extracted witness construction is
claimed by this soundness adaptation.

The existing `emcurve_instances.go` renderer has a source extension for
actual folded `AssertZero` checks with `checkTop = false` and their literal
input and carry layouts. The new `CompletenessGeneratedChain` output contains
model-to-actual bridges, literal quotient inequalities, literal carry
capacities, and constructors from bounded elements, the intended expression
congruence, and completeness of the small range tables. It follows the
actual extracted primitive conjunct sequence and emits source using the
existing expression reflection proofs. `CompletenessVector.lean` preserves
every range piece as a pointwise `SmallCheck`, including a final one-bit
Boolean, and permits arbitrary extracted vector lengths.

The parent's first authorized run failed closed on the final-quad
`CheckPolynomial_48_hae80c491`, whose range vector has eleven pieces. That
run produced no integrated new output. The source renderer was then
generalized to every actual folded `AssertZero` with no result, eight
32-bit result-width metadata entries, and `checkTop = false`, using its
literal input layout instead of assuming six eight-limb elements. It now
handles direct small/Boolean range checks, arbitrary hint-vector lengths,
and each group of a multiple-group carry chain. The actual folded
`cert_ha71ae55f` has groups `[0,3,130]` and `[3,5,131]`; the repaired
`cert_h8696e642` has one group `[0,4,108]`. Every selected primitive still
passes the actual conjunct parser, and every arithmetic-wire comparison
remains an ordinary kernel proof obligation.

The same renderer has `CompletenessGeneratedLazy` output for functional
actual Lazy witnesses at their literal input arities, including 16, 24,
and 40, and monotonicity. Its constructor attaches the
existing certified integer bounds and value congruence to the concrete
native output; no lookup soundness or successful-Lazy premise is needed.
`CompletenessGeneratedChainComposition` separately assembles the explicit
24-piece balanced hints, their actual range checks, a slope assertion, and
a lazy continuation into each nonfirst actual `CombChainStep`. Those are
composition lemmas, not completeness theorems: the outer mathematical
construction must discharge the two primitive premises using the preceding
constructors. The first step retains its hand-written bridge.

`CompletenessGeneratedCombSteps` adds a separate complete individual-step
wrapper per nonfirst actual chain hash. It uses the independently written
`CompletenessCombMath` slope construction from finite noncolliding points,
discharges each literal slope certificate and lazy update through the
generated constructors, and then applies the composition bridge. Its
premises are small-table completeness, the actual static input bounds, and
the curve/noncollision facts. Its result contains bounded output limbs,
the integer chain relation, the mathematical group sum, and the actual
continuation-preserving step. Static bounds use certificate input records;
the complete scalar construction must derive these from previous outputs
and prove each step's noncollision. This is an individual-step constructor,
not yet a complete `ScalarMulBase` assembly.

At the time of this source edit the new renderer had not been run by this
component. No Go compilation, Lean, tests, generators, or arithmetic/witness
evaluation was performed here. Generated proof candidates, including their
closed numeric obligations, remain unelaborated until separately checked;
the renderer preserves the existing soundness output code.

The renderer also has a separate `CompletenessGeneratedQuadComposition`
output for the three middle and one final actual quad variants. It traverses
the actual continuation fragments and checks the presence of all six
24-limb hint vectors, all 72 range checks, four assertion primitives, and
five lazy continuations. A middle variant additionally requires the actual
native `IsZero` and flagged field assertion; the final variant uses its
unflagged field assertion. Fixed input helpers name each actual primitive
layout and the literal P-256 coefficient limbs. The composition proof
supplies all hints and ranges and substitutes the native gate arithmetic
before applying the supplied continuation constructors. These are pure
composition lemmas; the mathematical pipeline must independently construct
every assertion and lazy premise. No whole-ladder completeness claim follows
from these bridges alone. The generated proof headers mirror the existing
instance modules' local heartbeat and recursion-depth options; no tactic,
Lake, CI, or build configuration was changed.

### Whole-value nonfolded arithmetic

`Field/CompletenessWholeEval.lean` now constructs the generic nonfolded
`CheckPolynomial.circuit` witness for an arbitrary positive emulated modulus,
including the scalar modulus. It sets the exact integer expression to `E`,
the remainder to `E % m`, and the quotient to `E / m`. The shifted quotient
is decomposed into radix-32 limbs with the recorded quotient widths, then
the recorded offset limbs are subtracted. The proof recomposes those signed
limbs to the quotient, derives every native residual equation, proves the
integer weighted residual is zero, and invokes the existing piece/carry/top
constructor. The Eval and AssertZero wrappers preserve their continuations;
AssertZero takes the mathematical modular identity being asserted.

Quotient capacity uses asymmetric bounds from each input record's `vlo/vhi`:
`Emin / m + offset >= 0` and `Emax / m + offset < 2^quotientBits`.
These are static certificate obligations, together with a full-limb/final-limb
radix-32 layout, an eight-limb remainder layout, `m < 2^256`, and the carry
capacity. In particular offset-zero scalar canonicalization does not need a
symmetric absolute-value bound or canonical scalar inputs. This generic
construction introduces no restriction on the existing supported domain or
on valid 32-byte noncanonical scalar encodings.

`Field/CompletenessScalarChecks.lean` discharges the literal static floor
bounds, quotient layouts and carry capacities for scalar reduction
`h57d6a69c`, the half-scalar product `h93312e5c`, and the signed decomposition
check `hb0ad1306`. It constructs their generic model predicates from bounded
elements and, for decomposition, the mathematical zero congruence. The scalar
input record covers the full interval from zero through `2^256-1`, including
noncanonical encodings greater than or equal to the scalar modulus.

After the user authorized Lean, both `CompletenessWholeEval` and
`CompletenessScalarChecks` passed the pinned Lean kernel build. Concrete
closed integer capacities and inverse identities use ordinary kernel-checked
proofs. The generic model witnesses still need model-to-extracted primitive
bridges with the correct hint/vector layout; later ladder composition must
derive input bounds and mathematical identities. No successful operation,
hint, or circuit is assumed by these constructors. This component ran the
authorized Lean checks; no tests, witness evaluation, extraction, or
generators were run.

`Field/CompletenessWholePieces.lean` also passed the kernel check. It supplies
the exact one-piece and thirteen-piece quotient hint vectors and preserves
each range constraint; the twenty-four-piece quotient uses the existing
remainder-vector helper. A separate source renderer,
`prover/extractor/emcurve_complete_whole.go`, now describes reverse bridges
for the three nonfolded scalar checks. It matches the combined 25/48/13-piece
initial hint, the native whole equation, every carry hint/range/equality,
and the exact output continuation or AssertZero endpoint. It uses the
checked scalar model constructors and rejects unsupported source order or
shape. This renderer has been formatted and source reviewed by its author;
Go compilation, generation and Lean checking of its emitted bridges await
the parent's independent review/run. No actual extracted scalar bridge is
claimed complete by the renderer's source alone.

### Authorized Lean validation and remaining native assembly

After the user authorized Lean checking, this component built the current
`Field.AllInstances` aggregate successfully (6036/6036 Lake targets), then
`Field.CompletenessEval` and `Field.CompletenessRemainder`. The latter required
explicit vector-getter and Fin numeral normalization in its output-list proof;
the final builds passed. These results validate the generic integer-limb and
24-piece decomposition constructors and the existing generated forward
instances; they do not validate newly generated reverse constructors.

`Curve.CompletenessQuadMath` and `Curve.CompletenessQuadFinal` now pass the
pinned Lean kernel build. The former constructs the tangent, first chord and
second slope from finite input points, the actual prefix noncollision facts,
and output finiteness. Its Nat/Int scalar bridge is explicit. The latter proves
the final low-bit determinant nonzero and small enough to derive output
finiteness from the primitive rational decomposition. Neither assumes success
of a native operation or narrows the supported scalar/point domain.

Actual native arithmetic candidates now cover all four quad variants:
`CompletenessQuad` for `haf2b5bed`, `CompletenessQuadFirst` for `h577e35e6`,
`CompletenessQuadTransition` for `h6e46ac5c`, and `CompletenessQuadLast` for
`h4bfcc75d`. Each constructs its own exact extracted primitive certificates,
Lazy outputs, balanced hints and continuation witnesses. First inputs are
reduced; the first output-Y bound is `h57fc266d`; transition accepts that bound
and returns the ordinary `hee995b41` bound. Final selected-Y is reduced,
output-Y uses `hc2c2cd77`, and its unflagged 48-input LastSlope check is
constructed directly from the first chord. These four native pipelines remain
unelaborated pending their generated reverse prerequisites. The fixed-base
whole constructor also remains unvalidated. Triple/AddStep/table/scalar-check
composition, whole variable-base assembly and final key-agreement assembly
still require work; the full production completeness objective is open.

The ordinary proof-source renderer now includes reviewed sequential Lazy
witness/continuation construction and folded reduced-output KindEval bridges,
with 1000-source-gate module chunks to keep validation manageable. Its strict
matcher rejects unmatched native constraints and never assumes the desired
predicate. Parent review authorized the extension; the parent runs extraction
and compilation. This component performed source edits and authorized Lean
checks only, with no tests, Go hint execution, circuit execution or generator
execution.

`Curve.CompletenessTripleMath` also passed the pinned kernel build. It constructs
both mathematical slopes and all coordinates of `3P` for every finite on-curve
input. The return-slope denominator is derived from the proven curve order:
`2P = P` or `2P = -P` would identify the distinct scalar-field residues 2 and
1 or -1. Native Triple constructors remain to be assembled from the exact
primitive arithmetic and pure native continuation bridges.

The original `Curve.Completeness` module now passes Lean after explicit cast
transport, vector-getter simplification for the split witnesses, and proving
the compressed packing equality as a whole vector instead of splitting
associative sums at an incorrect congruence depth. The unchanged public
`twoPowLimbs` definition moved from `ScalarMulBase` to handwritten `CombConstants` so the
constructive bits/slopes do not require elaborating the entire older fixed-base
soundness proof first; that soundness theorem still requires its own check.

An isolated first actual Lazy witness (`Lazy_16_h30893ad5_witness`) passed the
kernel with default linters. Profiling separated proof checking (about half a
second) from metavariable instantiation (19.5 seconds) and lint traversal
(44.3 seconds). Whole Lazy witness/mono/complete validation was stopped without
a theorem diagnostic; no aggregate pass is claimed. A parent-authorized retry
omitted only the optional constructor-name style linter through a command-line
option and was also stopped without a full pass. The ordinary renderer now
constructs witness and monotonicity proofs per existing native fragment and
composes them, validating every fragment's exact extracted header and
continuation arguments. This preserves the public main APIs and requires
independent parent review, regeneration and kernel checking.

`Curve.CompletenessLimbs` now passes Lean. Its dependency graph directly imports
`Completeness` and `CombWindows`, because balanced slopes use coordinate limb
helpers and native bounds, rather than fixed-base recoding. Its checked proofs
construct balanced integer limbs, their P-256 casts, and all actual 24 range
pieces for every `Fp` slope; unfolding and cast transport are explicit.

The owned variable-base mathematical modules `CompletenessLadderDecomposition`,
`Selection`, `Prefixes`, `Chords`, `Last`, `HalfTangent`, `Bits`, `Native` and
`Repair` now pass pinned Lean 4.16.0-rc2 builds. These cover universal primitive
signed decomposition, exceptional-scalar selection and eager-correction
guards, middle/final noncollisions, half-tangent existence and uniqueness,
actual 259-bit wiring, and fallback soundness. The existing `Assumptions`,
`P256`, `GroupLaw`, `Guards`, `Ladder`, `Native`, `AddStep`, revised `QuadStep`,
`TripleStep`, `Select`, `Bits`, `LadderAux` and revised `LadderTable` also pass.
The three repaired quad soundness proofs therefore checked against the actual
regenerated flag constraints and preserve the public ladder group results.

The fixes use explicit multiplication/cast orientations and the additive
group's integer-action lemmas. A generic affine-point constructor avoids
eagerly evaluating the huge concrete half scalar, and a generic finite
word-to-row identity avoids case splitting on captured let definitions.
No new input-domain premise or successful-operation assumption was added.
Logs are `/private/tmp/ecies-ladder-math-lean-2.log` through `-6.log`,
`/private/tmp/ecies-ladder-prerequisites-lean-1.log`, and
`/private/tmp/ecies-ladder-bits-lean-2.log`.

`CompletenessLadderCounterexample` now also passes the kernel build, recorded
in `/private/tmp/ecies-ladder-counterexample-lean-3.log`. This verifies the
literal valid recipient, `Q=2H`, tangent and half-tangent equations, stored
slot sign, exact balanced representatives, their native-order alias, and
failure of the actual standalone extracted guard. Quartic-root uniqueness
and interior balance uniqueness rule out alternative slopes or roots on
this primitive path. The scalar-two lattice-loop inequality also passes.
This still does not assert unsatisfiability of every nonprimitive
decomposition or report a Go hint/circuit/witness execution. Whole-ladder
witness assembly remains separate ongoing work.

An axiom audit of the primitive/signed decomposition, finite prefixes,
middle/final noncollisions, half-tangent existence/uniqueness, concrete
counterexample and repaired public `ladder_step_haf2b5bed` passes: each uses
only `propext`, `Classical.choice` and `Quot.sound`. The audit source and
output are `/private/tmp/ecies-ladder-axioms.lean` and `.log`.

The separate ordinary renderer `emcurve_native_compositions.go` now has
source for two Triple and all seven Add native composition bridges. Its
strict parser preserves every hint, range and primitive call and follows
the actual fragment boundaries. The proof source opens only the current
fragment, composes its explicit continuations and then opens the tail;
it does not unfold an entire wrapper or use broad `convert` unification.
The ratio layout includes the actual doubled-y input. These remain pure
composition lemmas pending parent review, generation and kernel checking;
the outer mathematical pipeline must construct all their premises.

`CompletenessTriple` and `CompletenessTripleSelected` now contain full actual
Triple constructor candidates for `h2c0228bb` and `hffcb8921`, including both
balanced hint vectors, tangent and return-ratio checks, the genuine `2Y`
native layout, Lazy doubled-X, both reduced-output Eval checks, and native
continuation composition. The selected-Y variant uses the actual `selC`
record. `CompletenessReducedOutput` identifies those explicitly constructed
canonical outputs from the integer remainder and certificate congruence,
without using lookup soundness. These source candidates depend on the
reviewed generated Eval and Triple composition APIs; they remain unelaborated
and are not evidence of full native Triple or ladder completeness until their
kernel checks pass.

The exact generated Triple/Add composition proof text, with its unchanged
Quad input-helper definitions copied into a temporary standalone source,
now passes Lean 4.16.0-rc2 (`/private/tmp/ecies-triple-add-isolated-lean-5.log`,
exit 0). The subsequent axiom audit also passes
(`/private/tmp/ecies-triple-add-isolated-axioms.log`): all nine composition
theorems use only `propext`, `Classical.choice`, and `Quot.sound`.
This checks both Triple hashes and all seven Add hashes against
the actual extracted definitions. The renderer fixes normalize literal limb
indices, use the normalized signed offset, and open the Add continuation
before invoking its Lazy callback. The regenerated integrated Triple/Add
module subsequently passed the kernel check as well
(`/private/tmp/ecies-triple-add-composition-lean-2.log`, exit 0). These
composition results do not yet check the outer mathematical constructors or
whole ladder.

The original generated Quad composition check failed at each initial
whole-body simplification (`/private/tmp/ecies-quad-composition-lean-1.log`):
the simplifier exceeded its step limit. The revised renderer records the
actual cumulative range-check counts at each continuation boundary and
opens each native fragment separately. After independent parent review and
authorized regeneration, the integrated Quad module passes Lean
(`/private/tmp/ecies-quad-composition-lean-2.log`, exit 0). The final Quad has
range cuts `[39,72,72]`; its last fragment has no range checks, but its actual
check and output continuations are still proved explicitly. The integrated
axiom audit (`/private/tmp/ecies-native-compositions-axioms.log`) passes for
all thirteen Quad/Triple/Add bridges, with only `propext`, `Classical.choice`,
and `Quot.sound`.

The initial `CompletenessLadderInputs` module also passes Lean
(`/private/tmp/ecies-ladder-inputs-lean-2.log`). It constructs canonical
bounded affine coordinates for every nonzero group point and nonzero scalar
product, constructs the scalar witness as `original % n`, and proves the
native squared-limb equality test exact on these canonical values. This
does not restrict the original scalar to be less than `n`. The additional
`originalScalar_product` theorem checks that `(original % n) • Q = original • Q`
using the derived all-point order theorem.

`CompletenessLadderGap` passes Lean in full
(`/private/tmp/ecies-ladder-gap-lean-4.log`). Its explicit 25-entry hint
encodes `n-1-(original % n)` with all 24 actual 11/11/10-bit ranges, a
constructed Boolean carry, exact unsigned limb recomposition, and the two
native 128-bit equalities against the actual `K_1233`, `K_1234`, and `K_392`.
`CompletenessLadderExceptional` also passes in full
(`/private/tmp/ecies-ladder-exceptional-lean-7.log`). It pins all six literal
native detector vectors to `±1`, `±3`, and `±1/3`, proves each squared-sum
zero flag exact, proves their sum is the Boolean exceptional selector, pins
the actual scalar-halving constant, and proves the actual per-limb select
relations and selected product identity for arbitrary original scalar words.
The parent independently reviewed these mathematical components. Their final
axiom audit (`/private/tmp/ecies-ladder-inputs-axioms-2.log`) also passes, with
only `propext`, `Classical.choice`, and `Quot.sound` for all audited input,
gap, exception, selection, and product theorems.

The ordinary scalar-prefix renderer now emits a pure composition candidate
for the actual ScalarMulChecked main/p1 fragments. It supplies the constructed
gap and six flags, and takes explicit scalar reduction, scalar halving,
tangent, doubled-X, and doubled-Y primitive constructors plus the exact
remaining p2 continuation. The outer ladder assembly must construct that
continuation; this composition candidate is not a completeness theorem by
itself. Parent source review, authorized generation, and kernel checking of
this new native prefix have completed. The first kernel attempt exposed
overbroad normalization of zero-test predicates; the renderer was corrected
to use closed literal getter facts and controlled simplification. The
regenerated actual main/p1 composition now passes Lean
(`/private/tmp/ecies-scalar-prefix-lean-2.log`) and its axiom audit
(`/private/tmp/ecies-scalar-prefix-axioms.log`), with only the standard three
axioms. Its exact remaining p2 continuation must still be constructed by the
outer assembly.

`CompletenessLadderBinary` also passes Lean
(`/private/tmp/ecies-ladder-binary-lean-2.log`). It constructs actual binary
slices, reconstructs shifted numerator/denominator words, and proves the
actual native denominator-bit sum nonzero from `0 < den < 2^129`, using the
integer sum bound `129 < Order`. The parent independently reviewed this
component. Ordinary per-fragment p2--p9 native composition source is now in
review; those composition candidates do not establish whole-ladder witness
existence until the mathematical assembly constructs every primitive and
final continuation.

`Curve.CompletenessCanonical` now passes Lean, including the actual canonical
P assertion, squared-limb sum separation, and constructed same-X/inverse
witnesses. The native zero indicator is proved against `GatesDef.is_zero`
explicitly, in addition to the separate formal `Gates.is_zero` specification;
those APIs simplify differently and are not interchanged.

The first fragment-based generated Lazy chunk now passes Lean in full,
including all native fragment witnesses, their continuation monotonicity, and
`Lazy_16_h30893ad5_complete`. Its explicit `Curve.Elem` dependency provides the
existing `ElemVal.bnd` projection; this adds no mathematical assumption. The
passing check retained default linters and normal kernel checking. Metavariable
instantiation took 30.2 seconds, linting 12 seconds, and kernel checking 1.39
seconds. Other Lazy chunks and the generated Eval family remain to be checked.


The nonfolded whole-value renderer has been independently reviewed and
regenerated by the parent. All three actual extracted bridges now pass Lean:
`CompletenessGeneratedWhole_57d6a69c`, `_93312e5c`, and `_b0ad1306`, together
with their aggregate import. They construct the scalar reduction, half-scalar
product, and signed-decomposition native gate witnesses from the checked model
constructors. The canonical continuation is proved for both Eval gadgets.
The source and renderer erase only the folded quotient argument ignored by
nonfolded residuals, using the checked `whole_residual_nonfold` lemma; no
constraint or mathematical premise changes. All 32-byte scalar representations
remain supported, including values at least `n`.

`Lookup.RowCompleteness` also passes Lean, including an honest singleton
source program and actual `RowLookup_12_16` call under an explicit trusted
backend compatibility/construction certificate. Its construction failure
budget retains `εbackend` in addition to the query-pole term; this does not
provide an unconditional primitive `RowComplete` instance. All six endpoints
(the three actual scalar bridges, row program construction, actual conditional
row call, and combined row construction failure bound) pass an axiom audit
with only `propext`, `Classical.choice`, and `Quot.sound`. No tests, witnesses,
or circuit execution were run by this component.

The first generated folded reduced-output Eval chunk now passes Lean in full:
`CheckPolynomial_16_h0c8d6bae_of_model`, literal quotient/carry capacities and
`CheckPolynomial_16_h0c8d6bae_complete`. Two concrete frontend issues were
corrected: expose `env` before the dependent remainder-vector match, and
transport quotient/residual/carry evaluation through existing evaluation
lemmas before converting the natural literal power. The actual native body and
its assertions remain unchanged. The passing run retained default linters and
kernel checking. All nine folded Eval chunks (ten actual primitives) and their
aggregate now pass. All twenty public `_of_model`/`_complete` endpoints also
pass an axiom audit containing only `propext`, `Classical.choice`, and
`Quot.sound`. The logs are `/private/tmp/ecies-eval-chunk-N.log` (chunks 2–9),
`/private/tmp/ecies-eval-1-explicit-full.log`, and
`/private/tmp/ecies-eval-axioms.log`.

`Field.CompletenessUnsignedPieces` passes Lean. It constructs actual unsigned
11/11/10 pieces for each of eight coordinate limbs, plus an exact 48-piece
joint x/y ordering and all sixteen triples of native range assertions.
`Curve.CompletenessChordAdd` and its six hash variants now contain actual
constructor candidates for all seven extracted Add gadgets, using canonical
chord coordinates, the actual Lazy squared-difference primitive and both
cross-multiplied polynomial checks. Their local distinct-x facts are obligations
of the proven slot/prefix geometry; they add no restriction to the production
input domain. These outer Add constructors remain unelaborated pending their
generated dependencies. Full variable-base and agreement assembly remain open.

The actual `RowLookup_12_16` primitive is opaque. `CompletenessLadderLookup`
states the explicit `RowComplete` contract separately from `RangeComplete`:
a valid finite row index and a continuation at the selected row imply the
actual opaque call. This is a stated lookup completeness premise, not a
construction of all curve operations or an unconditional backend theorem.
The independent concrete row-provider component keeps its good-challenge,
query-pole/account bounds and source-program/backend realization boundary
explicit. Full public variable-base completeness must retain both lookup
contracts unless that implementation boundary is separately established.

`Curve.CompletenessLadderRows` passes Lean. `signedLadderRow` constructs the
actual twelve-column layout from eight reduced x limbs, three signed packed y
groups and the original balanced native half-slope value. Its unpack theorem
constructs an `unpackC` element with the exact callback limbs and signed group
point. `constructedLadderRows_ok` derives the mirrored sixteen-row table from
eight slot-point identities and quartic roots. The three row endpoints pass
the standard-axiom audit. These are row-data constructions; the surrounding
native scalar fragments and complete ladder continuation remain separate
open assembly work. `slotChordPairs` derives all four chord-pair separation
facts for the eager slot additions from the selected scalar's proven
nonexceptionality, without imposing an extra input-domain condition.

The shared pure coordinate helpers now live in `CompletenessCoordinates`,
retaining their public names and types. That module and
`CompletenessReducedOutput` pass Lean. The latter identifies canonical output
coordinates directly from the constructive folded remainder and its proved
congruence, independently of lookup soundness. `winX_native` needed a proof
repair: constrained simplification keeps division over natural numbers and
normalizes only the finite indices and literal powers. The Add/Quad callers
inherit these helpers by imports; their actual gadget constructors still need
their own kernel checks.

The complete actual `Add_8_8_8_8_h3f5cf0cd` outer constructor now passes
Lean (`/private/tmp/ecies-chord-add-base-6.log`). It constructs both canonical
output coordinates, all 48 unsigned pieces, the actual Lazy primitive and
both polynomial assertions, and returns the actual native continuation with
the group-sum identity. Finite-index conversion at the composition boundary
uses the explicit `Nat.zero_add` identity, rather than relying on definitional
equality of `0 + 3*i` and `3*i`. All six other Add bound/hash variants now also
pass Lean, including the wide unpacked-y variant with two carry groups.
All seven constructor endpoints pass an axiom audit using only `propext`,
`Classical.choice`, and `Quot.sound` (`/private/tmp/ecies-chord-add-axioms.log`).
Full scalar and agreement composition remains open.

Serial parent review completed the full ordinary Triple constructor on
2026-10-12. `CompletenessTripleX`, `CompletenessTripleY`,
`CompletenessTripleArithmetic`, and `CompletenessTriple` pass Lean. The full
`triple_h2c0228bb_complete` theorem constructs canonical reduced outputs,
proves their group identity `3 • P`, and constructs the actual extracted
`Triple_8_8_h2c0228bb` continuation for every finite reduced input point.
`RangeComplete` remains explicit; there is no assumed successful arithmetic
primitive, additional point exclusion, or narrowed production input domain.
The checked geometric triple theorem discharges both denominators. The
arithmetic constructors supply both balanced slope vectors and their range
pieces, the Lazy doubled x coordinate, and both actual folded Eval outputs.

The parent factored integer expressions and vector layouts with abstract
elements before substituting constructed slopes. This avoids long checker
expansion while preserving all literal certificate bounds and native wiring.
The original quiet/interrupted runs and intentional diagnostic cut markers
remain unvalidated runs; the later full source checks establish the result.
Logs: `/private/tmp/ecies-triple-x-factored-9.log`,
`/private/tmp/ecies-triple-y-factored-1.log`,
`/private/tmp/ecies-triple-arithmetic-factored-7.log`, and
`/private/tmp/ecies-triple-factored-2.log`.
All six arithmetic/full endpoints have axiom audits containing only
`propext`, `Classical.choice`, and `Quot.sound`
(`/private/tmp/ecies-triple-factored-axioms.log`).

The full Quad constructors and complete fixed-base/variable-base/agreement
assemblies remain open. The selected-y variant has subsequently passed the
full kernel check and audit recorded below. This establishes mathematical
witness existence for both actual Triple components; correspondence
with the actual Go hints remains unproved. Checking is serial. No Go hints,
witnesses, tests or solvers were executed.

### Selected-y Triple: full kernel validation

`CompletenessTripleSelectedArithmetic`, `CompletenessTripleSelectedY`, and
the full `triple_hffcb8921_complete` endpoint now pass kernel checking. The
source preserves the actual `selC` y-input domain, tangent check `h8cfcaa46`,
return-slope check `h6a3ed603`, and y-output Eval `h70dd0288`. It reuses the
checked DoubleX and TripleX constructors and generic abstract-element layouts.
Certificate expression equality is checked definitionally; the selected
certificate's own bounds and native predicate are retained.

The full endpoint retains only `RangeComplete`, reduced x bounds, signed y
bounds and the finite on-curve input condition. It constructs balanced slopes,
all actual primitive witnesses and canonical reduced outputs, proves the group
result is `3P`, and supplies the exact extracted continuation. There is no
successful-operation premise in this outer theorem. All five selected
arithmetic/full endpoints have axiom audits containing only `propext`,
`Classical.choice`, and `Quot.sound`.

Logs: `/private/tmp/ecies-triple-selected-arithmetic-2.log`,
`/private/tmp/ecies-triple-selected-y-1.log`,
`/private/tmp/ecies-triple-selected-full-1.log`, and
`/private/tmp/ecies-triple-selected-axioms.log`. Checks used one Lean process
with `-j1`, the requested heartbeat/recursion limits and default linters. No
tests, Go hints, witnesses, solvers or generators were executed. All owned
Lean processes are stopped for parent review. Full Quad and fixed-base,
variable-base and agreement assemblies remain open.

Parent review confirmed the selected certificate bounds, explicit premises,
actual predicate names, and constructed primitive continuations. After removing
one redundant layout wrapper and import, the selected-y helper and full
endpoint passed parent checks again:
`/private/tmp/ecies-triple-selected-y-parent.log` and
`/private/tmp/ecies-triple-selected-full-parent.log`.

### First fixed-base chain: full kernel validation

The current 49-step composition module initially failed its balanced-limb
rewrites. Explicit `change` statements convert each instantiated finite index
to its literal native counterpart. This proof-only correction is mirrored in
`emcurve_instances.go`; the actual circuit and every theorem premise/target
are unchanged. All 49 later-step composition lemmas now pass together in the
current module (`/private/tmp/ecies-chain-composition-main-3.log`). Fresh
generator reproduction of this renderer correction remains unperformed.

`CompletenessCombFirstNative`, `CompletenessCombFirstArithmetic`, and the full
`combFirst_complete` endpoint now pass. The first step's actual four-element
assertion is constructed independently of the later six-element assertions.
The proof constructs its chord slope, balanced pieces, bounded Lazy x-update,
exact native continuation, `FirstRel`, and group-sum identity. Its local
noncollision premise derives from the fixed-base prefix mathematics; it is
not a new production input restriction or an assumed successful operation.

All 54 composition/first-step endpoints pass an axiom audit with only
`propext`, `Classical.choice`, and `Quot.sound`. Logs:
`/private/tmp/ecies-comb-first-native-2.log`,
`/private/tmp/ecies-comb-first-arithmetic-1.log`,
`/private/tmp/ecies-comb-first-full-1.log`, and
`/private/tmp/ecies-comb-first-chain-axioms.log`.
The remaining complete step constructors, full fixed-base and variable-base
assemblies, and key-agreement completeness remain open. The second step has
subsequently passed the full check and audit recorded below.
All checks were serial; no tests, Go hints, witnesses or circuits ran.

### Second fixed-base chain: full kernel validation

`CompletenessCombMath`, `CompletenessCombSecondNative`,
`CompletenessCombSecondArithmetic`, and the full `combSecond_complete`
endpoint pass kernel checking. The latter constructs the actual
`CombChainStep_8_8_8_8_8_8_8_hd0a2e1d5` predicate, using the six-element
`hd6f972c2` slope assertion and bounded `h33616364` Lazy output. The original
input bounds, `RangeComplete` premise, local finite-point noncollision,
`ChainRel` and group-sum result are unchanged. The outer theorem constructs
both primitive witnesses; it has no successful-operation premise.

The field-to-modular slope equation is now proved using abstract elements in
`combChainSlope_zero`, before substituting the balanced mathematical slope.
The native bridge follows the checked later-step template and preserves all
24 range pieces and native gates. The unused local vector helpers were removed after
confirming they had no external callers.

All eight mathematical/native/arithmetic/full endpoints have axiom audits
containing only `propext`, `Classical.choice`, and `Quot.sound`. Logs:
`/private/tmp/ecies-comb-math-factored-1.log`,
`/private/tmp/ecies-comb-second-native-1.log`,
`/private/tmp/ecies-comb-second-arithmetic-1.log`,
`/private/tmp/ecies-comb-second-full-1.log`, and
`/private/tmp/ecies-comb-second-axioms.log`. Checks used one Lean process with
`-j1`, default linters and the requested capped diagnostics. No tests, Go
hints, witnesses, solvers, circuits or generators were run. All owned Lean
processes have finished for parent review. Full fixed-base, variable-base and
agreement assembly remain open.

Parent review confirmed all actual hash predicates, certificate bounds,
domain premises and constructed continuations. The unused local
`lazySecond_complete` compatibility wrapper was removed after confirming no
callers. The full theorem then passed parent checking again, and the seven
remaining endpoints passed a standard-only axiom audit:
`/private/tmp/ecies-comb-second-full-parent.log` and
`/private/tmp/ecies-comb-second-parent-axioms.log`.

The generic `Field.CompletenessLazy.combLazy_complete` now also passes Lean
and a standard-only axiom audit. Its native-body equality and conditional
bound/congruence soundness premises are established separately for each actual
hash. It constructs an actual native output using the already checked first
Lazy witness and transports that witness to the chosen predicate, attaching
integer bounds and value congruence. It does not assume witness existence.
Logs: `/private/tmp/ecies-comb-lazy-generic-2.log` and
`/private/tmp/ecies-comb-lazy-generic-axioms.log`.
The remaining individual-step instantiations have subsequently passed the
kernel checks below. Full multiplication remains open.

### Remaining forty-nine comb steps: kernel-checked proof-source mirror

`CompletenessCombLayout` passes Lean and now holds the unchanged shared
`combSecondSlope_layout` theorem, abstract Lazy layout/expression facts and a
generic arithmetic constructor using the checked `combLazy_complete`.
`CompletenessCombSecondArithmetic` and the full second-step endpoint were
rechecked after moving the layout; their public types remain unchanged.

All forty-nine remaining complete native comb-step endpoints and their
per-hash Lazy constructors pass Lean in `CompletenessGeneratedCombSteps`.
The original statement headers, actual hashes, literal certificate/input
bounds, local noncollision conditions and `RangeComplete` premise are
preserved. Matching is proved with abstract `ElemVal L` before substituting
the constructed balanced slope. Actual Lazy witnesses come from the checked
native-body equality and conditional forward bound/congruence theorem; no
successful-predicate premise is added to the complete step theorem.

The ordinary `renderCompleteChainStep` source and its proof-source mirror now
use those helpers. The comb module imports exactly its forty-nine required
assertion leaves, without either generated completeness aggregate. The
renderer records each assertion's emitted leaf and fails closed if a required
leaf is missing. Required unchanged assertion `hf93ee67b` in leaf77 was also
kernel-checked. Its prior missing artifact was an import blocker rather than
a theorem failure.

All103 audited endpoints (forty-nine complete steps, forty-nine Lazy
constructors, four shared helpers and assertion77) depend only on `propext`,
`Classical.choice`, and `Quot.sound`. Logs:
`/private/tmp/ecies-comb-layout-generic-1.log`,
`/private/tmp/ecies-comb-required-assert77-1.log`,
`/private/tmp/ecies-comb-remaining49-2.log`,
`/private/tmp/ecies-comb-remaining49-axioms.log`,
`/private/tmp/ecies-comb-second-layout-move-1.log`, and
`/private/tmp/ecies-comb-second-layout-move-full-1.log`.

Go source was formatted, but neither Go compilation nor the existing
generator was executed by this worker. Exact generator reproduction remains
pending at that checkpoint. The parent subsequently reviewed the helpers and
renderer, independently verified all49 original public theorem headers, and
compiled the already-authorized generator with one Go worker. Existing
`extract-ve-tables` completed into `/private/tmp/ecies-comb-reviewed-extraction-1`.
The corrected composition module and complete step module reproduce
byte-for-byte, resolving this integration obligation. The comparison found
277 matching generated modules and only ScalarCore's previously reviewed ten
nil-case proof replacements; those exact proof-only replacements were
integrated. The full ScalarCore kernel check remains pending. No circuit,
table, certificate, native wire or public theorem statement changed.
Log: `/private/tmp/ecies-comb-reviewed-generator-1.log`.
All owned execution processes have finished. Full fixed-base, variable-base and agreement
assembly remain open; no Quad work, tests, hints, witnesses, solvers or
circuits ran in this bounded component.

### Final fixed-base coordinate arithmetic

`Field.CompletenessCombReduce` and `Field.CompletenessCombRecover` now pass
Lean. They retain their literal certificate bounds, public completeness
premises and actual extracted predicates, and obtain the full remainder,
quotient and carry construction from the checked generated `h78194ae0` and
`h0845ed76` primitives. The unused cross-hash recovery equality was removed.
All eight completeness/capacity endpoints have axiom audits containing only
standard logical axioms. Logs:
`/private/tmp/ecies-comb-reduce-parent-1.log`,
`/private/tmp/ecies-comb-recover-parent-2.log`, and
`/private/tmp/ecies-comb-final-fields-axioms.log`.

The unverified full `ScalarMulBase` assembly now references the checked second
step by its actual declaration name `combSecond_complete`; all48 remaining
generated step names used by the assembly exist. Complete addition has now
passed the full validation below; tail composition and full multiplication
still require validation. These component passes are not evidence that the
full fixed-base theorem has passed.

### Complete addition: full kernel validation, including equal points

`completeAdd_with_point_complete` and its compatibility wrapper now pass
kernel checking for actual `CompleteAdd_8_8_8_8_h3f5cf0cd`. Their original
domain is unchanged: all four coordinate elements have reduced bounds, the
two x coordinates are canonical below p, both points are finite/on-curve,
and the points are not inverses. Equal points are included; the unchanged
`affineSlope_given_flag` selects the tangent and proves its denominator is
nonzero from the checked finite-curve facts.

The outer proof constructs the actual same-x Boolean/inverse hint, both
canonical input guards, balanced slope pieces, both flag assertions, the
unified slope assertion and both canonical output Eval predicates. It returns
the group-sum identity and exact native continuation. It assumes only the
explicit `RangeComplete` lookup contract, with no successful-primitive premise
and no lookup-soundness dependency to identify the constructed outputs.

The source was factored into `CompletenessAddLayout`, `CompletenessAddMath`,
`CompletenessAddNative`, `CompletenessAddArithmetic`, and
`CompletenessAddOutputs`. Layout, matching and integer/field equations use
abstract elements before substituting `slopeElem` or `canonicalFpElem`.
The lower native helper retains every canonical guard, range piece and
assertion. The original flag/slope vector and affine-slope declaration names
are retained through imports.

All ten audited mathematical/native/arithmetic/full endpoints use only
`propext`, `Classical.choice`, and `Quot.sound`. Passing logs:
`/private/tmp/ecies-completeadd-layout-2.log`,
`/private/tmp/ecies-completeadd-native-3.log`,
`/private/tmp/ecies-completeadd-arithmetic-3.log`,
`/private/tmp/ecies-completeadd-outputs-1.log`,
`/private/tmp/ecies-completeadd-math-1.log`,
`/private/tmp/ecies-completeadd-full-2.log`, and
`/private/tmp/ecies-completeadd-axioms.log`. Checks were serial with default
linters and capped diagnostics. All owned Lean processes have finished for
parent review. No tests, hints, witnesses, solvers, Go builds, generators,
circuits, Quad work or full assembly checks ran in this component.

Parent review subsequently confirmed the full complete-addition construction,
including equal-point tangents, unchanged domain premises, canonical guards,
same-x Boolean/inverse witness,24 balanced pieces,three actual assertions and
both actual Eval outputs. The outer theorem constructs every lower primitive
premise. The unused weaker `completeAdd_complete` wrapper and unused
`addDifference_native` layout lemma were removed after confirming no callers.
The layout/full theorem were rechecked and nine remaining endpoints were
audited against only standard logical axioms:
`/private/tmp/ecies-completeadd-layout-parent.log`,
`/private/tmp/ecies-completeadd-full-parent.log`, and
`/private/tmp/ecies-completeadd-parent-axioms.log`.
Tail composition has subsequently passed the check below. Full fixed-base
multiplication still requires validation.

### Fixed-base tail: full nested continuation validated

`CompletenessCombTailArithmetic` and the full `combTail_complete` endpoint
pass kernel checking. The public domain and actual nested predicate are
unchanged: `CheckPolynomial_8_h78194ae0`, followed by
`CheckPolynomial_24_h0845ed76`, followed by
`CompleteAdd_8_8_8_8_h3f5cf0cd`. X retains the literal last-lazy
`h7e1bb4d8` bound, and recovery retains the packed-y input bound.

The constructor chooses canonical FP representatives of the accumulator x
and implicit y. Abstract-element matching, expression, field and layout
lemmas identify them with the actual Eval remainders, using the checked
`addCanonical_native` bridge. It constructs the accumulator point identity,
canonical x bound and inherited noninverse condition before invoking checked
CompleteAdd, preserving equal-point addition. The outer theorem constructs
every primitive continuation; no operation-success premise or extra point
exclusion was introduced. The scalar assembly must still derive its unchanged
local geometric premises from the supported scalar domain.

All ten arithmetic/layout/full endpoints depend only on `propext`,
`Classical.choice`, and `Quot.sound`. Logs:
`/private/tmp/ecies-comb-tail-arithmetic-2.log`,
`/private/tmp/ecies-comb-tail-full-1.log`, and
`/private/tmp/ecies-comb-tail-axioms.log`. All owned Lean processes have
finished for parent review. Checks were serial with default linters and capped
diagnostics. No field interface, generator, full assembly or Quad changes,
and no tests, hints, witnesses, solvers or Go execution occurred.

### Full fixed-base multiplication: kernel validation

`scalarMulBase_complete` now passes Lean for actual `ScalarMulBase_8_h3037b025`.
Its domain is every reduced 256-bit scalar whose integer value has nonzero
residue modulo n, including representatives above n. The only lookup-completeness
premise is `RangeComplete`. It constructs canonical x/y below p, proves their
point is `S.value • G`, and supplies the exact native continuation. It has no
successful-operation premise, additional point exclusion, or assumption that
intermediate operations succeed.

The full proof assembles recoding bits, all window/top selections, fifty actual
chain steps, balanced slopes and pieces, concrete quotients/carries, every
intermediate point identity and noncollision, final noninverse geometry,
canonical recovery and complete addition. Parent checking found an import
collision between equivalent `affine_of_nonzero` helpers; these were consolidated
in `CompletenessAffine`, and both fixed-base/ladder callers passed again. One
final recoding-input vector equality was closed definitionally. No native wire,
circuit constraint, scalar domain or theorem premise changed.

The full fixed-base endpoint, shared affine helper, prefix coordinates,
half-tangent theorem and tail pass an axiom audit containing only `propext`,
`Classical.choice`, and `Quot.sound`. Logs:
`/private/tmp/ecies-fixed-base-complete-parent-3.log`,
`/private/tmp/ecies-fixed-base-complete-axioms.log`,
`/private/tmp/ecies-affine-shared-parent.log`,
`/private/tmp/ecies-comb-bits-shared-affine.log`, and
`/private/tmp/ecies-half-tangent-shared-affine.log`.

This is satisfying-witness existence for the actual fixed-base predicate;
it does not prove that the Go hints construct these witnesses. Go hints,
witnesses, solvers and tests were not executed. Variable-base and agreement
completeness remain open, as do byte-API composition and hint correspondence.

### Independent fixed-base review and actual half-tangent validation

Independent source review found no defect in the full fixed-base domain or
native continuation order. A static traversal of the actual extracted main,
p1 and p2 fragments confirmed all fifty chain hashes match the assembly order
exactly. The fifty-one selected windows, top selector and recoding are
constructed before the chain continuation. The final h781→h084→CompleteAdd
wiring agrees with the checked tail. `reducedC` supplies the full 256-bit
integer without truncation; the nonzero residue condition does not add an
S<n restriction. The final group-identity calculation uses the proper tail
orientation. This review does not establish Go hint correspondence.

`CompletenessHalfTangentArithmetic`, `CompletenessHalfTangentNative`, and
the full `halfTangent_complete` endpoint now pass kernel checking for actual
`HalfTangentSlope_8_8_h2c0228bb`. The domain remains every finite reduced input
point, with explicit `RangeComplete` and no point exclusion or assumed
successful operation. The root is supplied by the already proved mathematical
half point and odd group order. Both tangent denominators follow from checked
finite-curve facts; no inverse-four API restriction appears.

The constructor retains both 24-piece hints, all balanced range constraints,
actual `Lazy_8_h158c056f`, `CheckPolynomial_40_h0930c075` with its complete
quotient/carry constructor, and the exact native return. Matching/layout,
integer expression and field equations are generic in abstract elements,
then instantiated at the chosen slope. Only required checked leaves Lazy62
and Assert23 are imported. The missing Lazy62 artifact was checked serially
from its unchanged source. Native a-coordinate wiring uses the checked
`triple_aElem_native` identity.

All nine audited arithmetic/native/full/primitive endpoints depend only on
`propext`, `Classical.choice`, and `Quot.sound`. Logs:
`/private/tmp/ecies-half-required-lazy62-1.log`,
`/private/tmp/ecies-half-tangent-arithmetic-2.log`,
`/private/tmp/ecies-half-tangent-native-3.log`,
`/private/tmp/ecies-half-tangent-full-2.log`, and
`/private/tmp/ecies-half-tangent-axioms.log`. All owned Lean processes have
finished for parent review. Checks were serial with default linters and capped
diagnostics. No fixed-base source edit, full Quad/variable assembly, Go build,
generator, tests, hints, witnesses or solver execution occurred.

Parent source review confirmed the actual half-tangent domain, literal
certificate bounds and native predicates, constructed square/quartic
premises, all24 balanced range pieces and returned slope. Its nine-endpoint
audit was independently checked against only standard logical axioms.
No cleanup or premise change was needed. Full Quad, variable-base and
key-agreement completeness still require work.

### First actual Quad constructor: kernel-checked checkpoint

`CompletenessQuadFirst.quadAdd_h577e35e6_complete` now passes kernel checking
for the actual `QuadrupleAndAddLazy_8_8_8_8_h577e35e6` predicate. Its public
statement is unchanged: reduced AX/AY/SX, unpacked SY, finite input points,
the existing geometric `hfirst` and `hout` premises, and explicit
`RangeComplete`. It constructs outputs with the literal `lazy_h9c68f146` and
`lazy_h57fc266d` bounds, their finite point and group identity
`4 • A + T`, and every actual native continuation. Those local geometric
premises remain obligations for the later whole-ladder assembly; this is not
a claim of full variable-base or agreement completeness.

The new `Curve.CompletenessQuadFirstArithmetic` takes abstract bounded
L/M/N elements before the outer theorem substitutes the constructed slopes.
It constructs tangent h35a4bc86, doubled-X h30893ad5, doubled-Y h846878ce,
chord hf71c5652, flagged fallback h8696e642, intermediate-X h33616364,
second-slope h78e663c8, and final Lazy X/Y h9c68f146/h57fc266d. The native
zero flag is chosen for arbitrary `hs`; the emulated LastSlope identity
constructs the eager fallback assertion for either Boolean value. No native
slope-separation hypothesis, successful primitive premise, extra point
exclusion, or lookup-soundness premise was introduced. Exact checked leaves
replace the old dependency on the unfinished ordinary Quad module. The
checked pure native composition retains all three raw/balanced slope hint
vectors, range checks, gates and actual return. Witness existence does not
claim that the production Go hints return these witnesses.

The previously missing assertion78 artifact was checked from its unchanged
source. The process completed with exit0 while a static performance proposal
was being reviewed; it was not cancelled. Profile: parsing651s, linting897s,
metavariable instantiation85.4s, type checking51.9s, tactic execution13.7s,
and dsimp895ms. A source-only proposal batching four long dsimp commands was
prepared in `/private/tmp/ecies-flag78-batched-proposal.lean` and reviewed for
exact coverage. It remains unvalidated and unintegrated; neither the generated
primitive nor its renderer was changed, because the actual profile located
most cost in parsing/linting rather than dsimp execution.

Both the abstract arithmetic helper and full FirstQuad endpoint pass. All
seven audited endpoints (the assertion78 bridge, quotient bounds, carry
capacity and complete constructor, the arithmetic helper and full Quad)
depend only on `propext`, `Classical.choice`, and `Quot.sound`, or a subset.
Logs: `/private/tmp/ecies-quad-first-flag78.log`,
`/private/tmp/ecies-quad-first-arithmetic-3.log`,
`/private/tmp/ecies-quad-first-full-1.log`, and
`/private/tmp/ecies-quad-first-axioms.log`. Checks were serial, with default
linters and capped diagnostics. No Go/generator, tests, hints, witnesses,
solver, other Quad constructor or whole variable-base assembly was run.
All owned Lean processes finished for parent review.

Parent review independently checked the first-Quad arithmetic and outer
constructor against `QuadrupleAndAddLazy_8_8_8_8_h577e35e6_compose`, including
all three balanced slope decompositions and their 11/11/10 range pieces,
the five Lazy calls, four polynomial checks, native zero flag and actual
return. The fallback equation follows from the geometric LastSlope identity
for either flag value, so arbitrary `hs` imposes no native separation premise.
The original reduced/unpacked bounds and local geometric premises remain
explicit. The seven-endpoint axiom output was independently read and contains
only standard logical axioms. No source cleanup or premise change was needed.
The reviewed batching proposal was not adopted after the original check's
profile showed the proof commands were inexpensive. Full variable-base and
key-agreement completeness remain unproved; production hint correspondence
and witness/solver execution remain unperformed.

### Transition Quad: independent source review before validation

The parent reviewed the prepared `CompletenessQuadTransitionArithmetic` and
`CompletenessQuadTransition` source while the worker was idle and the sole
unchanged assertion80 check continued. The public
`quadAdd_h6e46ac5c_complete` header, premises and actual extracted target are
byte-identical to the saved original source. AX/AY retain the first-Quad Lazy
bounds, SX/SY retain their reduced/unpacked bounds, and the local geometric
premises remain explicit obligations for whole-ladder composition.

The helper constructs the exact tangent, chord, second-slope and flagged
fallback certificates, all five Lazy calls, native zero flag, output point
and continuations using abstract bounded L/M/N. The fallback equation is
supplied for either flag value by the checked geometric LastSlope identity;
no native-separation or primitive-success assumption appears. The outer
constructor supplies all three balanced slope decompositions and range
pieces through the checked native composition. No source defect was found
in this review, and neither file contains an unproved proof placeholder,
new axiom or unchecked decision procedure.

This is source review only. Assertion80 (`h9104a5ae`), Lazy60 (output-Y), the
helper, the full transition constructor and their axiom audit remain pending
at this checkpoint. The current single-process certificate log is
`/private/tmp/ecies-quad-transition-flag80.log`. No generator, Go hint,
witness/solver or test execution was performed.

### Ordinary Quad: independent source review before validation

The parent reviewed the prepared `CompletenessQuadArithmetic` and refactored
`CompletenessQuad` while the worker was idle. The public
`quadAdd_haf2b5bed_complete` header, bounds, local geometric premises and actual
extracted target are byte-identical to the original source. The helper
constructs tangent h6485b116, chord hdaa6ee4a, flagged fallback ha68a8775,
second-slope h4960297a and all five exact Lazy continuations, including their
literal certificate bounds and limb layouts. The outer constructor supplies
all slope hints and range pieces through the checked native composition.
The native flag is chosen for arbitrary `hs`, with LastSlope proving the
fallback equation for either value. No additional operation-success or
native-separation premise was introduced; no source defect was found.

This remains source review only: the ordinary helper and full constructor
have not been checked, and their assertion81 dependency is pending. The
single existing transition-certificate Lean process was independently
confirmed live during review; no additional checker was started. Transition
validation remains the next step. Whole variable-base and key-agreement
completeness, production hint correspondence and witness/solver execution
remain unfinished or unperformed.

### Last Quad: independent source review before validation

The parent independently reviewed `CompletenessQuadLastArithmetic` and the
refactored `CompletenessQuadLast` while the subagent was inactive. The public
`quadAdd_h4bfcc75d_complete` header, all bounds, local geometric premises and
actual extracted target are byte-identical to the original source. In
particular, this final variant retains reduced SY and the unflagged 48-input
LastSlope assertion; it does not inherit the middle variants' unpacked bound
or Boolean fallback predicate.

The helper constructs tangent h6485b116, chord h5fddb6f9, LastSlope hae80c491,
second-slope h28b208c7, and all five Lazy continuations with their exact
certificate bounds and limb layouts. The actual native composition receives
all three balanced slope hints, range pieces and return values. The
unflagged assertion follows from the checked geometric LastSlope identity,
without assuming primitive success or native slope separation. No defect
was found in this source review; helper/full kernel checks and their axiom
audit remain pending. Whole variable-base and key-agreement completeness
remain unfinished, and no Go hint, witness/solver or test execution occurred.

### Transition Quad: kernel-checked checkpoint

The reviewed `quadAdd_h6e46ac5c_complete` now passes kernel checking for actual
`QuadrupleAndAddLazy_8_8_8_8_h6e46ac5c`. Its public header and target remain
byte-identical to the original saved source. The input domain retains AX at
`lazy_h9c68f146`, AY at `lazy_h57fc266d`, reduced SX, unpacked SY, arbitrary
native `hs`, both finite input points, and the existing geometric exclusions
`2 • A ≠ T`, `2 • A ≠ -T`, and `4 • A + T ≠ 0`. `RangeComplete` is its only
lookup-completeness premise. It constructs outputs at the literal
`lazy_h9c68f146`/`lazy_hee995b41` bounds, their finite point and identity
`4 • A + T`, and every actual native continuation. Those local geometric
premises still need discharge by the later whole-ladder assembly.

`CompletenessQuadTransitionArithmetic` constructs all four assertions and
five Lazy operations from abstract bounded L/M/N elements before the outer
theorem instantiates the three mathematical slopes. It includes the actual
native IsZero flag for arbitrary `hs` and the eager flagged LastSlope check
for either Boolean value. All raw/balanced slope hints, decomposition ranges,
primitive input layouts, quotient/carry witnesses and actual return are
retained. No successful-primitive premise, native separation requirement,
extra point exclusion or lookup-soundness premise was introduced. Required
leaf imports are assertions19/14/26/80 and Lazy2/4/49/38/60, plus the checked
shared coordinate/tangent layout helpers.

Both missing unchanged leaves now pass: assertion80 h9104a5ae and Lazy60
hee995b41. Assertion80 profile: parsing672s, default linting898s,
metavariable instantiation86.5s, type checking51.7s, tactic execution13.8s,
and dsimp902ms. Lazy60 profile: parsing426ms, metavariable instantiation66.2s,
default linting19.9s and type checking2.68s. No batching proposal, diagnostic
option, linter omission, renderer change or prototype was integrated. The
aggregate profile does not identify which individual linter dominated; the
read-only pinned-source investigation found invocation-only diagnostic and
optional-linter options, but none was applied.

The abstract helper and full transition endpoint pass. All ten audited
endpoints (assertion80 bridge/capacities/complete; Lazy60 witness/mono/complete;
helper and full transition) use only `propext`, `Classical.choice`, and
`Quot.sound`, or a subset. Logs:
`/private/tmp/ecies-quad-transition-flag80.log`,
`/private/tmp/ecies-quad-transition-lazy60.log`,
`/private/tmp/ecies-quad-transition-arithmetic-1.log`,
`/private/tmp/ecies-quad-transition-full-1.log`, and
`/private/tmp/ecies-quad-transition-axioms.log`. All checks were serial with
-j1, default linters and capped diagnostics. All owned processes finished.

During this same serial leaf check, source-only ordinary and last Quad
refactors were prepared with parent authorization and independently reviewed.
Their original public headers/targets were preserved byte-for-byte against
`/private/tmp/ecies-quad-ordinary-original.lean` and
`/private/tmp/ecies-quad-last-original.lean`. Their kernel checks and axiom
audits remain pending; no ordinary/last checker was launched. No whole
variable-base/agreement assembly, Go/generator, tests, Go hints, witnesses,
solver or circuit execution occurred. Witness existence remains separate
from production hint correspondence.

Parent post-validation review confirmed the unchanged actual transition
header, predicate and witness construction, checked the four resulting
kernel artifacts and independently parsed all ten axiom reports, including
the multiline helper entry. Only standard logical axioms appear. No further
source change or broader claim was needed. The main status report now records
both first and transition Quad constructors as checked, with ordinary/final
checks and whole variable-base/key-agreement composition still outstanding.

### Ordinary and final Quad: kernel-checked checkpoint

Both previously reviewed constructors now pass kernel checking without a
source correction: `quadAdd_haf2b5bed_complete` for actual
`QuadrupleAndAddLazy_8_8_8_8_haf2b5bed`, and
`quadAdd_h4bfcc75d_complete` for actual
`QuadrupleAndAddLazy_8_8_8_8_h4bfcc75d`. Their public headers and targets remain
byte-identical to the saved original snapshots. Both retain AX at
`lazy_h9c68f146`, AY at `lazy_hee995b41`, reduced SX, arbitrary native hs,
finite input points and the original local hfirst/hout geometric premises.
The ordinary variant retains unpacked SY and the eager Boolean/flagged49
fallback; the final variant retains reduced SY and the unflagged48 LastSlope
assertion. Neither gains an operation-success, native-separation or extra
point-exclusion premise. `RangeComplete` remains the only lookup-completeness
premise in these constructors.

The ordinary output has the actual h9c68f146/hee995b41 Lazy bounds; the final
output has h9c68f146/hc2c2cd77 bounds. Both construct all primitive calls,
three raw/balanced slope hints and ranges, their finite output point with
identity `4 • A + T`, and every actual continuation. Their arithmetic helpers
operate on abstract bounded elements before instantiated slope elements.
The final SY bound and unflagged check were independently reviewed against
the extracted source before validation.

The only missing required artifact, unchanged assertion81 ha68a8775, now
passes. Profile: parsing662s, default linting892s, metavariable
instantiation86.1s, type checking51.7s, tactic execution13.6s and dsimp887ms.
No batching/prototype, linter omission, option, renderer, configuration or
tactic infrastructure change was used. Ordinary helper/full and final
helper/full all pass; each seven-endpoint audit contains only `propext`,
`Classical.choice` and `Quot.sound`, or a subset. Logs:
`/private/tmp/ecies-quad-ordinary-flag81.log`,
`/private/tmp/ecies-quad-ordinary-arithmetic-1.log`,
`/private/tmp/ecies-quad-ordinary-full-1.log`,
`/private/tmp/ecies-quad-ordinary-axioms.log`,
`/private/tmp/ecies-quad-last-arithmetic-1.log`,
`/private/tmp/ecies-quad-last-full-1.log`, and
`/private/tmp/ecies-quad-last-axioms.log`. Checks were serial with -j1,
default linters and capped diagnostics. All owned processes finished.

A read-only next-stage inventory identified exact remaining assembly work.
The variable predicate is `ScalarMulChecked_8_8_8_h9a706aba`; the key-agreement
predicate is `AgreeKey_32_65_6`, with the already defined valid 65-byte
uncompressed-public-key domain and all 32-byte nonzero-residue secrets.
The checked main/p1 prefix bridge exists. ScalarCore p2..p9 composition and
next-input records exist as source, but their aggregate kernel artifact was
absent at this checkpoint. Their outer mathematical witness assembly is not
yet present: signed selected-y bounds, RawR48 recomposition, slot/half/row
callbacks, native selector index identities, prefix state identities, final
low-bit selectors and normalization comparators still need stitching.
Existing checked primitive decomposition, selection, bits, rows and geometric
noncollision helpers supply the relevant mathematics. Middle hfirst follows
from middle_chord_noncollision; hout follows from the prefix identities and
ladder_prefix_nonzero. The last pre-add/chord/output helpers supply final
geometry. Both eager low-bit additions, including inverse-four, are covered
by correction_product_distinct and lowbit_correction_distinct. The repaired
Quad constructors do not require the old nativeSlope_nonzero_iff exclusions.

Agreement still needs an actual reverse body combining byte Horner decoding,
AssertOnCurve (Lazy8 h2d947ec4 and Check40 h29707435), canonical guards,
variable-base and the checked fixed-base constructor, compression and splits.
Existing split/packing/canonical helpers and numerical primitive leaves do
not themselves prove that full assembly. Whole variable-base and agreement
completeness remain unfinished; no assembly source/check, Go/generator, test,
Go hint, witness, solver or circuit execution occurred in this checkpoint.
Witness existence remains separate from production hint correspondence.

Parent post-validation review independently checked the ordinary and final
public headers against their original snapshots, verified all four helper/full
kernel artifacts, and parsed both seven-endpoint axiom outputs. All fourteen
entries use only standard logical axioms. The reviewed source needed no
correction. The main status report now records all four actual Quad
constructors as checked, while explicitly retaining the whole scalar-core,
variable-base and key-agreement assembly gaps.

### Scalar-core composition: kernel-checked checkpoint before commit

The current full `CompletenessGeneratedScalarCore.lean` passes the pinned
Lean kernel check, including all eight actual p2..p9 fragment-composition
theorems and seven next-input record equalities. No source correction was
needed. The aggregate artifact was written; the process returned exit0.
Log: `/private/tmp/ecies-scalar-core-whole-1.log`. Profile: parsing2.56s,
elaboration10.7s, type checking1.34s, default linting1.08s and serialization1.31s.
The dedicated fifteen-endpoint axiom audit has not been performed at this
commit checkpoint. Work was frozen for the user's snapshot request.

These are composition theorems with explicit primitive premises, not a
whole variable-base witness-existence theorem. The later assembly must still
construct every premise and bind the mathematical points, ranges, selectors,
row lookups and correction branches to the native records. Whole variable-base
and key-agreement completeness remain unfinished. Tests, production Go-hint
correspondence and witness/solver execution remain unperformed.
