# Native slope guard repair — integrated source, unperformed proof validation

The authorized offline arithmetic search found this valid P-256 recipient for
the scalar 2:

```text
041bafbedd4beef1aa27c8c8443dae7bef8314ab20a58ddfe300f60f11da68cd409b335b71ccfff12ab40b94b0509a97f141549b23c5fa96564a562f8953623db6
```

The pinned rational reconstruction returns numerator 2, denominator 1 and a
negative signed denominator. The first accumulator is -Q, and the leading
zero bits select the row 3Q. The balanced tangent at -Q and half tangent at
3Q are respectively:

```text
 44276850581706675402633548879493395649342029952622209993727888124831289624929
-22388607709867400180387143134236120560793665552206175650029683938255481129312
```

Their sum is the BN254 field order. The existing native-field product is
therefore zero, despite distinct P-256 slopes and finite curve additions.
The table stores the half slope with the slot's sign; the guard's symmetric
product includes both signs, so this sign convention does not avoid the failure.
This establishes failure of this production hint path by arithmetic and source
tracing. It does not establish that every alternative decomposition witness
fails for this input. No production hint or circuit was executed.

The proposed repair preserves the twelve-column table and its half-slope
binding. On a zero native product it requires the doubling-aware P-256 chord
equation already used by the last step. On a nonzero native product it retains
the existing soundness implication. The zero indicator is constrained by
`api.IsZero`, so the prover cannot choose which case applies.

Replace the nonzero assertion in the middle-step branch with:

```go
nativeProduct := c.nativeSlopeDifferenceProduct(tangentSlope, halfSlope)
guardZero := c.api.IsZero(nativeProduct)
guard := fp.Bounded([]frontend.Variable{guardZero}, []int{1})
xSum := fp.Add(doubledX, selectedPoint.X)
fp.AssertZero(
    T(1, guard, chordSlope, fp.Add(doubledY, selectedPoint.Y)),
    T(-1, guard, xSum, xSum),
    T(1, guard, doubledX, selectedPoint.X),
    T(-1, guard, c.a),
)
```

`nativeSlopeDifferenceProduct` contains the existing native arithmetic and
returns its product. The existing `assertDistinctSlopeConstrained` can retain
its original assertion by calling this helper. The last step remains unchanged.
No new generator, tactic, build or CI infrastructure is needed.

Soundness uses the disjunction `dX != xT` or `LastSlope`, which is already the
premise of `quad_add_correct`. When the indicator is zero, the old nonzero
product and half-tangent relation supply the first case. When it is one, the
new field equation supplies `LastSlope`. Constructive primitive witnesses
satisfy that field equation in either case, so they require no native residue
exclusion. The repair adds field constraints; its cost has not been measured.

The user authorized the existing VE generators and their required Go/circuit
compilation. The Go repair was applied, its generated predicates/certificates
were reviewed in a temporary directory and integrated, and the three middle
Quad/table soundness proofs were adapted in source. An explicit formal wrapper
retains the actual standalone guard and its diagnostic theorem. Field instance
imports were updated for the generator's new module partitions.

The existing generator commands completed successfully. The user subsequently
authorized Lean checking. All three revised Quad soundness lemmas and the
public ladder-step soundness interfaces passed against the refreshed extracted
predicates; the concrete old-guard failure also passed its kernel checks.
Full witness assembly remains underway. Tests, production hint
execution, circuit/witness execution and cost measurement remain unperformed
and unauthorized.
