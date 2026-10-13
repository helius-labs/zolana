# Final curve check for the P-256 ladder

`quadrupleAndAddLazy` checks no per-step doubling certificate. Each step
carries one output guard, and a single curve check on the ladder output
certifies every step backwards. This note gives the argument and the residual
completeness gap of the guard. It is ported from the gnark-gadgets P-256
experiment (`gnark-gadgets/p256/ladder-soundness.md`, commit 33c16ef).

## Step identities

All equations are in the P-256 base field. Write
`F(x,y) = y² − x³ − a x − b` with `a = −3`. A step receives `A = (xA,yA)`
and an on-curve table point `T = (u,v)`. The tangent hint `α` satisfies
`2 α yA = 3 xA² + a`, and `x = α² − 2 xA`, `y = α (xA − x) − yA`. Direct
expansion gives `F(x,y) = F(xA,yA)`, with no assumption on `A`.

The chord and second slopes `λ`, `μ` and the output satisfy

```
λ (u − x) = v − y
z = λ² − x − u
μ (z − x) = 2 y
w = u + μ (μ + 2λ)            (computed as (λ+μ)² − λ² + u)
r = (λ + μ) (w − x) − y
```

With `K = (z − x) (u − x + λμ) − 3x² − a`, expansion using the two slope
equations gives `F(u,v) − F(x,y) = (u − x) K` and
`F(w,r) − F(x,y) = (w − x) K`. Since `F(u,v) = 0`,

```
F(w,r) = (w − u) K.
```

The output guard proves `w − u = μ(μ+2λ) ≠ 0`. If the output is on the curve,
then `K = 0`, so `F(x,y) = 0` and `F(xA,yA) = 0`. Applied backwards from one
curve check on the ladder output, every step input, doubled point and output
is on the curve and every step has `K = 0`. On-curve points have nonzero y
(P-256 has no point of order two), so the tangent is unique; `K = 0` makes
the chord equation the tangent equation when `u = x`; and the second slope
equation forces `z ≠ x`. Each step therefore computes `4A + T` with no
exceptional denominator. `TestFinalCurveCheckNeedsLadderOutputGuard` and
`TestLadderOutputGuardNeedsFinalCurveCheck` show that neither check suffices
alone.

## Where the curve check is

The ladder keeps its target-side correction: it asserts
`acc = 3R + (1−d₀)R + (1−n₀)Q`, building the target from `3R` and guarded
additions of on-curve points. The target is on the curve, so this equality is
the curve check on the uncorrected ladder output; no separate
`assertOnCurve(acc)` is needed. Correcting `acc` itself, as the experiment
does, would reject the scalars `±1/4` and `±2/3` (`sweep_test.go`).

## First step from the table

Rational reconstruction returns both halves below `2^128`
(`TestReconstructionHalvesFit128Bits`): the half-GCD invariant
`r0|t1| + r1|t0| = n` and the stop at `r1 < floor(sqrt(n)) <= r0` give
`|t1| <= n/floor(sqrt(n)) < 2^128`. The circuit bounds the top radix-four
digit to one bit.
From `Q + R`, the step over bits 128 and 127 lands on
`(1+2n₁₂₇)Q + (1+2d₁₂₇)R`, one of the checked table points, so the ladder
starts there and resumes at bit pair 126/125.

## Native output guard and its completeness gap

Both slopes come from `HintBalanced`: limb `i` lies in
`[−2^(wᵢ−1), 2^(wᵢ−1)−1]`, so with `M = Σ 2^(wᵢ−1) 2^(32 i)` the circuit
checks at compile time `M < p` and `3M < 2p`. The integer representatives of
zero modulo `p` are therefore `0` for `μ` and `−p, 0, p` for `S = μ + 2λ`.
The guard asserts that the native value of `μ S (S² − p²)` is nonzero. Every
zero modulo `p` makes this integer exactly zero, aliases modulo the BN254
field included, so the guard admits no zero modulo `p`.

The converse does not hold. The integer `μ S (S² − p²)` exceeds the native
field, so it can vanish natively while `μ` and `S` are nonzero modulo `p`:
when `μ` is a nonzero multiple of the BN254 order `r`, or `S` is one of
`±k r` or `±p ± k r`. An honest witness hitting such a value is rejected.
This is a completeness gap, not a soundness one. The slopes are rational
functions of points that depend on the secret scalar, so a step hits one of
these values with probability about `2^-250`; nobody can steer a recipient
key towards it without the scalar. An exact guard (an integer-zero test of
`μ` and of each candidate `S − kp` through the native value and its low limb)
is estimated at about 30 more constraints per step, roughly 1.8k per key
agreement, and was not adopted.
