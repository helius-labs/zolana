package spp

import "github.com/consensys/gnark/frontend"

// Generic boolean-gated constraint helpers shared by the spend checks. In each,
// cond must already be constrained boolean.

// assertEqualWhen constrains a == b only when cond == 1.
func assertEqualWhen(api frontend.API, cond, a, b frontend.Variable) {
	api.AssertIsEqual(api.Mul(cond, api.Sub(a, b)), 0)
}

// assertZeroWhen constrains v == 0 only when cond == 1.
func assertZeroWhen(api frontend.API, cond, v frontend.Variable) {
	api.AssertIsEqual(api.Mul(cond, v), 0)
}

// assertStrictlyOrdered constrains lo < mid < hi for a real entry. Dummy entries
// (isDummy == 1) become 0 < 1 < 2, so the check always passes for them. It uses
// AssertIsLessOrEqual plus AssertIsDifferent instead of a `+1` step, which could
// wrap around at the field boundary.
func assertStrictlyOrdered(api frontend.API, isDummy, lo, mid, hi frontend.Variable) {
	lo = api.Select(isDummy, frontend.Variable(0), lo)
	mid = api.Select(isDummy, frontend.Variable(1), mid)
	hi = api.Select(isDummy, frontend.Variable(2), hi)
	api.AssertIsLessOrEqual(lo, mid)
	api.AssertIsDifferent(lo, mid)
	api.AssertIsLessOrEqual(mid, hi)
	api.AssertIsDifferent(mid, hi)
}
