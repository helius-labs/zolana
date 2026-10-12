package emcurve

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// FormalGuardedAdd exposes guardedAdd on reduced coordinate limbs for the
// formal-verification GuardedAdd circuit.
func FormalGuardedAdd(api frontend.API, px, py, qx, qy []frontend.Variable) (rx, ry []frontend.Variable) {
	c := newCurve(api)
	p := &point{X: c.fp.Reduced(px), Y: c.fp.Reduced(py)}
	q := &point{X: c.fp.Reduced(qx), Y: c.fp.Reduced(qy)}
	r := c.guardedAdd(p, q)
	return r.X.Limbs(), r.Y.Limbs()
}

// FormalNativeSlopeGuard retains the standalone native guard in the
// extraction library. Middle ladder steps use its constrained fallback;
// the standalone implication and the counterexample still refer to this
// actual gadget on the same balanced-limb metadata as production slopes.
func FormalNativeSlopeGuard(api frontend.API, limbs []frontend.Variable, other frontend.Variable) {
	c := newCurve(api)
	lo, hi := make([]*big.Int, len(limbs)), make([]*big.Int, len(limbs))
	for i := range limbs {
		lo[i] = big.NewInt(-2147483648)
		hi[i] = big.NewInt(2147483647)
	}
	c.assertDistinctSlope(c.fp.WithBounds(limbs, lo, hi), other)
}
