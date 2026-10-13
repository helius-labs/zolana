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

// FormalLadderOutputGuard exposes the ladder step's output guard on the
// balanced-limb metadata of production slopes.
func FormalLadderOutputGuard(api frontend.API, chordSlope, secondSlope []frontend.Variable) {
	c := newCurve(api)
	balanced := func(limbs []frontend.Variable) *fpElement {
		lo, hi := make([]*big.Int, len(limbs)), make([]*big.Int, len(limbs))
		for i := range limbs {
			lo[i] = big.NewInt(-2147483648)
			hi[i] = big.NewInt(2147483647)
		}
		return c.fp.WithBounds(limbs, lo, hi)
	}
	c.assertLadderOutputDistinct(balanced(chordSlope), balanced(secondSlope))
}
