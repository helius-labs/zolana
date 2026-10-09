package emcurve

import (
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
