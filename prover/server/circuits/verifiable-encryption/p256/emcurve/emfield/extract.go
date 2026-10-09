package emfield

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// RangeCheck stands for a lookup range check of V to Bits bits. It exists only
// for Lean extraction: the lookup argument is committed in a deferred
// callback, so Lean receives it as the opaque predicate RangeCheck whose
// soundness is an explicit assumption.
type RangeCheck struct {
	V    frontend.Variable
	Bits int
}

func (RangeCheck) DefineGadget(frontend.API) interface{} { panic("extraction-only") }

func (RangeCheck) OpaqueOutputs() int { return 0 }

// Bounds encodes the compile-time metadata of e as
// [valueMin, valueMax, combined, lo_0..lo_{n-1}, hi_0..hi_{n-1}], where
// combined is 1 for a linear combination. Extraction gadgets carry it as a
// hashed parameter so the rebuilt element reproduces every bound-dependent
// choice (fold path, quotient and carry widths) of the original call.
func (e *Element) Bounds() []*big.Int {
	combined := big.NewInt(0)
	if e.parts != nil {
		combined.SetInt64(1)
	}
	out := []*big.Int{new(big.Int).Set(e.valueMin), new(big.Int).Set(e.valueMax), combined}
	for _, l := range e.lo {
		out = append(out, new(big.Int).Set(l))
	}
	for _, h := range e.hi {
		out = append(out, new(big.Int).Set(h))
	}
	return out
}

// FromBounds rebuilds an element from limbs and metadata produced by Bounds.
// Like Bounded, it attaches bounds without constraining them.
func (f *Field) FromBounds(limbs []frontend.Variable, bounds []*big.Int) *Element {
	n := len(limbs)
	if len(bounds) != 3+2*n {
		panic("bounds do not match the limb count")
	}
	e := &Element{
		limbs:    limbs,
		valueMin: new(big.Int).Set(bounds[0]),
		valueMax: new(big.Int).Set(bounds[1]),
		lo:       make([]*big.Int, n),
		hi:       make([]*big.Int, n),
	}
	if bounds[2].Sign() != 0 {
		e.parts = []part{}
	}
	for i := range limbs {
		e.lo[i] = new(big.Int).Set(bounds[3+i])
		e.hi[i] = new(big.Int).Set(bounds[3+n+i])
	}
	return e
}

// SameBounds reports whether a and b carry identical metadata.
func SameBounds(a, b *Element) bool {
	x, y := a.Bounds(), b.Bounds()
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i].Cmp(y[i]) != 0 {
			return false
		}
	}
	return true
}
