package emcurve

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// Fixed-base comb extraction gadgets, in the pattern of step_gadgets.go.

// CombSelect is combSelect: the table entry indexed by SelectorBits (little
// endian). TableX holds each entry's x limbs and TableY its y limbs, or its
// packed y limb groups when PackY is set. The table constants are call
// arguments, so every window shares one definition per shape.
type CombSelect struct {
	TableX, TableY [][]frontend.Variable
	SelectorBits   []frontend.Variable
	PackY          bool
	Lookups        bool
}

func (g CombSelect) DefineGadget(api frontend.API) interface{} {
	c := newCurveFor(api, g.Lookups)
	out := c.combSelectConstrained(g.TableX, g.TableY, g.SelectorBits, g.PackY)
	recordOutputs(g, out.X, out.Y)
	return pointLimbs(out)
}

func (c *curve) combSelect(table [][2]*big.Int, selectorBits []frontend.Variable, packY bool) *point {
	xs, ys := c.combTableLimbs(table, packY)
	if !abstractor.Extracting(c.api) {
		return c.combSelectConstrained(xs, ys, selectorBits, packY)
	}
	g := CombSelect{TableX: xs, TableY: ys, SelectorBits: selectorBits, PackY: packY, Lookups: c.layout.Lookups}
	return c.pointFromGadget(g, abstractor.Call2(c.api, g))
}

// CombChainStep is one step of the comb addition chain: from the accumulator
// x-coordinate X with implicit y (given by PreviousSlope and the previous
// window point), add the window point W. It returns [nextX, slope]; the first
// step (First) reads the y-coordinate of window zero, FirstWindowY.
type CombChainStep struct {
	X, PreviousSlope, PreviousWindowX, PreviousWindowY, WindowX, WindowY, FirstWindowY []frontend.Variable
	XBounds, PreviousSlopeBounds, PreviousWindowXBounds, PreviousWindowYBounds         []*big.Int
	WindowXBounds, WindowYBounds, FirstWindowYBounds                                   []*big.Int
	First                                                                              bool
	Lookups                                                                            bool
}

func (g CombChainStep) DefineGadget(api frontend.API) interface{} {
	c := newCurveFor(api, g.Lookups)
	fp := c.fp
	window := &point{X: fp.FromBounds(g.WindowX, g.WindowXBounds), Y: fp.FromBounds(g.WindowY, g.WindowYBounds)}
	nextX, slope := c.combChainStepConstrained(g.First,
		fp.FromBounds(g.X, g.XBounds),
		fp.FromBounds(g.PreviousSlope, g.PreviousSlopeBounds),
		fp.FromBounds(g.PreviousWindowX, g.PreviousWindowXBounds),
		fp.FromBounds(g.PreviousWindowY, g.PreviousWindowYBounds),
		window,
		fp.FromBounds(g.FirstWindowY, g.FirstWindowYBounds))
	recordOutputs(g, nextX, slope)
	return [][]frontend.Variable{nextX.Limbs(), slope.Limbs()}
}

func (c *curve) combChainStep(first bool, x, previousSlope, previousWindowX, previousWindowY *fpElement, windowPoint *point, firstWindowY *fpElement) (nextX, slope *fpElement) {
	if !abstractor.Extracting(c.api) {
		return c.combChainStepConstrained(first, x, previousSlope, previousWindowX, previousWindowY, windowPoint, firstWindowY)
	}
	g := CombChainStep{
		X: x.Limbs(), PreviousSlope: previousSlope.Limbs(), PreviousWindowX: previousWindowX.Limbs(), PreviousWindowY: previousWindowY.Limbs(),
		WindowX: windowPoint.X.Limbs(), WindowY: windowPoint.Y.Limbs(), FirstWindowY: firstWindowY.Limbs(),
		XBounds: x.Bounds(), PreviousSlopeBounds: previousSlope.Bounds(), PreviousWindowXBounds: previousWindowX.Bounds(),
		PreviousWindowYBounds: previousWindowY.Bounds(), WindowXBounds: windowPoint.X.Bounds(), WindowYBounds: windowPoint.Y.Bounds(),
		FirstWindowYBounds: firstWindowY.Bounds(),
		First:              first,
		Lookups:            c.layout.Lookups,
	}
	out := abstractor.Call2(c.api, g)
	bounds := recordedOutputs(g)
	return c.fp.FromBounds(out[0], bounds[0]), c.fp.FromBounds(out[1], bounds[1])
}

// CompleteAdd is completeAdd: P + Q for distinct points or a doubling, with
// inverse points rejected.
type CompleteAdd struct {
	PX, PY, QX, QY                         []frontend.Variable
	PXBounds, PYBounds, QXBounds, QYBounds []*big.Int
	Lookups                                bool
}

func (g CompleteAdd) DefineGadget(api frontend.API) interface{} {
	c := newCurveFor(api, g.Lookups)
	p := &point{X: c.fp.FromBounds(g.PX, g.PXBounds), Y: c.fp.FromBounds(g.PY, g.PYBounds)}
	q := &point{X: c.fp.FromBounds(g.QX, g.QXBounds), Y: c.fp.FromBounds(g.QY, g.QYBounds)}
	out := c.completeAddConstrained(p, q)
	recordOutputs(g, out.X, out.Y)
	return pointLimbs(out)
}

func (c *curve) completeAdd(p, q *point) *point {
	if !abstractor.Extracting(c.api) {
		return c.completeAddConstrained(p, q)
	}
	g := CompleteAdd{
		PX: p.X.Limbs(), PY: p.Y.Limbs(), QX: q.X.Limbs(), QY: q.Y.Limbs(),
		PXBounds: p.X.Bounds(), PYBounds: p.Y.Bounds(), QXBounds: q.X.Bounds(), QYBounds: q.Y.Bounds(),
		Lookups: c.layout.Lookups,
	}
	return c.pointFromGadget(g, abstractor.Call2(c.api, g))
}
