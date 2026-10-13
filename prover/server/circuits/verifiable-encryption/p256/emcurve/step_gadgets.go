package emcurve

import (
	"math/big"
	"reflect"
	"sync"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// Ladder and curve-step extraction gadgets. Each original method is renamed
// *Constrained and the method below keeps its name: on a builder it calls the
// original, under the extractor it calls the gadget. The output bounds of a
// gadget depend only on its parameters, so DefineGadget records them under the
// gadget's parameter key and every call rebuilds its outputs from them.

var gadgetOutputBounds sync.Map

func outputKey(g any) string {
	return reflect.TypeOf(g).Name() + "/" + abstractor.ParamHash(g)
}

func recordOutputs(g any, elements ...*fpElement) {
	bounds := make([][]*big.Int, len(elements))
	for i, e := range elements {
		bounds[i] = e.Bounds()
	}
	gadgetOutputBounds.Store(outputKey(g), bounds)
}

func recordedOutputs(g any) [][]*big.Int {
	bounds, ok := gadgetOutputBounds.Load(outputKey(g))
	if !ok {
		panic("gadget output bounds were not recorded")
	}
	return bounds.([][]*big.Int)
}

func (c *curve) pointFromGadget(g any, coordinates [][]frontend.Variable) *point {
	bounds := recordedOutputs(g)
	return &point{X: c.fp.FromBounds(coordinates[0], bounds[0]), Y: c.fp.FromBounds(coordinates[1], bounds[1])}
}

func pointLimbs(p *point) [][]frontend.Variable {
	return [][]frontend.Variable{p.X.Limbs(), p.Y.Limbs()}
}

// QuadrupleAndAddLazy is quadrupleAndAddLazy: 4·acc + selected.
type QuadrupleAndAddLazy struct {
	AccX, AccY, SelectedX, SelectedY                         []frontend.Variable
	AccXBounds, AccYBounds, SelectedXBounds, SelectedYBounds []*big.Int
}

func (g QuadrupleAndAddLazy) DefineGadget(api frontend.API) interface{} {
	c := newCurve(api)
	acc := &point{X: c.fp.FromBounds(g.AccX, g.AccXBounds), Y: c.fp.FromBounds(g.AccY, g.AccYBounds)}
	selected := &point{X: c.fp.FromBounds(g.SelectedX, g.SelectedXBounds), Y: c.fp.FromBounds(g.SelectedY, g.SelectedYBounds)}
	out := c.quadrupleAndAddLazyConstrained(acc, selected)
	recordOutputs(g, out.X, out.Y)
	return pointLimbs(out)
}

func (c *curve) quadrupleAndAddLazy(accumulator, selectedPoint *point) *point {
	if !abstractor.Extracting(c.api) {
		return c.quadrupleAndAddLazyConstrained(accumulator, selectedPoint)
	}
	g := QuadrupleAndAddLazy{
		AccX: accumulator.X.Limbs(), AccY: accumulator.Y.Limbs(),
		SelectedX: selectedPoint.X.Limbs(), SelectedY: selectedPoint.Y.Limbs(),
		AccXBounds: accumulator.X.Bounds(), AccYBounds: accumulator.Y.Bounds(),
		SelectedXBounds: selectedPoint.X.Bounds(), SelectedYBounds: selectedPoint.Y.Bounds(),
	}
	return c.pointFromGadget(g, abstractor.Call2(c.api, g))
}

// Triple is triple: 3·P by a tangent and a return chord.
type Triple struct {
	X, Y             []frontend.Variable
	XBounds, YBounds []*big.Int
}

func (g Triple) DefineGadget(api frontend.API) interface{} {
	c := newCurve(api)
	out := c.tripleConstrained(&point{X: c.fp.FromBounds(g.X, g.XBounds), Y: c.fp.FromBounds(g.Y, g.YBounds)})
	recordOutputs(g, out.X, out.Y)
	return pointLimbs(out)
}

func (c *curve) triple(p *point) *point {
	if !abstractor.Extracting(c.api) {
		return c.tripleConstrained(p)
	}
	g := Triple{X: p.X.Limbs(), Y: p.Y.Limbs(), XBounds: p.X.Bounds(), YBounds: p.Y.Bounds()}
	return c.pointFromGadget(g, abstractor.Call2(c.api, g))
}

// Add is add: incomplete affine P + Q for distinct x-coordinates.
type Add struct {
	PX, PY, QX, QY                         []frontend.Variable
	PXBounds, PYBounds, QXBounds, QYBounds []*big.Int
}

func (g Add) DefineGadget(api frontend.API) interface{} {
	c := newCurve(api)
	p := &point{X: c.fp.FromBounds(g.PX, g.PXBounds), Y: c.fp.FromBounds(g.PY, g.PYBounds)}
	q := &point{X: c.fp.FromBounds(g.QX, g.QXBounds), Y: c.fp.FromBounds(g.QY, g.QYBounds)}
	out := c.addConstrained(p, q)
	recordOutputs(g, out.X, out.Y)
	return pointLimbs(out)
}

func (c *curve) add(p, q *point) *point {
	if !abstractor.Extracting(c.api) {
		return c.addConstrained(p, q)
	}
	g := Add{
		PX: p.X.Limbs(), PY: p.Y.Limbs(), QX: q.X.Limbs(), QY: q.Y.Limbs(),
		PXBounds: p.X.Bounds(), PYBounds: p.Y.Bounds(), QXBounds: q.X.Bounds(), QYBounds: q.Y.Bounds(),
	}
	return c.pointFromGadget(g, abstractor.Call2(c.api, g))
}

// AssertLadderOutputDistinct is assertLadderOutputDistinct: the ladder step
// output differs from its table point, ChordSlope and SecondSlope being
// balanced slopes.
type AssertLadderOutputDistinct struct {
	ChordSlope, SecondSlope             []frontend.Variable
	ChordSlopeBounds, SecondSlopeBounds []*big.Int
}

func (g AssertLadderOutputDistinct) DefineGadget(api frontend.API) interface{} {
	c := newCurve(api)
	c.assertLadderOutputDistinctConstrained(c.fp.FromBounds(g.ChordSlope, g.ChordSlopeBounds), c.fp.FromBounds(g.SecondSlope, g.SecondSlopeBounds))
	return nil
}

func (c *curve) assertLadderOutputDistinct(chordSlope, secondSlope *fpElement) {
	if !abstractor.Extracting(c.api) {
		c.assertLadderOutputDistinctConstrained(chordSlope, secondSlope)
		return
	}
	abstractor.CallVoid(c.api, AssertLadderOutputDistinct{
		ChordSlope: chordSlope.Limbs(), SecondSlope: secondSlope.Limbs(),
		ChordSlopeBounds: chordSlope.Bounds(), SecondSlopeBounds: secondSlope.Bounds(),
	})
}

// AssertDistinctX is assertDistinctX: canonical P and Q differ.
type AssertDistinctX struct {
	P, Q             []frontend.Variable
	PBounds, QBounds []*big.Int
}

func (g AssertDistinctX) DefineGadget(api frontend.API) interface{} {
	c := newCurve(api)
	c.assertDistinctXConstrained(c.fp.FromBounds(g.P, g.PBounds), c.fp.FromBounds(g.Q, g.QBounds))
	return nil
}

func (c *curve) assertDistinctX(p, q *fpElement) {
	if !abstractor.Extracting(c.api) {
		c.assertDistinctXConstrained(p, q)
		return
	}
	abstractor.CallVoid(c.api, AssertDistinctX{P: p.Limbs(), Q: q.Limbs(), PBounds: p.Bounds(), QBounds: q.Bounds()})
}
