package emcurve

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

// Extraction gadgets. Each wrapper below calls the original curve method on
// a constraint builder and the gadget only under the Lean extractor, so the
// production constraint system is untouched. Under the extractor the gadget
// rebuilds its elements from limbs plus the encoded bounds of the caller's
// elements, which reproduces every bound-dependent choice of the original
// call. Products the builder caches across calls are recomputed inside a
// gadget; those are functional gates, so the extracted relation is the same.

// RowLookup stands for a log-derivative row lookup of Rows[Index]. It exists
// only for Lean extraction, where the deferred lookup argument becomes the
// opaque predicate RowLookup_<columns>_<rows> with an explicit soundness
// assumption.
type RowLookup struct {
	Rows  [][]frontend.Variable
	Index frontend.Variable
}

func (RowLookup) DefineGadget(frontend.API) interface{} { panic("extraction-only") }

func (g RowLookup) OpaqueOutputs() int {
	if len(g.Rows) == 0 {
		panic("row lookup without rows")
	}
	return len(g.Rows[0])
}

// fieldOps routes the polynomial checks of every curve method through the
// CheckPolynomial and Lazy extraction gadgets; on a builder they are the
// plain Field methods.
type fieldOps struct {
	*emfield.Field
}

func (f *fieldOps) Eval(terms ...emfield.Term) *fpElement { return f.GadgetEval(terms...) }

func (f *fieldOps) AssertZero(terms ...emfield.Term) { f.GadgetAssertZero(terms...) }

func (f *fieldOps) Lazy(terms ...emfield.Term) *fpElement { return f.GadgetLazy(terms...) }

const (
	baseField  = 0
	orderField = 1
)

func (c *curve) field(id int) *fieldOps {
	if id == orderField {
		return c.fr
	}
	return c.fp
}

func (c *curve) fieldID(f *fieldOps) int {
	if f == c.fr {
		return orderField
	}
	return baseField
}

func (c *curve) reducedPoint(coordinates [][]frontend.Variable) *point {
	if len(coordinates) != 2 {
		panic("expecting two coordinates")
	}
	return &point{X: c.fp.Reduced(coordinates[0]), Y: c.fp.Reduced(coordinates[1])}
}

// requireReduced panics unless both coordinates carry exactly the reduced
// layout bounds the wrappers attach to gadget outputs.
func (c *curve) requireReduced(p *point) [][]frontend.Variable {
	if !emfield.SameBounds(p.X, c.fp.Reduced(p.X.Limbs())) || !emfield.SameBounds(p.Y, c.fp.Reduced(p.Y.Limbs())) {
		panic("gadget output is not a reduced point")
	}
	return [][]frontend.Variable{p.X.Limbs(), p.Y.Limbs()}
}

// ScalarMulChecked is scalarMulChecked: R = [s]Q for an on-curve Q.
type ScalarMulChecked struct {
	PointX, PointY, Scalar []frontend.Variable
	PointXBounds           []*big.Int
	PointYBounds           []*big.Int
	ScalarBounds           []*big.Int
	Lookups                bool
}

func (g ScalarMulChecked) DefineGadget(api frontend.API) interface{} {
	c := newCurveFor(api, g.Lookups)
	p := &point{X: c.fp.FromBounds(g.PointX, g.PointXBounds), Y: c.fp.FromBounds(g.PointY, g.PointYBounds)}
	return c.requireReduced(c.scalarMulChecked(p, c.fr.FromBounds(g.Scalar, g.ScalarBounds)))
}

func (c *curve) scalarMulCheckedAt(p *point, s *frElement) *point {
	if !abstractor.Extracting(c.api) {
		return c.scalarMulChecked(p, s)
	}
	return c.reducedPoint(abstractor.Call2(c.api, ScalarMulChecked{
		PointX: p.X.Limbs(), PointY: p.Y.Limbs(), Scalar: s.Limbs(),
		PointXBounds: p.X.Bounds(), PointYBounds: p.Y.Bounds(), ScalarBounds: s.Bounds(),
		Lookups: c.layout.Lookups,
	}))
}

// ScalarMulBase is scalarMulBase: E = [s]G on the fixed-base comb.
type ScalarMulBase struct {
	Scalar       []frontend.Variable
	ScalarBounds []*big.Int
	Lookups      bool
}

func (g ScalarMulBase) DefineGadget(api frontend.API) interface{} {
	c := newCurveFor(api, g.Lookups)
	return c.requireReduced(c.scalarMulBase(c.fr.FromBounds(g.Scalar, g.ScalarBounds)))
}

func (c *curve) scalarMulBaseAt(s *frElement) *point {
	if !abstractor.Extracting(c.api) {
		return c.scalarMulBase(s)
	}
	return c.reducedPoint(abstractor.Call2(c.api, ScalarMulBase{Scalar: s.Limbs(), ScalarBounds: s.Bounds(), Lookups: c.layout.Lookups}))
}

// AssertOnCurve is assertOnCurve: y^2 = x^3 - 3x + b modulo p.
type AssertOnCurve struct {
	X, Y             []frontend.Variable
	XBounds, YBounds []*big.Int
	Lookups          bool
}

func (g AssertOnCurve) DefineGadget(api frontend.API) interface{} {
	c := newCurveFor(api, g.Lookups)
	c.assertOnCurve(&point{X: c.fp.FromBounds(g.X, g.XBounds), Y: c.fp.FromBounds(g.Y, g.YBounds)})
	return nil
}

func (c *curve) assertOnCurveAt(p *point) {
	if !abstractor.Extracting(c.api) {
		c.assertOnCurve(p)
		return
	}
	abstractor.CallVoid(c.api, AssertOnCurve{X: p.X.Limbs(), Y: p.Y.Limbs(), XBounds: p.X.Bounds(), YBounds: p.Y.Bounds(), Lookups: c.layout.Lookups})
}

// AssertCanonical is Field.AssertCanonical: the limbs encode a value below the
// modulus of Field (0: base field p, 1: group order n).
type AssertCanonical struct {
	Limbs   []frontend.Variable
	Bounds  []*big.Int
	Field   int
	Lookups bool
}

func (g AssertCanonical) DefineGadget(api frontend.API) interface{} {
	c := newCurveFor(api, g.Lookups)
	f := c.field(g.Field)
	f.AssertCanonical(f.FromBounds(g.Limbs, g.Bounds))
	return nil
}

func (c *curve) assertCanonical(f *fieldOps, e *fpElement) {
	if !abstractor.Extracting(c.api) {
		f.AssertCanonical(e)
		return
	}
	abstractor.CallVoid(c.api, AssertCanonical{Limbs: e.Limbs(), Bounds: e.Bounds(), Field: c.fieldID(f), Lookups: c.layout.Lookups})
}

// SplitLowBits is splitLowBits: V = high * 2^LowBits + low with
// high < 2^(TotalBits-LowBits) and low < 2^LowBits. It returns [high, low].
type SplitLowBits struct {
	V         frontend.Variable
	LowBits   int
	TotalBits int
	Lookups   bool
}

func (g SplitLowBits) DefineGadget(api frontend.API) interface{} {
	c := newCurveFor(api, g.Lookups)
	high, low := c.splitLowBitsConstrained(g.V, g.LowBits, g.TotalBits)
	return []frontend.Variable{high, low}
}

// CompressedPacking is compressedPacking over canonical coordinate limbs. It
// returns [lo, hi].
type CompressedPacking struct {
	XLimbs, YLimbs []frontend.Variable
	LimbBits       int
	Lookups        bool
}

func (g CompressedPacking) DefineGadget(api frontend.API) interface{} {
	c := newCurveFor(api, g.Lookups)
	lo, hi := c.compressedPackingConstrained(g.XLimbs, g.YLimbs, g.LimbBits)
	return []frontend.Variable{lo, hi}
}
