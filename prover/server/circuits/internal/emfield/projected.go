package emfield

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// The native and low projections of an aligned quadratic CRT product reuse its
// cached products, so a later full multiplication shares them.
type projectionPair struct {
	native, low []*big.Int
}

func (s *arithmeticState) projectionBasis(f *Field, end int) *projectionPair {
	if s.projections == nil {
		s.projections = map[int]*projectionPair{}
	}
	if pair, ok := s.projections[end]; ok {
		return pair
	}
	bits := f.layout.LimbBits
	q := f.api.Compiler().Field()
	crt := s.crtBasis(f, q)
	if crt == nil || !crt.quadratic {
		s.projections[end] = nil
		return nil
	}
	pair := &projectionPair{native: make([]*big.Int, len(crt.forms)), low: make([]*big.Int, len(crt.forms))}
	for k := range crt.forms {
		pair.native[k], pair.low[k] = new(big.Int), new(big.Int)
		for j := range crt.combine {
			v := new(big.Int).Mul(pow2(bits*j), crt.combine[j][k])
			pair.native[k].Add(pair.native[k], v)
			if j < end {
				pair.low[k].Add(pair.low[k], v)
			}
		}
		pair.native[k].Mod(pair.native[k], q)
		pair.low[k].Mod(pair.low[k], q)
	}
	s.projections[end] = pair
	return pair
}

func (f *Field) pairProjectedForms(terms []term, degree int, fold [][]*big.Int, end int) (*linForm, *linForm) {
	q, n := f.api.Compiler().Field(), f.layout.NbLimbs
	pair := f.arithmetic.projectionBasis(f, end)
	if pair == nil {
		return nil, nil
	}
	crt := f.arithmetic.crtBasis(f, q)
	if crt == nil {
		return nil, nil
	}
	native, low := newLinForm(), newLinForm()
	var fallback []term
	for _, t := range terms {
		if len(t.factors) >= 2 {
			// A one-limb element has polynomial degree zero. Pull it outside
			// both projections rather than scaling all folded coefficients.
			var scalar frontend.Variable = 1
			var core []*Element
			for _, e := range t.factors {
				if len(e.limbs) == 1 {
					scalar = f.api.Mul(scalar, e.limbs[0])
				} else {
					core = append(core, e)
				}
			}
			if len(core) != len(t.factors) {
				innerNative, innerLow := f.pairProjectedForms([]term{{coef: big.NewInt(1), factors: core}}, degree, fold, end)
				if innerNative != nil {
					native.add(f.api.Mul(scalar, f.build(innerNative)), t.coef)
					low.add(f.api.Mul(scalar, f.build(innerLow)), t.coef)
					continue
				}
			}
		}
		if len(t.factors) != 2 || len(t.factors[0].limbs) != n || len(t.factors[1].limbs) != n {
			fallback = append(fallback, t)
			continue
		}
		a, b := t.factors[0], t.factors[1]
		if a == b {
			fallback = append(fallback, t)
			continue
		}
		for k := range crt.forms {
			if pair.native[k].Sign() == 0 && pair.low[k].Sign() == 0 {
				continue
			}
			v := f.crtProductAt(crt, a, b, k)
			native.add(v, new(big.Int).Mul(t.coef, pair.native[k]))
			low.add(v, new(big.Int).Mul(t.coef, pair.low[k]))
		}
	}
	if len(fallback) > 0 {
		forms := f.foldedForms(fallback, degree, fold)
		for j := 0; j < n; j++ {
			mergeForm(native, forms(j), pow2(f.layout.LimbBits*j))
			if j < end {
				mergeForm(low, forms(j), pow2(f.layout.LimbBits*j))
			}
		}
	}
	return native, low
}
