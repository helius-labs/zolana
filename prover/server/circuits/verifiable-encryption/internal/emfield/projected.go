package emfield

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// Two product projections share n diagonal products and one rank-one product.
// For aligned quadratic CRT factors, nil left/right forms instead select the
// cached CRT products, preserving reuse with full coefficients.
type projectionPair struct {
	left, right [][]*big.Int
	native, low []*big.Int
}

type projectionKey struct {
	a, b *Element
	end  int
}
type projectedValue struct{ native, low frontend.Variable }
type nativeMatrix [][]*big.Int

func newMatrix(rows, cols int) nativeMatrix {
	m := make(nativeMatrix, rows)
	for i := range m {
		m[i] = make([]*big.Int, cols)
		for j := range m[i] {
			m[i][j] = new(big.Int)
		}
	}
	return m
}

func matrixMultiply(a, b nativeMatrix, q *big.Int) nativeMatrix {
	c := newMatrix(len(a), len(b[0]))
	for i := range c {
		for j := range c[i] {
			for k := range b {
				c[i][j].Add(c[i][j], new(big.Int).Mul(a[i][k], b[k][j]))
			}
			c[i][j].Mod(c[i][j], q)
		}
	}
	return c
}

func matrixInverse(a nativeMatrix, q *big.Int) nativeMatrix {
	n := len(a)
	rows := newMatrix(n, 2*n)
	for i := range rows {
		for j := 0; j < n; j++ {
			rows[i][j].Set(a[i][j])
		}
		rows[i][n+i].SetInt64(1)
	}
	for col := 0; col < n; col++ {
		pivot := -1
		for i := col; i < n; i++ {
			if rows[i][col].Sign() != 0 {
				pivot = i
				break
			}
		}
		if pivot < 0 {
			return nil
		}
		rows[col], rows[pivot] = rows[pivot], rows[col]
		scale := new(big.Int).ModInverse(rows[col][col], q)
		for _, v := range rows[col] {
			v.Mul(v, scale).Mod(v, q)
		}
		for i := range rows {
			if i == col {
				continue
			}
			scale := new(big.Int).Set(rows[i][col])
			for j, v := range rows[i] {
				v.Sub(v, new(big.Int).Mul(scale, rows[col][j])).Mod(v, q)
			}
		}
	}
	for i := range rows {
		rows[i] = rows[i][n:]
	}
	return rows
}

// For distinct d_i, let r_i=(M1-d_i*M0)^-1*u, with u a unit vector.
// Putting those columns in R gives M1*R=M0*R*diag(d_i)+u*1^T.
// For x=(M0*R)^T*a and y=R^-1*b, the two projections are
// sum_i x_i*y_i and sum_i d_i*x_i*y_i + a[seed]*sum_i y_i.
func (s *plainState) projectionBasis(f *Field, end int) *projectionPair {
	if s.projections == nil {
		s.projections = map[int]*projectionPair{}
	}
	if pair, ok := s.projections[end]; ok {
		return pair
	}
	n, bits := f.lay.NbLimbs, f.lay.LimbBits
	q := f.api.Compiler().Field()
	if crt := s.crtBasis(f, q); crt != nil && crt.quadratic {
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
	fold := s.fold(n, 2*n-2)
	projection := func(limit int) nativeMatrix {
		m := newMatrix(n, n)
		for i := range m {
			for j := range m[i] {
				for k := 0; k < limit; k++ {
					m[i][j].Add(m[i][j], new(big.Int).Mul(fold[i+j][k], pow2(bits*k)))
				}
				m[i][j].Mod(m[i][j], q)
			}
		}
		return m
	}
	m0, m1 := projection(n), projection(end)
	// Keep the full-product fallback for singular or noncyclic pencils.
	s.projections[end] = nil
	if matrixInverse(m0, q) == nil {
		return nil
	}
	var nodes []*big.Int
	var inverses []nativeMatrix
	// Over a field larger than 2n, the degree-n determinant leaves n usable nodes.
	for d := 0; d < 2*n && len(nodes) < n; d++ {
		node := big.NewInt(int64(d))
		pencil := newMatrix(n, n)
		for i := range pencil {
			for j := range pencil[i] {
				pencil[i][j].Sub(m1[i][j], new(big.Int).Mul(node, m0[i][j])).Mod(pencil[i][j], q)
			}
		}
		if inv := matrixInverse(pencil, q); inv != nil {
			nodes = append(nodes, node)
			inverses = append(inverses, inv)
		}
	}
	if len(nodes) != n {
		return nil
	}
	for seed := 0; seed < n; seed++ {
		r := newMatrix(n, n)
		for i := range r {
			for j := range r[i] {
				r[i][j].Set(inverses[j][i][seed])
			}
		}
		right := matrixInverse(r, q)
		if right == nil {
			continue
		}
		left := matrixMultiply(m0, r, q)
		pair := &projectionPair{left: make([][]*big.Int, n+1), right: make([][]*big.Int, n+1), native: make([]*big.Int, n+1), low: make([]*big.Int, n+1)}
		for k := 0; k <= n; k++ {
			pair.left[k] = make([]*big.Int, n)
			pair.right[k] = make([]*big.Int, n)
			pair.native[k], pair.low[k] = new(big.Int), new(big.Int)
			for i := 0; i < n; i++ {
				pair.left[k][i], pair.right[k][i] = new(big.Int), new(big.Int)
				if k < n {
					pair.left[k][i].Set(left[i][k])
					pair.right[k][i].Set(right[k][i])
				} else {
					for j := 0; j < n; j++ {
						pair.right[k][i].Add(pair.right[k][i], right[j][i])
					}
					pair.right[k][i].Mod(pair.right[k][i], q)
				}
			}
			if k < n {
				pair.native[k].SetInt64(1)
				pair.low[k].Set(nodes[k])
			} else {
				pair.left[k][seed].SetInt64(1)
				pair.low[k].SetInt64(1)
			}
		}
		// Check every basis coefficient: an exact tensor identity over Fq.
		for which, expected := range []nativeMatrix{m0, m1} {
			coeffs := pair.native
			if which == 1 {
				coeffs = pair.low
			}
			for i := range expected {
				for j, want := range expected[i] {
					got := new(big.Int)
					for k, coef := range coeffs {
						v := new(big.Int).Mul(pair.left[k][i], pair.right[k][j])
						got.Add(got, v.Mul(v, coef))
					}
					if got.Mod(got, q).Cmp(want) != 0 {
						panic("projected product tensor mismatch")
					}
				}
			}
		}
		s.projections[end] = pair
		return pair
	}
	return nil
}

func (f *Field) pairProjectedForms(terms []term, degree int, fold [][]*big.Int, end int) (*linForm, *linForm) {
	q, n := f.api.Compiler().Field(), f.lay.NbLimbs
	pair := f.plain.projectionBasis(f, end)
	if pair == nil {
		return nil, nil
	}
	crt := f.plain.crtBasis(f, q)
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
					native.add(f.api.Mul(scalar, innerNative.build(f.api)), t.coef)
					low.add(f.api.Mul(scalar, innerLow.build(f.api)), t.coef)
					continue
				}
			}
		}
		if len(t.factors) != 2 || len(t.factors[0].limbs) != n || len(t.factors[1].limbs) != n {
			fallback = append(fallback, t)
			continue
		}
		a, b := t.factors[0], t.factors[1]
		if pair.left == nil {
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
			continue
		}
		combine := crt.combine
		offset := 0
		if a == b {
			combine = crt.squareCombine
			offset = len(crt.forms)
		}
		cached := true
		for k := range combine[0] {
			_, ok := f.plain.crtProducts[productKey{a, b, offset + k}]
			_, reverse := f.plain.crtProducts[productKey{b, a, offset + k}]
			if !ok && !reverse {
				cached = false
				break
			}
		}
		if cached {
			// The full coefficient forms reuse those cached products below.
			fallback = append(fallback, t)
			continue
		}
		if f.plain.projectedProducts == nil {
			f.plain.projectedProducts = map[projectionKey]projectedValue{}
		}
		key := projectionKey{a, b, end}
		value, ok := f.plain.projectedProducts[key]
		if !ok {
			value, ok = f.plain.projectedProducts[projectionKey{b, a, end}]
		}
		if !ok {
			sum0, sum1 := newLinForm(), newLinForm()
			for k := range pair.left {
				lf, rf := newLinForm(), newLinForm()
				for j := range a.limbs {
					lf.add(a.limbs[j], pair.left[k][j])
					rf.add(b.limbs[j], pair.right[k][j])
				}
				v := f.api.Mul(lf.build(f.api), rf.build(f.api))
				sum0.add(v, pair.native[k])
				sum1.add(v, pair.low[k])
			}
			value = projectedValue{sum0.build(f.api), sum1.build(f.api)}
			f.plain.projectedProducts[key] = value
		}
		native.add(value.native, t.coef)
		low.add(value.low, t.coef)
	}
	if len(fallback) > 0 {
		forms := f.foldedForms(fallback, degree, fold)
		for j := 0; j < n; j++ {
			mergeForm(native, forms(j), pow2(f.lay.LimbBits*j))
			if j < end {
				mergeForm(low, forms(j), pow2(f.lay.LimbBits*j))
			}
		}
	}
	return native, low
}
