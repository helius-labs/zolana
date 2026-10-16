package shortchecker

import (
	"errors"
	"math/big"
	"sync"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
)

var generatorTablesMu sync.Mutex
var generatorTables = map[int][][]hostPoint{}

// MultiplyBase returns the Montgomery coordinate [8*s]G, where G has u=9.
// bits is the 252-bit quotient of a clamped X25519 scalar, with top bit one.
// Its caller constrains the bits. The fixed tables use H=[4]G and centered
// odd digits D_i=2*d_i-(2^w-1), plus C=[2^252-1]H. Thus C+sum D_i*2^i H
// equals [2*s]H=[8*s]G without a scalar-recoding hint.
func MultiplyBase(api frontend.API, f *emfield.Field, bits []frontend.Variable) *emfield.Element {
	return multiplyBaseWindow(api, f, bits, 7)
}

// multiplyBaseWindow evaluates the fixed-base sum for a clamped scalar quotient.
// The caller must constrain all 252 input bits. The top bit is asserted here.
// Public tables and the scalar-interval argument in baseAdd exclude infinity
// and exceptional intermediate additions for every allowed scalar.
func multiplyBaseWindow(api frontend.API, f *emfield.Field, bits []frontend.Variable, window int) *emfield.Element {
	// 1. Check public dimensions and constrain the clamped scalar's top bit.
	if len(bits) != 252 || window < 2 || window > 10 {
		panic("x25519: invalid fixed-base scalar or window")
	}
	api.AssertIsEqual(bits[251], 1)
	// 2. Construct the curve and its witness-independent constant tables.
	a, b := coefficients(false)
	c := &curve{api: api, fp: f, lay: f.Layout(), a: f.Const(a), b: f.Const(b)}
	tables := generatorWindowTables(window)
	var acc *point
	// 3. Select and accumulate each digit, using the unified final-addition check.
	for i, start := 0, 0; start < len(bits); i, start = i+1, start+window {
		end := min(start+window, len(bits))
		selected := c.baseSelect(tables[i], bits[start:end], i != 0)
		if acc == nil {
			acc = selected
		} else if end == len(bits) {
			acc = &point{X: c.baseFinalAddX(acc, selected)}
		} else {
			acc = c.baseAdd(acc, selected)
		}
	}
	// 4. Undo the coordinate translation to obtain the Montgomery public key.
	return f.EvalProjected(T(1, acc.X), T(-1, f.Const(offset())))
}

// baseAdd computes a nonfinal fixed-base addition with a unique chord.
// After consuming m low bits, the accumulator is
// [2^252-2^m+2*s_low]H. For m<252 its coefficient is positive, even and
// below 2*L, so it cannot be zero modulo the odd prime L. Before any
// nonfinal addition the difference from the selected point has the same
// properties, ruling out an equal-X denominator. In the final addition
// equality is possible, but opposites are not. baseFinalAddX handles it.
func (c *curve) baseAdd(p, q *point) *point {
	f := c.fp
	// 1. Bind the chord using the scalar-interval guarantee of distinct X.
	l := c.ratio(f.Sub(q.Y, p.Y), f.Sub(q.X, p.X))
	// 2. Carry the affine result as bounded lazy expressions.
	x := f.Lazy(T(1, l, l), T(-1, p.X), T(-1, q.X))
	y := f.Lazy(T(1, l, f.Sub(p.X, x)), T(-1, p.Y))
	return &point{X: x, Y: y}
}

// baseFinalAddX computes the final sum's X coordinate with chord and tangent
// equations enforced together. Its inputs must be on the curve. The fixed-base
// scalar interval excludes opposites but permits equal points, for which the
// second equation uniquely fixes the tangent.
func (c *curve) baseFinalAddX(p, q *point) *fpElement {
	f := c.fp
	// 1. Obtain an untrusted final slope.
	l := f.HintBalanced(baseFinalSlopeHint, 1, nil, p.X, p.Y, q.X, q.Y, c.a)[0]
	// The chord and sum equations hold simultaneously. When X differs,
	// the first fixes the slope. At equal points the second is the tangent.
	// 2. Bind both equations so equal inputs require the tangent as well.
	f.AssertZeroProjected(T(1, l, f.Sub(q.X, p.X)), T(-1, q.Y), T(1, p.Y))
	f.AssertZeroProjected(T(1, l, f.Add(p.Y, q.Y)), T(-1, p.X, p.X), T(-1, p.X, q.X), T(-1, q.X, q.X), T(-1, c.a))
	// 3. Compute only X, the coordinate exposed by the X25519 public key.
	return f.Lazy(T(1, l, l), T(-1, p.X), T(-1, q.X))
}

// init registers the untrusted final-slope witness. baseFinalAddX constrains
// it with both chord and tangent-compatible equations.
func init() { solver.RegisterHint(baseFinalSlopeHint) }

// baseFinalSlopeHint proposes a chord or tangent for the final fixed-base sum.
// The circuit checks both equations and does not trust the hint's case split.
func baseFinalSlopeHint(q *big.Int, in, out []*big.Int) error {
	return emfield.Unwrap(q, in, out, func(p *big.Int, n, v, o []*big.Int) error {
		// 1. Check the hint shape.
		if len(n) != 0 || len(v) != 5 || len(o) != 1 {
			return errors.New("x25519: fixed-base final slope shape")
		}
		// 2. Propose the tangent for equal X, otherwise the ordinary chord.
		dx := new(big.Int).Sub(v[2], v[0])
		dx.Mod(dx, p)
		if dx.Sign() == 0 {
			numerator := new(big.Int).Mul(v[0], v[0])
			numerator.Mul(numerator, big.NewInt(3)).Add(numerator, v[4])
			o[0].Set(modRatio(p, numerator, new(big.Int).Lsh(v[1], 1)))
		} else {
			o[0].Set(modRatio(p, new(big.Int).Sub(v[3], v[1]), dx))
		}
		return nil
	})
}

// generatorWindowTables constructs and caches public centered odd-digit tables.
// The first table includes [2^252-1]H with H=[4]G. All entries are computed
// from the fixed generator, not witness data. Infinity entries are rejected.
// Returned tables are shared compile-time constants and must not be mutated.
func generatorWindowTables(window int) [][]hostPoint {
	// 1. Serialize construction and reuse only tables for the same window.
	generatorTablesMu.Lock()
	defer generatorTablesMu.Unlock()
	if tables, ok := generatorTables[window]; ok {
		return tables
	}
	// 2. Lift u=9, derive H=[4]G and the fixed centering offset.
	p := prime()
	a, _ := coefficients(false)
	u := big.NewInt(9)
	y2 := new(big.Int).Mul(u, u)
	y2.Add(y2, new(big.Int).Mul(big.NewInt(486662), u)).Add(y2, big.NewInt(1)).Mul(y2, u).Mod(y2, p)
	y := new(big.Int).ModSqrt(y2, p)
	if y == nil {
		panic("x25519: generator has no curve lift")
	}
	g := hostPoint{new(big.Int).Mod(new(big.Int).Add(u, offset()), p), y}
	h := hostMul(g, big.NewInt(4), a)
	constant := hostMul(h, new(big.Int).Sub(pow2(252), big.NewInt(1)), a)
	var tables [][]hostPoint
	base := h
	// 3. Enumerate signed odd multiples, folding the offset into the first table.
	for start := 0; start < 252; start += window {
		width := min(window, 252-start)
		double := hostAdd(base, base, a)
		positive := make([]hostPoint, 1<<(width-1))
		positive[0] = base
		for i := 1; i < len(positive); i++ {
			positive[i] = hostAdd(positive[i-1], double, a)
		}
		table := make([]hostPoint, 1<<width)
		for i := range table {
			digit := 2*i - (1 << width) + 1
			negative := digit < 0
			if negative {
				digit = -digit
			}
			q := positive[(digit-1)/2]
			if negative {
				q = hostPoint{q.x, new(big.Int).Sub(p, q.y)}
			}
			if start == 0 {
				q = hostAdd(constant, q, a)
			}
			if q.x == nil {
				panic("x25519: fixed-base table reached infinity")
			}
			table[i] = q
		}
		tables = append(tables, table)
		for i := 0; i < window; i++ {
			base = hostAdd(base, base, a)
		}
	}
	// 4. Cache the immutable public constants for subsequent circuit construction.
	generatorTables[window] = tables
	return tables
}

// baseOneHot expands caller-constrained Boolean bits into one-hot weights.
// Exactly one weight is one, binding subsequent selection to a single table
// entry without an additional range check on each selected coordinate.
func baseOneHot(api frontend.API, bits []frontend.Variable) []frontend.Variable {
	// Start with the unit weight and split it by each already Boolean selector.
	flags := []frontend.Variable{1}
	for _, bit := range bits {
		next := make([]frontend.Variable, len(flags)*2)
		for i, flag := range flags {
			hi := api.Mul(flag, bit)
			next[i], next[i+len(flags)] = api.Sub(flag, hi), hi
		}
		flags = next
	}
	return flags
}

// baseSelect selects a fixed-base point using caller-constrained Boolean bits.
// Optional sign folding uses table symmetry. One-hot selection of public
// constants justifies the packed coordinate bounds recorded with WithBounds.
// Those bounds are metadata, not independent range constraints.
func (c *curve) baseSelect(points []hostPoint, bits []frontend.Variable, foldSign bool) *point {
	// 1. Fold sign symmetry when the table has no centering offset.
	api, f := c.api, c.fp
	sign := frontend.Variable(1)
	if foldSign {
		sign = bits[len(bits)-1]
		magnitude := make([]frontend.Variable, len(bits)-1)
		for i := range magnitude {
			magnitude[i] = api.Select(sign, bits[i], api.Sub(1, bits[i]))
		}
		bits = magnitude
		points = points[len(points)/2:]
	}
	// 2. Choose a public row/column split to minimize selection constraints.
	n, limbBits := c.lay.NbLimbs, c.lay.LimbBits
	columns := (n+1)/2 + (n+2)/3
	hotCost := func(k int) int {
		if k < 2 {
			return 0
		}
		return (1 << k) - k - 1
	}
	rowBits, best := 0, hotCost(len(bits))
	for k := 1; k <= len(bits); k++ {
		if cost := hotCost(k) + hotCost(len(bits)-k) + (1<<k)*columns; cost < best {
			rowBits, best = k, cost
		}
	}
	// 3. Select packed coordinate constants with one-hot row and column weights.
	rows, cols := baseOneHot(api, bits[:rowBits]), baseOneHot(api, bits[rowBits:])
	pack := func(group int, coordinate func(hostPoint) *big.Int) *fpElement {
		limbs := make([]frontend.Variable, n)
		lo, hi := make([]*big.Int, n), make([]*big.Int, n)
		for i := range limbs {
			limbs[i] = 0
			lo[i] = new(big.Int)
			hi[i] = new(big.Int)
			if i%group != 0 {
				continue
			}
			width := min(group*limbBits, 255-i*limbBits)
			mask := new(big.Int).Sub(pow2(width), big.NewInt(1))
			value := frontend.Variable(0)
			for row, rf := range rows {
				inner := frontend.Variable(0)
				for col, cf := range cols {
					v := new(big.Int).Rsh(coordinate(points[row+col*len(rows)]), uint(i*limbBits))
					v.And(v, mask)
					inner = api.Add(inner, api.Mul(cf, v))
				}
				value = api.Add(value, api.Mul(rf, inner))
			}
			limbs[i] = value
			hi[i] = mask
		}
		return f.WithBounds(limbs, lo, hi)
	}
	x := pack(2, func(p hostPoint) *big.Int { return p.x })
	y := pack(3, func(p hostPoint) *big.Int { return p.y })
	// 4. Restore the selected sign without changing curve membership.
	if foldSign {
		y = f.Select(sign, y, f.Neg(y))
	}
	return &point{X: x, Y: y}
}
