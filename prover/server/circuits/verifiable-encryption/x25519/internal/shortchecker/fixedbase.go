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
	window := 7
	if !f.Layout().Lookups {
		window = 10
	}
	return multiplyBaseWindow(api, f, bits, window)
}

func multiplyBaseWindow(api frontend.API, f *emfield.Field, bits []frontend.Variable, window int) *emfield.Element {
	if len(bits) != 252 || window < 2 || window > 10 {
		panic("x25519: invalid fixed-base scalar or window")
	}
	api.AssertIsEqual(bits[251], 1)
	a, b := coefficients(false)
	c := &curve{api: api, fp: f, lay: f.Layout(), a: f.Const(a), b: f.Const(b)}
	tables := generatorWindowTables(window)
	var acc *point
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
	return f.EvalProjected(T(1, acc.X), T(-1, f.Const(offset())))
}

// After consuming m low bits, the accumulator is
// [2^252-2^m+2*s_low]H. For m<252 its coefficient is positive, even and
// below 2*L, so it cannot be zero modulo the odd prime L. Before any
// nonfinal addition the difference from the selected point has the same
// properties, ruling out an equal-X denominator. In the final addition
// equality is possible, but opposites are not; baseFinalAddX handles it.
func (c *curve) baseAdd(p, q *point) *point {
	f := c.fp
	l := c.ratio(f.Sub(q.Y, p.Y), f.Sub(q.X, p.X))
	x := f.Lazy(T(1, l, l), T(-1, p.X), T(-1, q.X))
	y := f.Lazy(T(1, l, f.Sub(p.X, x)), T(-1, p.Y))
	return &point{X: x, Y: y}
}

// The final addition may have equal inputs, but its known scalar interval
// excludes opposite inputs. Only the resulting X coordinate is consumed.
func (c *curve) baseFinalAddX(p, q *point) *fpElement {
	f := c.fp
	l := f.HintBalanced(baseFinalSlopeHint, 1, nil, p.X, p.Y, q.X, q.Y, c.a)[0]
	// The chord and sum equations hold simultaneously. When X differs,
	// the first fixes the slope; at equal points the second is the tangent.
	f.AssertZeroProjected(T(1, l, f.Sub(q.X, p.X)), T(-1, q.Y), T(1, p.Y))
	f.AssertZeroProjected(T(1, l, f.Add(p.Y, q.Y)), T(-1, p.X, p.X), T(-1, p.X, q.X), T(-1, q.X, q.X), T(-1, c.a))
	return f.Lazy(T(1, l, l), T(-1, p.X), T(-1, q.X))
}

func init() { solver.RegisterHint(baseFinalSlopeHint) }

func baseFinalSlopeHint(q *big.Int, in, out []*big.Int) error {
	return emfield.Unwrap(q, in, out, func(p *big.Int, n, v, o []*big.Int) error {
		if len(n) != 0 || len(v) != 5 || len(o) != 1 {
			return errors.New("x25519: fixed-base final slope shape")
		}
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

func generatorWindowTables(window int) [][]hostPoint {
	generatorTablesMu.Lock()
	defer generatorTablesMu.Unlock()
	if tables, ok := generatorTables[window]; ok {
		return tables
	}
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
	generatorTables[window] = tables
	return tables
}

func baseOneHot(api frontend.API, bits []frontend.Variable) []frontend.Variable {
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

func (c *curve) baseSelect(points []hostPoint, bits []frontend.Variable, foldSign bool) *point {
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
	if foldSign {
		y = f.Select(sign, y, f.Neg(y))
	}
	return &point{X: x, Y: y}
}
