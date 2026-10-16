package ed25519

import (
	"errors"
	"math/big"
	"sync"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
)

// Short Weierstrass coordinates keep lazy values and balanced slopes. Signed odd
// digits avoid identity points, and complete Edwards addition fixes zero and even scalars.
type montPoint struct{ x, y *emfield.Element }

var montOffset = new(big.Int).Mod(new(big.Int).Mul(big.NewInt(486662), new(big.Int).ModInverse(big.NewInt(3), fieldPrime())), fieldPrime())
var montScale = new(big.Int).ModSqrt(new(big.Int).Sub(fieldPrime(), big.NewInt(486664)), fieldPrime())
var montA = new(big.Int).Mod(new(big.Int).Sub(big.NewInt(1), new(big.Int).Mul(big.NewInt(486662), montOffset)), fieldPrime())

// Bind the birational map of an on-curve point. Checking the result closes the
// order-two 0/0 case. The identity has no finite image and is rejected.
func (c *curve) montFromEd(p *point) *montPoint {
	fp := c.fp
	// 1 - Reduction preserves residues. Membership must be established separately.
	p = &point{x: fp.EvalProjected(emfield.T(1, p.x)), y: fp.EvalProjected(emfield.T(1, p.y))}
	// 2 - Bind the candidate to the rational map, including its exceptional equations.
	out := fp.Hint(montFromEdHint, 2, nil, p.x, p.y)
	u := fp.Sub(out[0], fp.Const(montOffset))
	fp.AssertZeroProjected(emfield.T(1, u, fp.Sub(c.one, p.y)), emfield.T(-1, c.one), emfield.T(-1, p.y))
	fp.AssertZeroProjected(emfield.T(1, out[1], p.x), emfield.T(-1, fp.Const(montScale), u))
	result := &montPoint{out[0], out[1]}
	// 3 - The order-two input leaves y free in the map. Target membership closes 0/0.
	c.assertMontOnCurve(result)
	return result
}

// Bind the inverse map of an on-curve point so exceptional denominators cannot
// admit an off-curve output. Subgroup policy belongs to the caller.
func (c *curve) edFromMont(p *montPoint) *point {
	fp := c.fp
	// 1 - Bind both coordinates to the same source point.
	out := fp.Hint(edFromMontHint, 2, nil, p.x, p.y)
	u := fp.Sub(p.x, fp.Const(montOffset))
	fp.AssertZeroProjected(emfield.T(1, out[1], fp.Add(u, c.one)), emfield.T(-1, u), emfield.T(1, c.one))
	fp.AssertZeroProjected(emfield.T(1, out[0], p.y), emfield.T(-1, fp.Const(montScale), u))
	result := &point{x: out[0], y: out[1]}
	// 2 - Target membership prevents an exceptional denominator freeing a coordinate.
	c.assertOnCurve(result)
	return result
}

// Reduce coordinate representatives while retaining their residues. This
// uses existing limb bounds and does not establish curve membership.
func (c *curve) montReduce(p *montPoint) *montPoint {
	reduce := func(e *emfield.Element) *emfield.Element {
		if e.IsReduced(c.fp.ReducedWidths()) {
			return e
		}
		return c.fp.EvalProjected(emfield.T(1, e))
	}
	return &montPoint{reduce(p.x), reduce(p.y)}
}

// Use a checked balanced tangent on an on-curve finite point. An order-two
// input has no finite double and cannot satisfy its tangent equation.
func (c *curve) montDouble(p *montPoint) *montPoint {
	fp := c.fp
	l := fp.HintBalanced(montTangentHint, 1, nil, p.x, p.y)[0]
	fp.AssertZeroProjected(emfield.T(2, l, p.y), emfield.T(-3, p.x, p.x), emfield.T(-1, fp.Const(montA)))
	x := fp.Lazy(emfield.T(1, l, l), emfield.T(-2, p.x))
	y := fp.Lazy(emfield.T(1, l, fp.Sub(p.x, x)), emfield.T(-1, p.y))
	return &montPoint{x, y}
}

// Bind a balanced slope and the finite group law on on-curve inputs. With complete
// false, the caller proves unequal x. Complete handles equal points, not opposites.
func (c *curve) montAdd(p, q *montPoint, complete bool) *montPoint {
	fp := c.fp
	var l *emfield.Element
	if complete {
		// Equal finite points use the tangent. The eq*dy certificate rejects
		// opposite points. Honest canonical scalar witnesses never encounter them.
		p = c.montReduce(p)
		q = c.montReduce(q)
		dx := fp.EvalProjected(emfield.T(1, q.x), emfield.T(-1, p.x))
		fp.AssertCanonical(dx)
		eq := c.api.IsZero(c.api.Add(0, 0, dx.Limbs()...))
		e := fp.Bounded([]frontend.Variable{eq}, []int{1})
		dy := fp.Sub(q.y, p.y)
		fp.AssertZeroProjected(emfield.T(1, e, dy))
		l = fp.HintBalanced(montSlopeHint, 1, []frontend.Variable{eq}, p.x, p.y, q.x, q.y)[0]
		fp.AssertZeroProjected(emfield.T(1, l, fp.Sub(q.x, p.x)), emfield.T(2, l, e, p.y), emfield.T(-3, e, p.x, p.x), emfield.T(-1, e, fp.Const(montA)), emfield.T(-1, dy))
	} else {
		l = fp.HintBalanced(montSlopeHint, 1, []frontend.Variable{0}, p.x, p.y, q.x, q.y)[0]
		fp.AssertZeroProjected(emfield.T(1, l, fp.Sub(q.x, p.x)), emfield.T(-1, q.y), emfield.T(1, p.y))
	}
	x := fp.Lazy(emfield.T(1, l, l), emfield.T(-1, p.x), emfield.T(-1, q.x))
	y := fp.Lazy(emfield.T(1, l, fp.Sub(q.x, x)), emfield.T(-1, q.y))
	return &montPoint{x, y}
}

// Bind every signed-odd digit to the reduced scalar modulo L. Callers supply its
// true odd and zero flags. The range argument below lifts this to integer equality.
func (c *curve) recodeValue(s *emfield.Element, odd, zero frontend.Variable, nbits int) ([]frontend.Variable, frontend.Variable, frontend.Variable) {
	api, fr := c.api, c.fr
	inputs := []frontend.Variable{nbits, layout.LimbBits}
	inputs = append(inputs, s.Limbs()...)
	out, err := api.Compiler().NewHint(oddRecodeHint, nbits, inputs...)
	if err != nil {
		panic(err)
	}
	for _, b := range out {
		api.AssertIsBoolean(b)
	}
	api.AssertIsEqual(out[len(out)-1], 1)
	b := fr.Bounded([]frontend.Variable{odd}, []int{1})
	z := fr.Bounded([]frontend.Variable{zero}, []int{1})
	constant := fr.Const(new(big.Int).Sub(big.NewInt(2), pow2(nbits)))
	fr.AssertZero(emfield.T(2, c.fromBits(fr, out)), emfield.T(1, constant), emfield.T(-1, s), emfield.T(-1, b), emfield.T(-2, z))
	// Both sides are positive odd integers below 2^253, so they differ by an even
	// multiple of L below 2L in size, which is zero.
	return out, odd, zero
}

// Undo odd-digit recoding with complete Edwards addition. Inputs must be
// on-curve and odd/zero must be the Boolean flags proved by the recoder.
func (c *curve) correctScalar(p, base *point, odd, zero frontend.Variable) *point {
	fp := c.fp
	// If T=d*x*y is available, one sign controls both correction x and T.
	// odd selects the identity, zero selects -base, otherwise selects base.
	if base.t != nil {
		sign := c.api.Mul(c.api.Sub(1, odd), c.api.Sub(1, c.api.Mul(2, zero)))
		scalar := fp.WithBounds([]frontend.Variable{sign}, []*big.Int{big.NewInt(-1)}, []*big.Int{big.NewInt(1)})
		correction := &point{x: fp.Lazy(emfield.T(1, scalar, base.x)), y: fp.Select(odd, c.one, base.y), t: fp.Lazy(emfield.T(1, scalar, base.t))}
		return c.add(p, correction)
	}
	correction := &point{x: fp.Select(zero, fp.Neg(base.x), base.x), y: base.y}
	correction = &point{x: fp.Select(odd, c.identity().x, correction.x), y: fp.Select(odd, c.one, correction.y)}
	return c.add(p, correction)
}

var montBaseOnce sync.Once
var montBaseWindows [][]hostPoint

// Converts a host Edwards point to Montgomery coordinates for hint computation.
func hostMont(p hostPoint) hostPoint {
	prime := fieldPrime()
	u := ratio(prime, new(big.Int).Add(big.NewInt(1), p.y), new(big.Int).Sub(big.NewInt(1), p.y))
	y := ratio(prime, new(big.Int).Mul(u, montScale), p.x)
	return hostPoint{new(big.Int).Mod(new(big.Int).Add(u, montOffset), prime), y}
}

// Signed odd windows contain opposite pairs with the same Montgomery x.
// Select the positive magnitude, then apply the sign only to its packed y.
func (c *curve) montConstantSelect(points []hostPoint, bits []frontend.Variable) *montPoint {
	if len(bits) < 2 {
		return c.montConstantSelectTable(points, bits)
	}
	positive := bits[len(bits)-1]
	magnitude := make([]frontend.Variable, len(bits)-1)
	for i := range magnitude {
		magnitude[i] = c.api.Select(positive, bits[i], c.api.Sub(1, bits[i]))
	}
	p := c.montConstantSelectTable(points[len(points)/2:], magnitude)
	p.y = c.fp.Select(positive, p.y, c.fp.Neg(p.y))
	return p
}

// Select all coordinate limbs from trusted curve constants. Boolean input
// bits make the one-hot products exclusive, justifying metadata-only bounds.
func (c *curve) montConstantSelectTable(points []hostPoint, bits []frontend.Variable) *montPoint {
	w := len(bits)
	n := layout.NbLimbs
	colsN := (n+2-1)/2 + (n+3-1)/3
	hotcost := func(k int) int {
		if k < 2 {
			return 0
		}
		return (1 << k) - k - 1
	}
	rb, best := 0, hotcost(w)
	for k := 1; k <= w; k++ {
		if cost := hotcost(k) + hotcost(w-k) + (1<<k)*colsN; cost < best {
			rb, best = k, cost
		}
	}
	rows, cols := oneHot(c.api, bits[:rb]), oneHot(c.api, bits[rb:])
	selectV := func(coord func(hostPoint) *big.Int, off, width int) frontend.Variable {
		out := frontend.Variable(0)
		mask := new(big.Int).Sub(pow2(width), big.NewInt(1))
		for i, rf := range rows {
			inner := frontend.Variable(0)
			for j, cf := range cols {
				v := new(big.Int).And(new(big.Int).Rsh(coord(points[i+(j<<rb)]), uint(off)), mask)
				inner = c.api.Add(inner, c.api.Mul(cf, v))
			}
			out = c.api.Add(out, c.api.Mul(rf, inner))
		}
		return out
	}
	pack := func(group int, coord func(hostPoint) *big.Int) *emfield.Element {
		vs := make([]frontend.Variable, n)
		lo, hi := make([]*big.Int, n), make([]*big.Int, n)
		for i := range vs {
			vs[i] = 0
			lo[i] = new(big.Int)
			hi[i] = new(big.Int)
			if i%group == 0 {
				width := min(group*layout.LimbBits, 255-i*layout.LimbBits)
				vs[i] = selectV(coord, i*layout.LimbBits, width)
				hi[i] = new(big.Int).Sub(pow2(width), big.NewInt(1))
			}
		}
		return c.fp.WithBounds(vs, lo, hi)
	}
	return &montPoint{pack(2, func(p hostPoint) *big.Int { return p.x }), pack(3, func(p hostPoint) *big.Int { return p.y })}
}

// s is a reduced scalar below 2^253. The recoding and the comb bind its integer,
// whose multiple of B depends only on its residue modulo L.
func (c *curve) montBaseElement(s *emfield.Element) *point {
	odd := c.lowBits(s.Limbs()[0], 1)[0]
	zero := c.api.IsZero(c.api.Add(0, 0, s.Limbs()...))
	digits, _, _ := c.recodeValue(s, odd, zero, 253)
	return c.montBaseRecoded(digits, odd, zero)
}

// Evaluate the fixed-base comb from fully constrained signed-odd digits.
// The 253-bit layout and correctScalar flags must come from recodeValue.
func (c *curve) montBaseRecoded(digits []frontend.Variable, odd, zero frontend.Variable) *point {
	const window = 8
	montBaseOnce.Do(func() {
		b := generator()
		for start := 0; start < 253; start += window {
			width := min(window, 253-start)
			half := 1 << (width - 1)
			d := hostAdd(b, b)
			pos := make([]hostPoint, half)
			pos[0] = b
			for i := 1; i < half; i++ {
				pos[i] = hostAdd(pos[i-1], d)
			}
			rows := make([]hostPoint, 1<<width)
			for idx := range rows {
				v := 2*idx - (1 << width) + 1
				sign := 1
				if v < 0 {
					sign = -1
					v = -v
				}
				q := pos[(v-1)/2]
				if sign < 0 {
					q = hostPoint{new(big.Int).Sub(fieldPrime(), q.x), q.y}
				}
				rows[idx] = hostMont(q)
			}
			montBaseWindows = append(montBaseWindows, rows)
			for i := 0; i < window; i++ {
				b = hostAdd(b, b)
			}
		}
	})
	var acc *montPoint
	for i, start := 0, 0; start < len(digits); i, start = i+1, start+window {
		q := c.montConstantSelect(montBaseWindows[i], digits[start:min(start+window, len(digits))])
		if acc == nil {
			acc = q
		} else {
			acc = c.montAdd(acc, q, start+window >= len(digits))
		}
	}
	g := generator()
	base := &point{x: c.fp.Const(g.x), y: c.fp.Const(g.y), t: c.fp.Const(new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Mul(parameterD(), g.x), g.y), fieldPrime()))}
	return c.correctScalar(c.edFromMont(c.montReduce(acc)), base, odd, zero)
}

// Registers untrusted witness hints. Their callers enforce the required relations.
func init() {
	solver.RegisterHint(montSecondHint, montFromEdHint, edFromMontHint, montTangentHint, montSlopeHint, oddRecodeHint)
}

// Computes a host field quotient for a hint. Circuit equations must bind the result.
func ratio(p, num, den *big.Int) *big.Int {
	d := new(big.Int).Mod(den, p)
	if d.ModInverse(d, p) == nil {
		return new(big.Int)
	}
	return d.Mul(d, num).Mod(d, p)
}

// Suggest finite map coordinates. montFromEd checks both membership and map.
func montFromEdHint(q *big.Int, in, out []*big.Int) error {
	return emfield.Unwrap(q, in, out, func(_ *big.Int, _, v, o []*big.Int) error {
		if len(v) != 2 || len(o) != 2 {
			return errors.New("montgomery map shape")
		}
		r := hostMont(hostPoint{v[0], v[1]})
		o[0].Set(r.x)
		o[1].Set(r.y)
		return nil
	})
}

// Suggest inverse-map coordinates. edFromMont checks membership and map.
func edFromMontHint(q *big.Int, in, out []*big.Int) error {
	return emfield.Unwrap(q, in, out, func(p *big.Int, _, v, o []*big.Int) error {
		if len(v) != 2 || len(o) != 2 {
			return errors.New("edwards map shape")
		}
		u := new(big.Int).Sub(v[0], montOffset)
		o[0].Set(ratio(p, new(big.Int).Mul(montScale, u), v[1]))
		o[1].Set(ratio(p, new(big.Int).Sub(u, big.NewInt(1)), new(big.Int).Add(u, big.NewInt(1))))
		return nil
	})
}

// Evaluates the Montgomery curve polynomial over the host field.
func montNumerator(x *big.Int) *big.Int {
	return new(big.Int).Add(new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(x, x)), montA)
}

// Suggest a tangent. Callers range-check its signed limbs and bind 2*y*slope.
func montTangentHint(q *big.Int, in, out []*big.Int) error {
	return emfield.Unwrap(q, in, out, func(p *big.Int, _, v, o []*big.Int) error {
		if len(v) != 2 || len(o) != 1 {
			return errors.New("montgomery tangent shape")
		}
		o[0].Set(ratio(p, montNumerator(v[0]), new(big.Int).Lsh(v[1], 1)))
		return nil
	})
}

// Suggest chord/tangent slope. montAdd or the guarded ladder binds its relation.
func montSlopeHint(q *big.Int, in, out []*big.Int) error {
	return emfield.Unwrap(q, in, out, func(p *big.Int, n, v, o []*big.Int) error {
		if len(n) != 1 || len(v) != 4 || len(o) != 1 {
			return errors.New("montgomery slope shape")
		}
		if n[0].Sign() != 0 || (new(big.Int).Mod(new(big.Int).Sub(v[2], v[0]), p).Sign() == 0 && new(big.Int).Mod(new(big.Int).Sub(v[3], v[1]), p).Sign() == 0) {
			o[0].Set(ratio(p, montNumerator(v[0]), new(big.Int).Lsh(v[1], 1)))
		} else {
			o[0].Set(ratio(p, new(big.Int).Sub(v[3], v[1]), new(big.Int).Sub(v[2], v[0])))
		}
		return nil
	})
}

// Suggest signed-odd digits. recodeValue/shortRecode bind all digits to inputs.
func oddRecodeHint(_ *big.Int, in, out []*big.Int) error {
	if len(in) < 3 || int(in[0].Int64()) != len(out) {
		return errors.New("odd recoding shape")
	}
	s := new(big.Int)
	for i := len(in) - 1; i >= 2; i-- {
		s.Lsh(s, uint(in[1].Uint64())).Add(s, in[i])
	}
	if s.Sign() == 0 {
		s.SetInt64(1)
	} else if s.Bit(0) == 0 {
		s.Sub(s, big.NewInt(1))
	}
	s.Add(s, new(big.Int).Sub(pow2(len(out)), big.NewInt(1))).Rsh(s, 1)
	for i, o := range out {
		o.SetUint64(uint64(s.Bit(i)))
	}
	return nil
}

// Suggest the second ladder slope. quadrupleAddChecked owns its relation.
func montSecondHint(q *big.Int, in, out []*big.Int) error {
	return emfield.Unwrap(q, in, out, func(p *big.Int, _, v, o []*big.Int) error {
		if len(v) != 3 || len(o) != 1 {
			return errors.New("montgomery second slope shape")
		}
		o[0].Set(ratio(p, new(big.Int).Lsh(v[1], 1), new(big.Int).Sub(v[2], v[0])))
		return nil
	})
}
