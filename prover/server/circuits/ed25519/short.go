package ed25519

import (
	"errors"
	"math/big"
	"sync"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/lookup"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/shortladder"
)

const shortBits = 127

var shortAlpha = new(big.Int).Div(new(big.Int).Sub(pow2(shortBits+1), big.NewInt(1)), big.NewInt(3))
var torsionOnce sync.Once
var torsionPoints []hostPoint

// Generate the eight trusted torsion constants from the fixed order-eight point.
func torsionTable() []hostPoint {
	torsionOnce.Do(func() {
		x, _ := new(big.Int).SetString("14399317868200118260347934320527232580618823971194345261214217575416788799818", 10)
		y, _ := new(big.Int).SetString("2707385501144840649318225287225658788936804267575313519463743609750303402022", 10)
		g := hostPoint{x, y}
		torsionPoints = make([]hostPoint, 8)
		torsionPoints[0] = hostPoint{new(big.Int), big.NewInt(1)}
		for i := 1; i < 8; i++ {
			torsionPoints[i] = hostAdd(torsionPoints[i-1], g)
		}
	})
	return torsionPoints
}

// Negates a host point for hint and public-table arithmetic.
func hostNeg(p hostPoint) hostPoint {
	return hostPoint{new(big.Int).Mod(new(big.Int).Neg(p.x), fieldPrime()), p.y}
}

// Complete extended coordinates (EFD madd-2008-hwcd-3, dbl-2008-hwcd) cover torsion
// points too. The scalar is not reduced modulo L.
type hostExtendedPoint struct{ x, y, z, t big.Int }

// Host integer scalar multiplication retains torsion by avoiding reduction modulo L.
// Callers still constrain every hinted result.
func hostMul(p hostPoint, s *big.Int) hostPoint {
	mod := fieldPrime()
	mul := func(out, a, b *big.Int) { out.Mul(a, b).Mod(out, mod) }
	add := func(out, a, b *big.Int) { out.Add(a, b).Mod(out, mod) }
	sub := func(out, a, b *big.Int) { out.Sub(a, b).Mod(out, mod) }
	var baseMinus, basePlus, baseD2T big.Int
	sub(&baseMinus, p.y, p.x)
	add(&basePlus, p.y, p.x)
	baseD2T.Mul(p.x, p.y).Mul(&baseD2T, hostD).Lsh(&baseD2T, 1).Mod(&baseD2T, mod)
	var acc hostExtendedPoint
	acc.y.SetInt64(1)
	acc.z.SetInt64(1)
	// Reuse temporaries so each scalar bit does not allocate new big.Ints.
	var a, b, c, d, e, f, g, h big.Int
	for i := s.BitLen() - 1; i >= 0; i-- {
		mul(&a, &acc.x, &acc.x)
		mul(&b, &acc.y, &acc.y)
		c.Mul(&acc.z, &acc.z).Lsh(&c, 1).Mod(&c, mod)
		d.Neg(&a).Mod(&d, mod)
		e.Add(&acc.x, &acc.y)
		e.Mul(&e, &e).Sub(&e, &a).Sub(&e, &b).Mod(&e, mod)
		add(&g, &d, &b)
		sub(&h, &d, &b)
		sub(&f, &g, &c)
		mul(&acc.x, &e, &f)
		mul(&acc.y, &g, &h)
		mul(&acc.z, &f, &g)
		mul(&acc.t, &e, &h)
		if s.Bit(i) != 0 {
			a.Sub(&acc.y, &acc.x)
			mul(&a, &a, &baseMinus)
			b.Add(&acc.y, &acc.x)
			mul(&b, &b, &basePlus)
			mul(&c, &acc.t, &baseD2T)
			d.Lsh(&acc.z, 1).Mod(&d, mod) // The fixed base has Z=1.
			sub(&e, &b, &a)
			sub(&f, &d, &c)
			add(&g, &d, &c)
			add(&h, &b, &a)
			mul(&acc.x, &e, &f)
			mul(&acc.y, &g, &h)
			mul(&acc.z, &f, &g)
			mul(&acc.t, &e, &h)
		}
	}
	inverse := new(big.Int).ModInverse(&acc.z, mod)
	if inverse == nil {
		// Invalid coordinates can yield Z=0. Hints must not panic. Circuit
		// constraints remain responsible for rejecting invalid points.
		return hostPoint{new(big.Int), new(big.Int)}
	}
	mul(&acc.x, &acc.x, inverse)
	mul(&acc.y, &acc.y, inverse)
	return hostPoint{&acc.x, &acc.y}
}

// Recognizes the host identity when checking exceptional hint paths.
func hostIdentity(p hostPoint) bool { return p.x.Sign() == 0 && p.y.Cmp(big.NewInt(1)) == 0 }

// Select a trusted point using an already-constrained one-hot selector.
func (c *curve) constantPoint(points []hostPoint, flags []frontend.Variable) *point {
	return c.constantPoint2D(points, []frontend.Variable{1}, flags, true)
}

// Select trusted coordinates and optional d*x*y. Rows and columns must each
// be one-hot. Their exclusivity is what justifies the attached limb bounds.
func (c *curve) constantPoint2D(points []hostPoint, rows, cols []frontend.Variable, withT bool) *point {
	pack := func(group int, coord func(hostPoint) *big.Int) *emfield.Element {
		return shortladder.SelectConstant(c.api, c.fp, rows, cols, group, func(i int) *big.Int { return coord(points[i]) })
	}
	p := &point{x: pack(2, func(p hostPoint) *big.Int { return p.x }), y: pack(3, func(p hostPoint) *big.Int { return p.y })}
	if withT {
		p.t = pack(1, func(p hostPoint) *big.Int {
			return new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Mul(parameterD(), p.x), p.y), fieldPrime())
		})
	}
	return p
}

// P=[8]W+T with an on-curve W proves the subgroup split, since [8]W lies in the
// prime subgroup. The torsion selector is constrained.
func (c *curve) splitTorsion(p *point) (*point, frontend.Variable) {
	in := append([]frontend.Variable{layout.LimbBits}, p.x.Limbs()...)
	in = append(in, p.y.Limbs()...)
	raw, err := c.api.Compiler().NewHint(torsionIndexHint, 1, in...)
	if err != nil {
		panic(err)
	}
	index := raw[0]
	bits := c.api.ToBinary(index, 3)
	t := c.constantPoint(torsionTable(), oneHot(c.api, bits))
	w := c.fp.Hint(torsionRootHint, 2, []frontend.Variable{index}, p.x, p.y)
	root := &point{x: w[0], y: w[1]}
	c.assertOnCurve(root)
	prime := c.double(c.double(c.double(root)))
	c.assertAdd(prime, t, p)
	return prime, index
}

// The short relation u*h=v mod L has u in [1,2^127) and |v|<2^127. Since u is
// invertible modulo L, uR+vA=(uS)B on prime points proves the signature equation.
func (c *curve) shortVerify(a, r *point, h, s *emfield.Element) {
	in := append([]frontend.Variable{layout.LimbBits}, h.Limbs()...)
	widths := []int{}
	per := 0
	for rem := shortBits; rem > 0; {
		w := min(layout.LimbBits, rem)
		widths = append(widths, w)
		per += (w + layout.PieceBits - 1) / layout.PieceBits
		rem -= w
	}
	raw, err := c.api.Compiler().NewHint(shortScalarsHint, 1+2*per, in...)
	if err != nil {
		panic(err)
	}
	sign := raw[0]
	c.api.AssertIsBoolean(sign)
	raw = raw[1:]
	take := func() *emfield.Element {
		ls := make([]frontend.Variable, len(widths))
		for i, w := range widths {
			k := (w + layout.PieceBits - 1) / layout.PieceBits
			ls[i] = c.fr.RangeChecker().Compose(raw[:k], w)
			raw = raw[k:]
		}
		return c.fr.Bounded(ls, widths)
	}
	u, v := take(), take()
	c.api.AssertIsDifferent(c.api.Add(0, 0, u.Limbs()...), 0)
	signedV := c.fr.Select(sign, c.fr.Neg(v), v)
	c.fr.AssertZero(emfield.T(1, u, h), emfield.T(-1, signedV))
	us := c.fr.Eval(emfield.T(1, u, s))
	// The comb computes the represented scalar. Equality modulo L suffices.
	// Its reduced bound is below 2^253, and honest hint outputs are canonical.
	rhs := c.montBaseElement(us)
	signedA := &point{x: c.fp.Select(sign, c.fp.Neg(a.x), a.x), y: a.y}
	ud, uo, uz := c.shortRecode(u)
	vd, vo, vz := c.shortRecode(v)
	j, k := c.offsetPoints(r, signedA, u, v)
	acc, table := c.shortTable(r, signedA, j)
	for start := shortBits - 3; start >= 0; start -= 2 {
		selector := c.api.Add(ud[start/2], c.api.Mul(vd[start/2], 4))
		row := table.Lookup(selector)
		t := &montPoint{x: shortladder.UnpackCoordinate(c.fp, row[:(layout.NbLimbs+1)/2], 2, false), y: shortladder.UnpackCoordinate(c.fp, row[(layout.NbLimbs+1)/2:], 2, false)}
		acc = c.quadrupleAddChecked(acc, t)
	}
	final := c.montReduce(acc)
	lhs := c.edFromMont(final)
	lhs = c.correctScalar(lhs, r, uo, uz)
	lhs = c.correctScalar(lhs, signedA, vo, vz)
	c.assertAdd(rhs, k, lhs)
}

// Both inputs are reduced. The exact three-case guard excludes equality
// modulo p, including the possible p-aliases within their 255-bit ranges.
func (c *curve) montGuardedAdd(p, q *montPoint) *montPoint {
	shortladder.AssertDistinct(c.api, c.fp, p.x, q.x, distinctHint)
	return c.montAdd(p, q, false)
}

// Build the joint odd-multiple table from checked curve maps and guarded
// additions. Offset selection may vary, but every table entry remains bound.
func (c *curve) shortTable(a, b, j *point) (*montPoint, *lookup.Table) {
	am, bm, jm := c.montFromEd(a), c.montFromEd(b), c.montFromEd(j)
	twiceA, twiceB := c.montReduce(c.montDouble(am)), c.montReduce(c.montDouble(bm))
	neg := func(p *montPoint) *montPoint { return &montPoint{x: p.x, y: c.fp.Neg(p.y)} }
	var grid [4][4]*montPoint
	grid[2][2] = c.montReduce(c.montGuardedAdd(c.montReduce(c.montGuardedAdd(jm, am)), bm))
	grid[2][1] = c.montReduce(c.montGuardedAdd(grid[2][2], neg(twiceB)))
	grid[2][0] = c.montReduce(c.montGuardedAdd(grid[2][1], neg(twiceB)))
	grid[2][3] = c.montReduce(c.montGuardedAdd(grid[2][2], twiceB))
	for col := 0; col < 4; col++ {
		grid[1][col] = c.montReduce(c.montGuardedAdd(grid[2][col], neg(twiceA)))
		grid[0][col] = c.montReduce(c.montGuardedAdd(grid[1][col], neg(twiceA)))
		grid[3][col] = c.montReduce(c.montGuardedAdd(grid[2][col], twiceA))
	}
	table := lookup.New(c.api, 2*((layout.NbLimbs+1)/2))
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			p := grid[row][col]
			table.Insert(append(shortladder.PackCoordinate(c.api, c.fp, p.x, 2), shortladder.PackCoordinate(c.api, c.fp, p.y, 2)...))
		}
	}
	return grid[2][2], table
}

// Bind the fused radix-four ladder step on finite odd-order inputs. There 2p is
// never 2-torsion, so mu and every other slope relation fix their slope.
func (c *curve) quadrupleAddChecked(p, t *montPoint) *montPoint {
	fp := c.fp
	l0 := fp.HintBalanced(montTangentHint, 1, nil, p.x, p.y)[0]
	fp.AssertZeroProjected(emfield.T(2, l0, p.y), emfield.T(-3, p.x, p.x), emfield.T(-1, fp.Const(montA)))
	xd := fp.Lazy(emfield.T(1, l0, l0), emfield.T(-2, p.x))
	yd := fp.Lazy(emfield.T(1, l0, fp.Sub(p.x, xd)), emfield.T(-1, p.y))
	l1 := fp.HintBalanced(montSlopeHint, 1, []frontend.Variable{0}, xd, yd, t.x, t.y)[0]
	diff := fp.Sub(t.x, xd)
	// Shared CRT products also serve the lazy y coordinate below.
	fp.AssertZeroProjected(emfield.T(1, l1, diff), emfield.T(-1, t.y), emfield.T(1, yd))
	// Equal x leaves the chord equation as 0=0. A canonical difference stops a
	// p-alias from skipping the tangent equation.
	dx := fp.EvalProjected(emfield.T(1, diff))
	fp.AssertCanonical(dx)
	equalX := c.api.IsZero(c.api.Add(0, 0, dx.Limbs()...))
	equal := fp.Bounded([]frontend.Variable{equalX}, []int{1})
	fp.AssertZeroProjected(emfield.T(2, equal, l1, yd), emfield.T(-3, equal, xd, xd), emfield.T(-1, equal, fp.Const(montA)))
	x2 := fp.Lazy(emfield.T(1, l1, l1), emfield.T(-1, xd), emfield.T(-1, t.x))
	mu := fp.HintBalanced(montSecondHint, 1, nil, xd, yd, x2)[0]
	fp.AssertZeroProjected(emfield.T(1, mu, fp.Sub(x2, xd)), emfield.T(2, l1, diff), emfield.T(-2, t.y))
	sum := fp.Add(mu, l1)
	x := fp.Lazy(emfield.T(1, sum, sum), emfield.T(-1, l1, l1), emfield.T(1, t.x))
	y := fp.Lazy(emfield.T(1, fp.Add(l1, mu), fp.Sub(x, xd)), emfield.T(1, l1, diff), emfield.T(-1, t.y))
	return &montPoint{x, y}
}

var offsetsOnce sync.Once
var offsetJs, offsetKs []hostPoint

// Select paired fixed offsets J and K=[alpha]J with one bounded index. The
// hint chooses a usable pair. Constraints bind both and guard each ladder step.
func (c *curve) offsetPoints(a, b *point, u, v *emfield.Element) (*point, *point) {
	in := []frontend.Variable{layout.LimbBits, len(u.Limbs()), len(v.Limbs()), layout.NbLimbs}
	in = append(in, u.Limbs()...)
	in = append(in, v.Limbs()...)
	in = append(in, a.x.Limbs()...)
	in = append(in, a.y.Limbs()...)
	in = append(in, b.x.Limbs()...)
	in = append(in, b.y.Limbs()...)
	raw, err := c.api.Compiler().NewHint(offsetHint, 1, in...)
	if err != nil {
		panic(err)
	}
	bits := c.api.ToBinary(raw[0], 8)
	rows, cols := oneHot(c.api, bits[:1]), oneHot(c.api, bits[1:])
	offsetsOnce.Do(func() {
		g := generator()
		kg := hostMul(g, shortAlpha)
		j, k := g, kg
		for i := 0; i < 256; i++ {
			offsetJs = append(offsetJs, j)
			offsetKs = append(offsetKs, k)
			j = hostAdd(j, g)
			k = hostAdd(k, kg)
		}
	})
	return c.constantPoint2D(offsetJs, rows, cols, false), c.constantPoint2D(offsetKs, rows, cols, true)
}

// Registers untrusted witness hints. Their callers enforce the required relations.
func init() {
	solver.RegisterHint(torsionIndexHint, torsionRootHint, distinctHint, offsetHint)
}

// Suggest the torsion index. splitTorsion proves the complete decomposition.
func torsionIndexHint(q *big.Int, in, out []*big.Int) error {
	if len(in) != 1+2*layout.NbLimbs || len(out) != 1 {
		return errors.New("torsion index shape")
	}
	n := layout.NbLimbs
	bits := int(in[0].Int64())
	p := hostPoint{shortladder.BalancedInteger(q, in[1:1+n], bits), shortladder.BalancedInteger(q, in[1+n:], bits)}
	p.x.Mod(p.x, fieldPrime())
	p.y.Mod(p.y, fieldPrime())
	t := hostMul(hostMul(p, groupOrder()), big.NewInt(5)) // L mod8=5, whose inverse is5.
	for i, v := range torsionTable() {
		if t.x.Cmp(v.x) == 0 && t.y.Cmp(v.y) == 0 {
			out[0].SetInt64(int64(i))
			return nil
		}
	}
	return errors.New("point has no torsion split")
}

// Suggest W for P=[8]W+T. splitTorsion checks W on-curve and the full equation.
func torsionRootHint(q *big.Int, in, out []*big.Int) error {
	return emfield.Unwrap(q, in, out, func(_ *big.Int, n, v, o []*big.Int) error {
		if len(n) != 1 || len(v) != 2 || len(o) != 2 || !n[0].IsUint64() || n[0].Uint64() >= 8 {
			return errors.New("torsion root shape")
		}
		t := torsionTable()[n[0].Uint64()]
		p := hostAdd(hostPoint{v[0], v[1]}, hostNeg(t))
		p = hostMul(p, new(big.Int).ModInverse(big.NewInt(8), groupOrder()))
		o[0].Set(p.x)
		o[1].Set(p.y)
		return nil
	})
}

// Find a short lattice relation. shortVerify bounds u/v and checks u*h=v mod L.
func shortRelationHint(q *big.Int, in, out []*big.Int) error {
	if len(in) < 2 || len(out) != 1+2*shortBits {
		return errors.New("short relation shape")
	}
	h := shortladder.BalancedInteger(q, in[1:], int(in[0].Int64()))
	h.Mod(h, groupOrder())
	r0, r1 := groupOrder(), new(big.Int).Set(h)
	t0, t1 := new(big.Int), big.NewInt(1)
	threshold := pow2(126)
	for r1.Cmp(threshold) > 0 {
		quot := new(big.Int).Div(r0, r1)
		r0, r1 = r1, new(big.Int).Sub(r0, new(big.Int).Mul(quot, r1))
		t0, t1 = t1, new(big.Int).Sub(t0, new(big.Int).Mul(quot, t1))
	}
	out[0].SetInt64(0)
	if t1.Sign() < 0 {
		out[0].SetInt64(1)
	}
	u := new(big.Int).Abs(t1)
	v := r1
	if u.Sign() == 0 || u.BitLen() > shortBits || v.BitLen() > shortBits {
		return errors.New("short relation exceeded bound")
	}
	for i := 0; i < shortBits; i++ {
		out[1+i].SetUint64(uint64(u.Bit(i)))
		out[1+shortBits+i].SetUint64(uint64(v.Bit(i)))
	}
	return nil
}

// Suggest inverse certificates. The caller binds the relevant nonzero equation.
// The name stays registered here so stored constraint systems resolve it.
func distinctHint(q *big.Int, in, out []*big.Int) error { return shortladder.PackedNonzero(q, in, out) }

// Chooses the signed scalar representative used by the recoding hint.
func adjustedScalar(v *big.Int) *big.Int {
	r := new(big.Int).Set(v)
	if r.Sign() == 0 {
		r.SetInt64(1)
	} else if r.Bit(0) == 0 {
		r.Sub(r, big.NewInt(1))
	}
	return r
}

// Choose an offset avoiding exceptional ladder steps. The circuit repeats all
// required guards, so successful host search is never a soundness premise.
func offsetHint(q *big.Int, in, out []*big.Int) error {
	if len(in) < 4 || len(out) != 1 {
		return errors.New("offset shape")
	}
	bits, nu, nv, n := int(in[0].Int64()), int(in[1].Int64()), int(in[2].Int64()), int(in[3].Int64())
	if len(in) != 4+nu+nv+4*n {
		return errors.New("offset length")
	}
	pos := 4
	take := func(count int) *big.Int {
		v := shortladder.BalancedInteger(q, in[pos:pos+count], bits)
		pos += count
		return v
	}
	u, v := adjustedScalar(take(nu)), adjustedScalar(take(nv))
	a := hostPoint{take(n), take(n)}
	b := hostPoint{take(n), take(n)}
	a.x.Mod(a.x, fieldPrime())
	a.y.Mod(a.y, fieldPrime())
	b.x.Mod(b.x, fieldPrime())
	b.y.Mod(b.y, fieldPrime())
	ua := new(big.Int).Rsh(new(big.Int).Add(u, new(big.Int).Sub(pow2(shortBits), big.NewInt(1))), 1)
	vb := new(big.Int).Rsh(new(big.Int).Add(v, new(big.Int).Sub(pow2(shortBits), big.NewInt(1))), 1)
	multiples := func(p hostPoint) []hostPoint {
		three := hostAdd(hostAdd(p, p), p)
		return []hostPoint{hostNeg(three), hostNeg(p), p, three}
	}
	aa, bb := multiples(a), multiples(b)
	g := generator()
	j := g
	for candidate := 0; candidate < 256; candidate++ {
		var grid [4][4]hostPoint
		good := !hostIdentity(hostAdd(j, a)) && j.y.Cmp(a.y) != 0 && hostAdd(j, a).y.Cmp(b.y) != 0
		for col := 0; col < 4; col++ {
			for row := 0; row < 4; row++ {
				grid[row][col] = hostAdd(hostAdd(j, aa[row]), bb[col])
				if hostIdentity(grid[row][col]) {
					good = false
				}
			}
		}
		ta, tb := hostAdd(a, a), hostAdd(b, b)
		if grid[2][2].y.Cmp(tb.y) == 0 || grid[2][1].y.Cmp(tb.y) == 0 {
			good = false
		}
		for col := 0; col < 4; col++ {
			if grid[2][col].y.Cmp(ta.y) == 0 || grid[1][col].y.Cmp(ta.y) == 0 {
				good = false
			}
		}
		acc := grid[2][2]
		if good {
			for start := shortBits - 3; start >= 0; start -= 2 {
				i := int(ua.Bit(start)) + 2*int(ua.Bit(start+1))
				k := int(vb.Bit(start)) + 2*int(vb.Bit(start+1))
				t := grid[i][k]
				d := hostAdd(acc, acc)
				if d.y.Cmp(t.y) == 0 && d.x.Cmp(t.x) != 0 {
					good = false
					break
				}
				acc = hostAdd(hostAdd(d, d), t)
				if hostIdentity(acc) {
					good = false
					break
				}
			}
		}
		if good {
			out[0].SetInt64(int64(candidate))
			return nil
		}
		j = hostAdd(j, g)
	}
	return errors.New("no valid bounded offset")
}

// Constrain y²=x³+A*x+B for the shifted Montgomery model. Existing element
// bounds are required. This adds membership, not a subgroup assertion.
func (c *curve) assertMontOnCurve(p *montPoint) {
	x2 := c.fp.Lazy(emfield.T(1, p.x, p.x))
	c.fp.AssertZeroProjected(emfield.T(1, p.y, p.y), emfield.T(-1, x2, p.x), emfield.T(-1, c.fp.Const(montA), p.x), emfield.T(-1, c.fp.Const(montB)))
}

// Registers untrusted witness hints. Their callers enforce the required relations.
func init() { solver.RegisterHint(shortScalarsHint, shortRecodeHint) }

// Package the lattice relation into pieces checked by shortVerify.
func shortScalarsHint(q *big.Int, in, out []*big.Int) error {
	bits := make([]*big.Int, 1+2*shortBits)
	for i := range bits {
		bits[i] = new(big.Int)
	}
	if e := shortRelationHint(q, in, bits); e != nil {
		return e
	}
	out[0].Set(bits[0])
	out = out[1:]
	for s := 0; s < 2; s++ {
		v := new(big.Int)
		for i := 0; i < shortBits; i++ {
			v.SetBit(v, i, uint(bits[1+s*shortBits+i].Uint64()))
		}
		for rem := shortBits; rem > 0; {
			w := min(layout.LimbBits, rem)
			limb := new(big.Int).And(v, new(big.Int).Sub(pow2(w), big.NewInt(1)))
			v.Rsh(v, uint(w))
			for done := 0; done < w; done += layout.PieceBits {
				out[0].And(limb, new(big.Int).Sub(pow2(layout.PieceBits), big.NewInt(1)))
				out = out[1:]
				limb.Rsh(limb, uint(layout.PieceBits))
			}
			rem -= w
		}
	}
	return nil
}

// Suggest radix-four digits and parity. shortRecode checks the integer relation.
func shortRecodeHint(q *big.Int, in, out []*big.Int) error {
	bits := make([]*big.Int, shortBits)
	for i := range bits {
		bits[i] = new(big.Int)
	}
	if e := oddRecodeHint(q, in, bits); e != nil {
		return e
	}
	v := shortladder.BalancedInteger(q, in[2:], int(in[1].Int64()))
	out[0].SetUint64(uint64(v.Bit(0)))
	for i := 0; i < (shortBits-1)/2; i++ {
		out[1+i].Add(bits[2*i], new(big.Int).Lsh(bits[2*i+1], 1))
	}
	return nil
}

// Bind all radix-four digits to a previously bounded 127-bit unsigned scalar.
// The full recomposition stays below BN254, including zero/even corrections.
func (c *curve) shortRecode(s *emfield.Element) ([]frontend.Variable, frontend.Variable, frontend.Variable) {
	api := c.api
	in := []frontend.Variable{shortBits, layout.LimbBits}
	in = append(in, s.Limbs()...)
	raw, e := api.Compiler().NewHint(shortRecodeHint, 1+(shortBits-1)/2, in...)
	if e != nil {
		panic(e)
	}
	odd, digits := raw[0], raw[1:]
	api.AssertIsBoolean(odd)
	c.fr.RangeChecker().Check(api.Mul(api.Sub(s.Limbs()[0], odd), new(big.Int).ModInverse(big.NewInt(2), api.Compiler().Field())), layout.LimbBits-1)
	zero := api.IsZero(api.Add(0, 0, s.Limbs()...))
	cv, sv := frontend.Variable(pow2(shortBits-1)), frontend.Variable(0)
	for i, d := range digits {
		c.fr.RangeChecker().Check(d, 2)
		cv = api.Add(cv, api.Mul(d, pow2(2*i)))
	}
	for i, l := range s.Limbs() {
		sv = api.Add(sv, api.Mul(l, pow2(layout.LimbBits*i)))
	}
	api.AssertIsEqual(api.Add(api.Mul(2, cv), new(big.Int).Sub(big.NewInt(2), pow2(shortBits))), api.Add(sv, odd, api.Mul(2, zero)))
	return digits, odd, zero
}
