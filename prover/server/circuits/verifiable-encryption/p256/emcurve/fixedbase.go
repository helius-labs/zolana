// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package emcurve

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

func init() {
	solver.RegisterHint(p256CombRecodeHint, p256CombChainHint, p256XEqualHint, p256UnifiedSlopeHint)
}

func combWindowFor(lay emfield.Layout) int {
	if lay.Lookups {
		return 5
	}
	return 8
}

type combAffine struct {
	x, y *big.Int
}

type combData struct {
	w, nw, n, tw int
	windows      [][][2]*big.Int
	topEven      [][2]*big.Int
}

var (
	combMu     sync.Mutex
	combCached = map[int]*combData{}
)

func p256Comb(w int) *combData {
	combMu.Lock()
	defer combMu.Unlock()
	if d, ok := combCached[w]; ok {
		return d
	}
	params := elliptic.P256().Params()
	a := new(big.Int).Sub(params.P, big.NewInt(3))
	d, err := computeCombData(params.Gx, params.Gy, a, params.P, params.N, w)
	if err != nil {
		panic(fmt.Sprintf("comb data: %v", err))
	}
	combCached[w] = d
	return d
}

func combNeg(p *combAffine, prime *big.Int) *combAffine {
	return &combAffine{x: p.x, y: new(big.Int).Sub(prime, p.y)}
}

func combAdd(p, q *combAffine, prime *big.Int) (*combAffine, error) {
	dx := new(big.Int).Sub(q.x, p.x)
	dx.Mod(dx, prime)
	if dx.Sign() == 0 {
		return nil, errors.New("x-coordinate collision in comb table computation")
	}
	dx.ModInverse(dx, prime)
	lam := new(big.Int).Sub(q.y, p.y)
	lam.Mul(lam, dx).Mod(lam, prime)
	xr := new(big.Int).Mul(lam, lam)
	xr.Sub(xr, p.x).Sub(xr, q.x).Mod(xr, prime)
	yr := new(big.Int).Sub(p.x, xr)
	yr.Mul(yr, lam).Sub(yr, p.y).Mod(yr, prime)
	return &combAffine{x: xr, y: yr}, nil
}

func combDouble(p *combAffine, a, prime *big.Int) (*combAffine, error) {
	if p.y.Sign() == 0 {
		return nil, errors.New("doubling a 2-torsion point in comb table computation")
	}
	den := new(big.Int).Lsh(p.y, 1)
	den.Mod(den, prime)
	den.ModInverse(den, prime)
	lam := new(big.Int).Mul(p.x, p.x)
	lam.Mul(lam, big.NewInt(3)).Add(lam, a)
	lam.Mul(lam, den).Mod(lam, prime)
	xr := new(big.Int).Mul(lam, lam)
	xr.Sub(xr, p.x).Sub(xr, p.x).Mod(xr, prime)
	yr := new(big.Int).Sub(p.x, xr)
	yr.Mul(yr, lam).Sub(yr, p.y).Mod(yr, prime)
	return &combAffine{x: xr, y: yr}, nil
}

func computeCombData(gx, gy, a, prime, r *big.Int, w int) (*combData, error) {
	n := r.BitLen()
	nw := (n + w - 1) / w
	tw := n - w*(nw-1)
	for t := nw - 2; t >= 1; t-- {
		if new(big.Int).Lsh(big.NewInt(1), uint(w*(t+1))).Cmp(r) > 0 {
			return nil, errors.New("only the top window may reach the group order")
		}
	}
	G := &combAffine{x: new(big.Int).Set(gx), y: new(big.Int).Set(gy)}
	windows := make([][][2]*big.Int, nw)
	Bt := G
	var err error
	for t := 0; t < nw; t++ {
		if t > 0 {
			for k := 0; k < w; k++ {
				if Bt, err = combDouble(Bt, a, prime); err != nil {
					return nil, err
				}
			}
		}
		width := w
		if t == nw-1 {
			width = tw
		}
		D, err := combDouble(Bt, a, prime)
		if err != nil {
			return nil, err
		}
		half := 1 << (width - 1)
		odd := make([]*combAffine, half)
		odd[0] = Bt
		for m := 1; m < half; m++ {
			if odd[m], err = combAdd(odd[m-1], D, prime); err != nil {
				return nil, err
			}
		}
		tab := make([][2]*big.Int, 1<<width)
		for j := range tab {
			d := 2*j - (1 << width) + 1
			var pt *combAffine
			if d > 0 {
				pt = odd[(d-1)/2]
			} else {
				pt = combNeg(odd[(-d-1)/2], prime)
			}
			tab[j] = [2]*big.Int{pt.x, pt.y}
		}
		windows[t] = tab
	}
	negG := combNeg(G, prime)
	topEven := make([][2]*big.Int, 1<<tw)
	for j := range topEven {
		q := &combAffine{x: windows[nw-1][j][0], y: windows[nw-1][j][1]}
		s, err := combAdd(q, negG, prime)
		if err != nil {
			return nil, fmt.Errorf("parity-fold table: %w", err)
		}
		topEven[j] = [2]*big.Int{s.x, s.y}
	}
	return &combData{w: w, nw: nw, n: n, tw: tw, windows: windows, topEven: topEven}, nil
}

func oneHot(api frontend.API, bs []frontend.Variable) []frontend.Variable {
	flags := []frontend.Variable{1}
	for _, b := range bs {
		next := make([]frontend.Variable, 2*len(flags))
		if len(flags) == 1 {
			next[0] = api.Sub(1, b)
			next[1] = b
		} else {
			for j := range flags {
				hi := api.Mul(flags[j], b)
				next[j] = api.Sub(flags[j], hi)
				next[j+len(flags)] = hi
			}
		}
		flags = next
	}
	return flags
}

func (c *curve) combSelect(table [][2]*big.Int, bs []frontend.Variable, packY bool) *point {
	nbLimbs := c.lay.NbLimbs
	limbBits := c.lay.LimbBits
	w := len(bs)
	if len(table) != 1<<w {
		panic("table size mismatch")
	}
	oneHotCost := func(k int) int {
		if k <= 1 {
			return 0
		}
		return 1<<k - 2
	}
	rb, best := 0, oneHotCost(w)
	for cand := 1; cand <= w; cand++ {
		if cost := oneHotCost(cand) + oneHotCost(w-cand) + (1<<cand)*2*nbLimbs; cost < best {
			best, rb = cost, cand
		}
	}
	rows := oneHot(c.api, bs[:rb])
	cols := oneHot(c.api, bs[rb:])
	mask := new(big.Int).Sub(pow2(limbBits), big.NewInt(1))
	limb := func(v *big.Int, i int) *big.Int {
		return new(big.Int).And(new(big.Int).Rsh(v, uint(limbBits*i)), mask)
	}
	sel := func(value func(e int) *big.Int) frontend.Variable {
		inner := make([]frontend.Variable, len(rows))
		for i := range rows {
			sum := frontend.Variable(0)
			for j := range cols {
				sum = c.api.Add(sum, c.api.Mul(cols[j], value(i+(j<<rb))))
			}
			inner[i] = sum
		}
		if len(rows) == 1 {
			return inner[0]
		}
		sum := frontend.Variable(0)
		for i := range rows {
			sum = c.api.Add(sum, c.api.Mul(rows[i], inner[i]))
		}
		return sum
	}
	xs := make([]frontend.Variable, nbLimbs)
	ys := make([]frontend.Variable, nbLimbs)
	for l := 0; l < nbLimbs; l++ {
		xs[l] = sel(func(e int) *big.Int { return limb(table[e][0], l) })
	}
	if !packY {
		for l := 0; l < nbLimbs; l++ {
			ys[l] = sel(func(e int) *big.Int { return limb(table[e][1], l) })
		}
		return &point{X: c.fp.Reduced(xs), Y: c.fp.Reduced(ys)}
	}
	widths := c.fp.ReducedWidths()
	lo, hi := make([]*big.Int, nbLimbs), make([]*big.Int, nbLimbs)
	for g := 0; g < nbLimbs; g++ {
		ys[g], lo[g], hi[g] = 0, new(big.Int), new(big.Int)
		if g%packedYGroup != 0 {
			continue
		}
		end := min(g+packedYGroup, nbLimbs)
		mask := new(big.Int).Sub(pow2(limbBits*(end-g)), big.NewInt(1))
		ys[g] = sel(func(e int) *big.Int {
			return new(big.Int).And(new(big.Int).Rsh(table[e][1], uint(limbBits*g)), mask)
		})
		bits := 0
		for _, w := range widths[g:end] {
			bits += w
		}
		hi[g].Sub(pow2(bits), big.NewInt(1))
	}
	return &point{X: c.fp.Reduced(xs), Y: c.fp.WithBounds(ys, lo, hi)}
}

func (c *curve) scalarMulBase(s *frElement) *point {
	d := p256Comb(combWindowFor(c.lay))
	api := c.api
	bits, err := api.Compiler().NewHint(p256CombRecodeHint, 1+d.n, c.limbHintInputs(s.Limbs())...)
	if err != nil {
		panic(fmt.Sprintf("recode hint: %v", err))
	}
	for _, b := range bits {
		api.AssertIsBoolean(b)
	}
	b0 := bits[0]
	cbits := bits[1:]
	cEl := c.scalarFromBits(cbits)
	c.fr.AssertZero(T(2, cEl), T(1, c.fr.Bounded([]frontend.Variable{b0}, []int{1})), T(-1, s), T(-1, c.fr.Const(pow2(d.n))))

	w, nw := d.w, d.nw
	tPts := make([]*point, nw)
	for t := 0; t < nw-1; t++ {
		tPts[t] = c.combSelect(d.windows[t], cbits[t*w:(t+1)*w], true)
	}
	stacked := append(append([][2]*big.Int{}, d.topEven...), d.windows[nw-1]...)
	topBits := append(append([]frontend.Variable{}, cbits[(nw-1)*w:]...), b0)
	tPts[nw-1] = c.combSelect(stacked, topBits, false)

	fp := c.fp
	zero := fp.Const(big.NewInt(0))
	x := tPts[0].X
	lamPrev, xTPrev, yTPrev := zero, tPts[0].X, fp.Neg(tPts[0].Y)
	for t := 1; t < nw-1; t++ {
		cur := tPts[t]
		lam := c.slope(p256CombChainHint, 1, nil, lamPrev, x, xTPrev, yTPrev, cur.X, cur.Y)[0]
		if t == 1 {
			fp.AssertZero(T(1, lam, fp.Sub(cur.X, x)), T(-1, cur.Y), T(1, tPts[0].Y))
		} else {
			fp.AssertZero(T(1, lam, fp.Sub(cur.X, x)), T(1, lamPrev, fp.Sub(xTPrev, x)), T(-1, cur.Y), T(-1, yTPrev))
		}
		x = fp.Lazy(T(1, lam, lam), T(-1, x), T(-1, cur.X))
		lamPrev, xTPrev, yTPrev = lam, cur.X, cur.Y
	}
	x = fp.Eval(T(1, x))
	y := fp.Eval(T(1, lamPrev, fp.Sub(xTPrev, x)), T(-1, yTPrev))
	return c.completeAdd(&point{X: x, Y: y}, tPts[nw-1])
}

func (c *curve) completeAdd(p, q *point) *point {
	fp, api := c.fp, c.api
	inputs := c.limbHintInputs(append(append([]frontend.Variable{}, p.X.Limbs()...), q.X.Limbs()...))
	hinted, err := api.Compiler().NewHint(p256XEqualHint, 2, inputs...)
	if err != nil {
		panic(err)
	}
	equal, inv := hinted[0], hinted[1]
	api.AssertIsBoolean(equal)
	api.AssertIsEqual(api.Mul(c.distinctProduct(p.X, q.X), inv), api.Sub(1, equal))
	eq := fp.Bounded([]frontend.Variable{equal}, []int{1})
	dx := fp.Sub(q.X, p.X)
	dy := fp.Sub(q.Y, p.Y)
	fp.AssertZero(T(1, eq, dx))
	fp.AssertZero(T(1, eq, dy))
	lam := c.slope(p256UnifiedSlopeHint, 1, nil, p.X, p.Y, q.X, q.Y)[0]
	fp.AssertZero(T(1, lam, dx), T(2, lam, eq, p.Y), T(-3, eq, p.X, p.X), T(-1, eq, c.a), T(-1, dy))
	x := fp.Eval(T(1, lam, lam), T(-1, p.X), T(-1, q.X))
	y := fp.Eval(T(1, lam, fp.Sub(p.X, x)), T(-1, p.Y))
	return &point{X: x, Y: y}
}

func p256CombRecodeHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(outputs) < 2 {
		return errors.New("expecting at least two outputs")
	}
	s := limbHintValue(inputs)
	n := len(outputs) - 1
	s.Mod(s, GroupOrder())
	b0 := s.Bit(0)
	kp := new(big.Int).Set(s)
	if b0 == 0 {
		kp.Add(kp, big.NewInt(1))
	}
	cv := new(big.Int).Lsh(big.NewInt(1), uint(n))
	cv.Sub(cv, big.NewInt(1)).Add(cv, kp).Rsh(cv, 1)
	outputs[0].SetUint64(uint64(b0))
	for i := 0; i < n; i++ {
		outputs[1+i].SetUint64(uint64(cv.Bit(i)))
	}
	return nil
}

func p256CombChainHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 6 || len(out) != 1 {
			return errors.New("expecting six inputs and one output")
		}
		lamPrev, x, xTPrev, yTPrev, xT, yT := in[0], in[1], in[2], in[3], in[4], in[5]
		y := new(big.Int).Sub(xTPrev, x)
		y.Mul(y, lamPrev).Sub(y, yTPrev)
		out[0].Set(modRatio(p, new(big.Int).Sub(yT, y), new(big.Int).Sub(xT, x)))
		return nil
	})
}

func p256XEqualHint(q *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) < 1 || len(outputs) != 2 {
		return errors.New("expecting two x-coordinates")
	}
	limbBits := uint(inputs[0].Uint64())
	inputs = inputs[1:]
	n := len(inputs) / 2
	if len(inputs) != 2*n {
		return errors.New("expecting two x-coordinates")
	}
	value := func(limbs []*big.Int) *big.Int {
		v := new(big.Int)
		for i := len(limbs) - 1; i >= 0; i-- {
			v.Lsh(v, limbBits).Add(v, limbs[i])
		}
		return v
	}
	p := elliptic.P256().Params().P
	diff := new(big.Int).Sub(value(inputs[n:]), value(inputs[:n]))
	outputs[0].SetUint64(0)
	outputs[1].SetUint64(0)
	if new(big.Int).Mod(diff, p).Sign() == 0 {
		outputs[0].SetUint64(1)
		return nil
	}
	prod := new(big.Int).Mul(diff, new(big.Int).Sub(diff, p))
	prod.Mul(prod, new(big.Int).Add(diff, p)).Mod(prod, q)
	if prod.Sign() != 0 {
		outputs[1].ModInverse(prod, q)
	}
	return nil
}

func p256UnifiedSlopeHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 4 || len(out) != 1 {
			return errors.New("expecting two points and one output")
		}
		if new(big.Int).Sub(in[2], in[0]).Mod(new(big.Int).Sub(in[2], in[0]), p).Sign() == 0 {
			num := new(big.Int).Mul(in[0], in[0])
			num.Sub(num, big.NewInt(1)).Mul(num, big.NewInt(3))
			out[0].Set(modRatio(p, num, new(big.Int).Lsh(in[1], 1)))
			return nil
		}
		out[0].Set(modRatio(p, new(big.Int).Sub(in[3], in[1]), new(big.Int).Sub(in[2], in[0])))
		return nil
	})
}
