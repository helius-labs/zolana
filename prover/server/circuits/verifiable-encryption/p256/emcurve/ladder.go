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
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/algebra/lattice"
	"github.com/consensys/gnark-crypto/ecc/secp256r1"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

func init() {
	solver.RegisterHint(p256DecomposeScalarHint, p256ScalarMulHint, p256ImplicitChordHint, p256ImplicitSecondSlopeHint, p256HalfTangentHint)
}

const (
	halfScalarBits = 129
	packedYGroup   = 3
)

func (c *curve) nativeValue(e *fpElement) frontend.Variable {
	sum := frontend.Variable(0)
	for i, l := range e.Limbs() {
		sum = c.api.Add(sum, c.api.Mul(l, pow2(c.lay.LimbBits*i)))
	}
	return sum
}

func (c *curve) distinctProduct(p, q *fpElement) frontend.Variable {
	widths := c.fp.ReducedWidths()
	if !p.IsReduced(widths) || !q.IsReduced(widths) {
		panic("distinct-x guard needs reduced coordinates")
	}
	diff := c.api.Sub(c.nativeValue(q), c.nativeValue(p))
	modulus := c.fp.Modulus()
	return c.api.Mul(c.api.Mul(diff, c.api.Sub(diff, modulus)), c.api.Add(diff, modulus))
}

func (c *curve) assertDistinctX(p, q *fpElement) {
	c.api.AssertIsDifferent(c.distinctProduct(p, q), 0)
}

func (c *curve) quadrupleAndAddLazy(a, t *point, halfSlope frontend.Variable) *point {
	fp := c.fp
	lambda0 := c.tangent(a)
	xD := fp.Lazy(T(1, lambda0, lambda0), T(-2, a.X))
	yD := fp.Lazy(T(1, lambda0, fp.Sub(a.X, xD)), T(-1, a.Y))
	tMinusD := fp.Sub(t.X, xD)
	lambda1 := c.slope(p256ImplicitChordHint, 1, nil, lambda0, a.X, xD, a.Y, t.X, t.Y)[0]
	fp.AssertZero(T(1, lambda1, tMinusD), T(-1, t.Y), T(1, yD))
	if halfSlope != nil {
		c.assertDistinctSlope(lambda0, halfSlope)
	} else {
		xSum := fp.Add(xD, t.X)
		fp.AssertZero(T(1, lambda1, fp.Add(yD, t.Y)), T(-1, xSum, xSum), T(1, xD, t.X), T(-1, c.a))
	}
	x2 := fp.Lazy(T(1, lambda1, lambda1), T(-1, xD), T(-1, t.X))
	mu := c.slope(p256ImplicitSecondSlopeHint, 1, nil, lambda0, a.X, xD, a.Y, x2)[0]
	fp.AssertZero(T(1, mu, fp.Sub(x2, xD)), T(2, lambda1, tMinusD), T(-2, t.Y))
	x3 := fp.Lazy(T(1, mu, fp.Lin([]int64{1, 2}, mu, lambda1)), T(1, t.X))
	y3 := fp.Lazy(T(1, fp.Add(lambda1, mu), fp.Sub(x3, xD)), T(1, lambda1, tMinusD), T(-1, t.Y))
	return &point{X: x3, Y: y3}
}

func (c *curve) guardedAdd(p, q *point) *point {
	c.assertDistinctX(p.X, q.X)
	return c.add(p, q)
}

func (c *curve) scalarMulChecked(q *point, s *frElement) *point {
	fr, fp, api := c.fr, c.fp, c.api
	decomposition, err := api.Compiler().NewHint(p256DecomposeScalarHint, 1+2*halfScalarBits, c.limbHintInputs(s.Limbs())...)
	if err != nil {
		panic(fmt.Sprintf("decompose hint: %v", err))
	}
	for _, b := range decomposition {
		api.AssertIsBoolean(b)
	}
	sign := decomposition[0]
	s1bits := decomposition[1 : 1+halfScalarBits]
	s2bits := decomposition[1+halfScalarBits:]
	s1 := c.scalarFromBits(s1bits)
	s2 := c.scalarFromBits(s2bits)
	fr.AssertZero(T(1, s, fr.Select(sign, fr.Neg(s2), s2)), T(1, s1))
	api.AssertIsDifferent(api.Add(s2bits[0], s2bits[1], s2bits[2:]...), 0)

	hinted := fp.Hint(p256ScalarMulHint, 2, nil, q.X, q.Y, s)
	r := &point{X: hinted[0], Y: hinted[1]}
	c.assertOnCurve(r)

	q3 := c.triple(q)
	rSigned := &point{X: r.X, Y: fp.Select(sign, fp.Neg(r.Y), r.Y)}
	r3 := c.triple(rSigned)
	c.assertDistinctX(r.X, q.X)
	c.assertDistinctX(r.X, q3.X)
	c.assertDistinctX(r3.X, q.X)
	negQ := c.neg(q)
	negR := c.neg(rSigned)

	acc := c.add(q, rSigned)
	t1 := c.add(q3, r3)
	t2 := acc
	t3 := c.add(q3, rSigned)
	t4 := c.add(q, r3)
	t12 := c.add(negR, q)
	negR3 := c.neg(r3)
	slots := []*point{t1, c.add(q, negR3), c.add(q3, negR), t2, t4, c.add(q3, negR3), t12, t3}
	nbits := halfScalarBits + 1
	halves := make([]frontend.Variable, len(slots))
	for i, slot := range slots {
		halves[i] = c.nativeValue(c.halfTangentSlope(slot))
	}
	lookup := func(i int, natives []frontend.Variable) (*point, frontend.Variable) {
		return c.muxSlot(slots, natives, s1bits[i], s2bits[i], s1bits[i-1], s2bits[i-1])
	}
	if c.lay.Lookups {
		lookup = c.packedTableLookup(slots, halves, s1bits, s2bits)
	}
	for i := nbits - 2; i > 2; i -= 2 {
		t, half := lookup(i, halves)
		acc = c.quadrupleAndAddLazy(acc, t, half)
	}
	last, _ := lookup(2, nil)
	acc = c.quadrupleAndAddLazy(acc, c.guardedAdd(last, r3), nil)
	acc = &point{X: fp.Eval(T(1, acc.X)), Y: acc.Y}

	acc = c.selectPoint(s1bits[0], acc, c.guardedAddReducing(negQ, acc, true, false))
	acc = c.selectPoint(s2bits[0], acc, c.guardedAddReducing(negR, acc, false, false))
	c.assertEqual(acc, r3)
	return r
}

func (c *curve) guardedAddReducing(p, q *point, reduceX, reduceY bool) *point {
	c.assertDistinctX(p.X, q.X)
	return c.addReducing(p, q, reduceX, reduceY)
}

func (c *curve) scalarFromBits(bits []frontend.Variable) *frElement {
	var limbs []frontend.Variable
	var widths []int
	for i := 0; i < len(bits); i += c.lay.LimbBits {
		chunk := bits[i:min(len(bits), i+c.lay.LimbBits)]
		limbs = append(limbs, c.api.FromBinary(chunk...))
		widths = append(widths, len(chunk))
	}
	return c.fr.Bounded(limbs, widths)
}

func p256DecomposeScalarHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(outputs) != 1+2*halfScalarBits {
		return errors.New("expecting the sign and bit outputs")
	}
	s := limbHintValue(inputs)
	n := GroupOrder()
	res := lattice.NewReconstructor(n).RationalReconstruct(s.Mod(s, n))
	x, z := new(big.Int).Set(res[0]), new(big.Int).Set(res[1])
	if x.Sign() < 0 {
		x.Neg(x)
		z.Neg(z)
	}
	outputs[0].SetUint64(0)
	if z.Sign() > 0 {
		outputs[0].SetUint64(1)
	}
	z.Abs(z)
	for i := 0; i < halfScalarBits; i++ {
		outputs[1+i].SetUint64(uint64(x.Bit(i)))
		outputs[1+halfScalarBits+i].SetUint64(uint64(z.Bit(i)))
	}
	return nil
}

func p256ScalarMulHint(q *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(_ *big.Int, _, in, out []*big.Int) error {
		if len(in) != 3 || len(out) != 2 {
			return errors.New("expecting a point and a scalar")
		}
		var p secp256r1.G1Affine
		p.X.SetBigInt(in[0])
		p.Y.SetBigInt(in[1])
		p.ScalarMultiplication(&p, new(big.Int).Mod(in[2], GroupOrder()))
		p.X.BigInt(out[0])
		p.Y.BigInt(out[1])
		return nil
	})
}

func implicitDoubledY(p *big.Int, lambda0, xA, xD, yA *big.Int) *big.Int {
	y := new(big.Int).Sub(xA, xD)
	y.Mul(y, lambda0).Sub(y, yA)
	return y.Mod(y, p)
}

func modRatio(p, num, den *big.Int) *big.Int {
	d := new(big.Int).Mod(den, p)
	if d.Sign() == 0 {
		return new(big.Int)
	}
	d.ModInverse(d, p)
	return d.Mul(d, num).Mod(d, p)
}

func p256ImplicitChordHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 6 || len(out) != 1 {
			return errors.New("expecting six inputs and one output")
		}
		yD := implicitDoubledY(p, in[0], in[1], in[2], in[3])
		out[0].Set(modRatio(p, new(big.Int).Sub(in[5], yD), new(big.Int).Sub(in[4], in[2])))
		return nil
	})
}

func p256ImplicitSecondSlopeHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 5 || len(out) != 1 {
			return errors.New("expecting five inputs and one output")
		}
		yD := implicitDoubledY(p, in[0], in[1], in[2], in[3])
		out[0].Set(modRatio(p, yD.Lsh(yD, 1), new(big.Int).Sub(in[4], in[2])))
		return nil
	})
}

func (c *curve) packedY(y *fpElement) []frontend.Variable {
	api := c.api
	limbs := y.Limbs()
	var out []frontend.Variable
	for g := 0; g < len(limbs); g += packedYGroup {
		sum := frontend.Variable(0)
		for j := g; j < min(g+packedYGroup, len(limbs)); j++ {
			sum = api.Add(sum, api.Mul(limbs[j], pow2(c.lay.LimbBits*(j-g))))
		}
		out = append(out, sum)
	}
	return out
}

func (c *curve) unpackedY(packed []frontend.Variable) *fpElement {
	widths := c.fp.ReducedWidths()
	n := len(widths)
	ys := make([]frontend.Variable, n)
	lo, hi := make([]*big.Int, n), make([]*big.Int, n)
	for j := range ys {
		ys[j] = 0
		lo[j], hi[j] = new(big.Int), new(big.Int)
		if j%packedYGroup != 0 {
			continue
		}
		bits := 0
		for _, w := range widths[j:min(j+packedYGroup, n)] {
			bits += w
		}
		ys[j] = packed[j/packedYGroup]
		hi[j].Sub(pow2(bits), big.NewInt(1))
		lo[j].Neg(hi[j])
	}
	return c.fp.WithBounds(ys, lo, hi)
}

func (c *curve) packedTableLookup(slots []*point, halves []frontend.Variable, s1bits, s2bits []frontend.Variable) func(i int, natives []frontend.Variable) (*point, frontend.Variable) {
	api, fp := c.api, c.fp
	widths := fp.ReducedWidths()
	nbLimbs := len(widths)
	nbPacked := (nbLimbs + packedYGroup - 1) / packedYGroup
	table := newRowTable(api, nbLimbs+nbPacked+1)
	for idx := 0; idx < 16; idx++ {
		sx := idx
		if idx >= 8 {
			sx = 15 - idx
		}
		slot := slots[sx]
		if !slot.X.IsReduced(widths) || !slot.Y.IsReduced(widths) {
			panic("table points must be reduced")
		}
		y := slot.Y
		if idx&1 == 0 {
			y = fp.Neg(y)
		}
		row := append(append([]frontend.Variable{}, slot.X.Limbs()...), c.packedY(y)...)
		table.insert(append(row, halves[sx]))
	}
	return func(i int, _ []frontend.Variable) (*point, frontend.Variable) {
		selector := api.Add(s1bits[i], api.Mul(s2bits[i], 2), api.Mul(s1bits[i-1], 4), api.Mul(s2bits[i-1], 8))
		cols := table.lookup(selector)
		return &point{X: fp.Reduced(cols[:nbLimbs]), Y: c.unpackedY(cols[nbLimbs : nbLimbs+nbPacked])}, cols[nbLimbs+nbPacked]
	}
}

func (c *curve) muxSlot(slots []*point, natives []frontend.Variable, b0, b1, b2, b3 frontend.Variable) (*point, frontend.Variable) {
	api, fp := c.api, c.fp
	widths := fp.ReducedWidths()
	for _, slot := range slots {
		if !slot.X.IsReduced(widths) || !slot.Y.IsReduced(widths) {
			panic("table points must be reduced")
		}
	}
	sel := []frontend.Variable{api.Xor(b0, b3), api.Xor(b1, b3), api.Xor(b2, b3)}
	mux := func(column func(int) []frontend.Variable) []frontend.Variable {
		level := make([][]frontend.Variable, len(slots))
		for i := range slots {
			level[i] = column(i)
		}
		for _, bit := range sel {
			next := make([][]frontend.Variable, len(level)/2)
			for j := range next {
				next[j] = make([]frontend.Variable, len(level[2*j]))
				for l := range next[j] {
					next[j][l] = api.Select(bit, level[2*j+1][l], level[2*j][l])
				}
			}
			level = next
		}
		return level[0]
	}
	xs := mux(func(i int) []frontend.Variable {
		if natives == nil {
			return slots[i].X.Limbs()
		}
		return append(append([]frontend.Variable{}, slots[i].X.Limbs()...), natives[i])
	})
	var native frontend.Variable
	if natives != nil {
		native, xs = xs[len(xs)-1], xs[:len(xs)-1]
	}
	packed := mux(func(i int) []frontend.Variable { return c.packedY(slots[i].Y) })
	sign := api.Sub(api.Mul(b0, 2), 1)
	for g := range packed {
		packed[g] = api.Mul(sign, packed[g])
	}
	return &point{X: fp.Reduced(xs), Y: c.unpackedY(packed)}, native
}

func (c *curve) halfTangentSlope(t *point) *fpElement {
	fp := c.fp
	lambda := c.slope(p256HalfTangentHint, 1, nil, t.X, t.Y)[0]
	square := fp.Lazy(T(1, lambda, lambda))
	fp.AssertZero(T(1, square, square), T(-6, square, t.X), T(-8, lambda, t.Y), T(-3, t.X, t.X), T(-4, c.a))
	return lambda
}

func (c *curve) assertDistinctSlope(lambda *fpElement, other frontend.Variable) {
	api := c.api
	p := c.fp.Modulus()
	pp := new(big.Int).Mul(p, p)
	value := c.nativeValue(lambda)
	factor := func(d frontend.Variable) frontend.Variable {
		return api.Mul(d, api.Sub(api.Mul(d, d), pp))
	}
	api.AssertIsDifferent(api.Mul(factor(api.Sub(value, other)), factor(api.Add(value, other))), 0)
}

func p256HalfTangentHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 2 || len(out) != 1 {
			return errors.New("expecting a point and one output")
		}
		var t secp256r1.G1Affine
		t.X.SetBigInt(in[0])
		t.Y.SetBigInt(in[1])
		half := new(big.Int).ModInverse(big.NewInt(2), GroupOrder())
		t.ScalarMultiplication(&t, half)
		var x, y big.Int
		t.X.BigInt(&x)
		t.Y.BigInt(&y)
		num := new(big.Int).Mul(&x, &x)
		num.Sub(num, big.NewInt(1)).Mul(num, big.NewInt(3))
		out[0].Set(modRatio(p, num, new(big.Int).Lsh(&y, 1)))
		return nil
	})
}
