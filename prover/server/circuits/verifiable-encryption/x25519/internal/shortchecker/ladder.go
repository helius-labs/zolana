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

package shortchecker

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/algebra/lattice"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/lookup"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/r1c"
)

func init() {
	solver.RegisterHint(shortDecomposeScalarHint, shortScalarMulHint, shortImplicitChordHint, shortImplicitSecondSlopeHint)
}

const (
	halfScalarBits = 129
	packedXGroup   = 2
)

func (c *curve) nativeValue(e *fpElement) frontend.Variable {
	sum := frontend.Variable(0)
	for i, l := range e.Limbs() {
		sum = c.api.Add(sum, c.api.Mul(l, pow2(c.lay.LimbBits*i)))
	}
	return sum
}

func (c *curve) assertDistinctX(a, b *fpElement) {
	widths := c.fp.ReducedWidths()
	if !a.IsReduced(widths) || !b.IsReduced(widths) {
		panic("x25519: distinct point guard needs reduced coordinates")
	}
	pack := func(e *fpElement, start, end int) frontend.Variable {
		out := frontend.Variable(0)
		for i := start; i < end; i++ {
			out = c.api.Add(out, c.api.Mul(e.Limbs()[i], pow2((i-start)*c.lay.LimbBits)))
		}
		return out
	}
	cut := (c.lay.NbLimbs + 1) / 2
	B := pow2(cut * c.lay.LimbBits)
	mask := new(big.Int).Sub(B, big.NewInt(1))
	p := prime()
	pl := new(big.Int).And(p, mask)
	ph := new(big.Int).Rsh(p, uint(cut*c.lay.LimbBits))
	lo := c.api.Sub(pack(a, 0, cut), pack(b, 0, cut))
	hi := c.api.Sub(pack(a, cut, c.lay.NbLimbs), pack(b, cut, c.lay.NbLimbs))
	// For reduced noncanonical coordinates in[0,2^255), equal Fp values
	// differ by0 or±p. Since p=2^255-19, only these three packed pairs are
	// possible; a low-half borrow would need a high difference of±2^(255-cut).
	for _, k := range []int64{-1, 0, 1} {
		dl := c.api.Sub(lo, new(big.Int).Mul(big.NewInt(k), pl))
		dh := c.api.Sub(hi, new(big.Int).Mul(big.NewInt(k), ph))
		inv, err := c.api.Compiler().NewHint(shortPackedNonzeroHint, 2, dl, dh)
		if err != nil {
			panic(err)
		}
		r1c.AssertProduct(c.api, inv[1], dh, c.api.Sub(1, c.api.Mul(inv[0], dl)))
	}
}

func (c *curve) quadrupleAndAddLazy(a, t *point) *point {
	fp := c.fp
	lambda0 := c.tangent(a)
	xD := fp.Lazy(T(1, lambda0, lambda0), T(-2, a.X))
	tMinusD := fp.Sub(t.X, xD)
	lambda1 := c.slope(shortImplicitChordHint, 1, nil, lambda0, a.X, xD, a.Y, t.X, t.Y, c.a)[0]
	yChord := fp.Lazy(T(1, lambda1, tMinusD))
	fp.AssertZeroProjected(T(1, yChord), T(1, lambda0, fp.Sub(a.X, xD)), T(-1, a.Y), T(-1, t.Y))
	x2 := fp.Lazy(T(1, lambda1, lambda1), T(-1, xD), T(-1, t.X))
	mu := c.slope(shortImplicitSecondSlopeHint, 1, nil, lambda0, a.X, xD, a.Y, x2)[0]
	fp.AssertZeroProjected(T(1, mu, fp.Sub(x2, xD)), T(2, lambda1, tMinusD), T(-2, t.Y))
	c.assertLadderOutputDistinct(lambda1, mu)
	eta := fp.Add(lambda1, mu)
	x3 := fp.Lazy(T(1, eta, eta), T(-1, lambda1, lambda1), T(1, t.X))
	y3 := fp.Lazy(T(1, eta, fp.Sub(x3, xD)), T(1, yChord), T(-1, t.Y))
	return &point{X: x3, Y: y3}
}

func (c *curve) guardedAdd(p, q *point) *point {
	c.assertDistinctX(p.X, q.X)
	return c.add(p, q)
}

func (c *curve) scalarMulChecked(q *point, s *frElement) *point {
	native := c.nativeValue(s)
	third0 := new(big.Int).ModInverse(big.NewInt(3), order(false))
	third1 := new(big.Int).ModInverse(big.NewInt(3), order(true))
	selected := c.api.Select(c.twist, third1, third0)
	exceptional := c.api.IsZero(c.api.Sub(native, selected))
	sixth0 := new(big.Int).ModInverse(big.NewInt(6), order(false))
	sixth1 := new(big.Int).ModInverse(big.NewInt(6), order(true))
	half := c.fp.Select(c.twist, c.fp.Const(sixth1), c.fp.Const(sixth0))
	return c.scalarMulLadder(c.selectPoint(exceptional, c.double(q), q), c.fp.Select(exceptional, half, s))
}

func (c *curve) scalarMulLadder(q *point, s *frElement) *point {
	fr, fp, api := c.fr, c.fp, c.api
	decomposition, err := api.Compiler().NewHint(shortDecomposeScalarHint, 1+2*halfScalarBits, append([]frontend.Variable{c.twist}, c.limbHintInputs(s.Limbs())...)...)
	if err != nil {
		panic(fmt.Sprintf("decompose hint: %v", err))
	}
	sign := decomposition[0]
	api.AssertIsBoolean(sign)
	s1bits := decomposition[1 : 1+halfScalarBits]
	s2bits := decomposition[1+halfScalarBits:]
	var s1, s2 *frElement
	var s1digits, s2digits []frontend.Variable
	var s1Top, s2Top frontend.Variable
	if c.lay.Lookups {
		// Bits above bit 0 are consumed only through their radix-four digit.
		// Bounding the digit is sufficient; the constituent hint values need
		// not themselves be Boolean. Keep the hint's existing output shape.
		s1digits = c.radixFourDigits(s1bits)
		s2digits = c.radixFourDigits(s2bits)
		s1Top, s2Top = s1digits[len(s1digits)-1], s2digits[len(s2digits)-1]
		s1 = c.scalarFromRadixFour(s1bits[0], s1digits)
		s2 = c.scalarFromRadixFour(s2bits[0], s2digits)
		api.AssertIsDifferent(api.Add(s2bits[0], s2digits[0], s2digits[1:]...), 0)
	} else {
		for _, bits := range [][]frontend.Variable{s1bits, s2bits} {
			api.AssertIsEqual(bits[halfScalarBits-1], 0)
			for _, b := range bits[:halfScalarBits-1] {
				api.AssertIsBoolean(b)
			}
		}
		s1 = c.scalarFromBits(s1bits[:halfScalarBits-1])
		s2 = c.scalarFromBits(s2bits[:halfScalarBits-1])
		s1Top, s2Top = s1bits[halfScalarBits-2], s2bits[halfScalarBits-2]
		api.AssertIsDifferent(api.Add(s2bits[0], s2bits[1], s2bits[2:]...), 0)
	}
	c.scalarZero(T(1, s, fr.Select(sign, fr.Neg(s2), s2)), T(1, s1))

	hinted := fp.Hint(shortScalarMulHint, 2, []frontend.Variable{c.twist}, q.X, q.Y, s)
	r := &point{X: hinted[0], Y: hinted[1]}
	c.assertOnCurve(r)
	c.assertSubgroup(r)

	q3 := c.triple(q)
	rSigned := &point{X: r.X, Y: fp.Select(sign, fp.Neg(r.Y), r.Y)}
	r3 := c.triple(rSigned)
	// Nonidentity prime-order R has 3R != ±R because its order exceeds four.
	r4 := c.add(r3, rSigned)
	c.assertDistinctX(r.X, q.X)
	c.assertDistinctX(r.X, q3.X)
	c.assertDistinctX(r3.X, q.X)
	negR := c.neg(rSigned)

	acc := c.add(q, rSigned)
	t1 := c.add(q3, r3)
	t2 := acc
	t3 := c.add(q3, rSigned)
	t4 := c.add(q, r3)
	t12 := c.add(negR, q)
	negR3 := c.neg(r3)
	slots := []*point{t1, c.add(q, negR3), c.add(q3, negR), t2, t4, c.add(q3, negR3), t12, t3}
	// Both subgroup orders give reconstructed halves strictly below2^127.
	// Thus bit127 is also zero and the leading folded step is Q+R.
	api.AssertIsEqual(s1Top, 0)
	api.AssertIsEqual(s2Top, 0)
	acc = t2
	lookup := func(i int) *point {
		return c.muxSlot(slots, s1bits[i], s2bits[i], s1bits[i-1], s2bits[i-1])
	}
	if c.lay.Lookups {
		lookup = c.packedTableLookup(slots, s1digits, s2digits)
	}
	for i := halfScalarBits - 3; i > 2; i -= 2 {
		acc = c.quadrupleAndAddLazy(acc, lookup(i))
	}
	acc = c.quadrupleAndAddLazy(acc, c.guardedAdd(lookup(2), r3))
	// Rational reconstruction returns coprime halves, so at least one is
	// odd. The uncorrected accumulator therefore equals one of 3R, 4R,
	// or Q+3R, all already certified on-curve. Equality to that point also
	// supplies the final curve membership needed by the backwards proof.
	api.AssertIsDifferent(api.Add(s1bits[0], s2bits[0]), 0)
	target := c.selectPoint(s1bits[0], c.selectPoint(s2bits[0], r3, r4), t4)
	c.assertEqual(acc, target)
	return r
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

func (c *curve) radixFourDigits(bits []frontend.Variable) []frontend.Variable {
	c.api.AssertIsBoolean(bits[0])
	digits := make([]frontend.Variable, (len(bits)-1)/2)
	for i := range digits {
		digits[i] = c.api.Add(bits[1+2*i], c.api.Mul(bits[2+2*i], 2))
		width := 2
		if i == len(digits)-1 {
			width = 1
		}
		c.rangeChecker().Check(digits[i], width)
	}
	return digits
}

func (c *curve) scalarFromRadixFour(low frontend.Variable, digits []frontend.Variable) *frElement {
	values := append([]frontend.Variable{low}, digits...)
	widths := make([]int, len(values))
	widths[0] = 1
	for i := 1; i < len(widths); i++ {
		widths[i] = 2
	}
	widths[len(widths)-1] = 1
	var limbs []frontend.Variable
	var limbWidths []int
	var limb frontend.Variable = 0
	used := 0
	for i, v := range values {
		width := widths[i]
		available := c.lay.LimbBits - used
		if width > available {
			// Only the radix-four digit straddling an odd limb boundary needs bits.
			split := c.api.ToBinary(v, width)
			limb = c.api.Add(limb, c.api.Mul(c.api.FromBinary(split[:available]...), pow2(used)))
			limbs = append(limbs, limb)
			limbWidths = append(limbWidths, c.lay.LimbBits)
			limb = c.api.FromBinary(split[available:]...)
			used = width - available
		} else {
			limb = c.api.Add(limb, c.api.Mul(v, pow2(used)))
			used += width
			if used == c.lay.LimbBits {
				limbs = append(limbs, limb)
				limbWidths = append(limbWidths, used)
				limb = 0
				used = 0
			}
		}
	}
	if used > 0 {
		limbs = append(limbs, limb)
		limbWidths = append(limbWidths, used)
	}
	return c.fr.Bounded(limbs, limbWidths)
}

func shortDecomposeScalarHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(outputs) != 1+2*halfScalarBits {
		return errors.New("expecting the sign and bit outputs")
	}
	s := limbHintValue(inputs[1:])
	n := order(inputs[0].Sign() != 0)
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

func shortScalarMulHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, n, in, out []*big.Int) error {
		if len(n) != 1 || len(in) != 3 || len(out) != 2 {
			return errors.New("scalar mul shape")
		}
		a, _ := coefficients(n[0].Sign() != 0)
		r := hostMul(hostPoint{in[0], in[1]}, in[2], a)
		if r.x == nil {
			return errors.New("scalar mul infinity")
		}
		out[0].Set(r.x)
		out[1].Set(r.y)
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

func shortImplicitChordHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 7 || len(out) != 1 {
			return errors.New("expecting seven inputs and one output")
		}
		yD := implicitDoubledY(p, in[0], in[1], in[2], in[3])
		dx := new(big.Int).Sub(in[4], in[2])
		dy := new(big.Int).Sub(in[5], yD)
		if new(big.Int).Mod(dx, p).Sign() == 0 && new(big.Int).Mod(dy, p).Sign() == 0 {
			// Equality to the known on-curve final target pins this tangent.
			num := new(big.Int).Mul(in[2], in[2])
			num.Mul(num, big.NewInt(3)).Add(num, in[6])
			out[0].Set(modRatio(p, num, new(big.Int).Lsh(yD, 1)))
			return nil
		}
		out[0].Set(modRatio(p, dy, dx))
		return nil
	})
}

func shortImplicitSecondSlopeHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 5 || len(out) != 1 {
			return errors.New("expecting five inputs and one output")
		}
		yD := implicitDoubledY(p, in[0], in[1], in[2], in[3])
		out[0].Set(modRatio(p, yD.Lsh(yD, 1), new(big.Int).Sub(in[4], in[2])))
		return nil
	})
}

func (c *curve) packedCoordinate(e *fpElement, group int) []frontend.Variable {
	api := c.api
	limbs := e.Limbs()
	var out []frontend.Variable
	for g := 0; g < len(limbs); g += group {
		sum := frontend.Variable(0)
		for j := g; j < min(g+group, len(limbs)); j++ {
			sum = api.Add(sum, api.Mul(limbs[j], pow2(c.lay.LimbBits*(j-g))))
		}
		out = append(out, sum)
	}
	return out
}

func (c *curve) unpackedCoordinate(packed []frontend.Variable, group int, signed bool) *fpElement {
	widths := c.fp.ReducedWidths()
	n := len(widths)
	limbs := make([]frontend.Variable, n)
	lo, hi := make([]*big.Int, n), make([]*big.Int, n)
	for j := range limbs {
		limbs[j] = 0
		lo[j], hi[j] = new(big.Int), new(big.Int)
		if j%group != 0 {
			continue
		}
		bits := 0
		for _, w := range widths[j:min(j+group, n)] {
			bits += w
		}
		limbs[j] = packed[j/group]
		hi[j].Sub(pow2(bits), big.NewInt(1))
		if signed {
			lo[j].Neg(hi[j])
		}
	}
	return c.fp.WithBounds(limbs, lo, hi)
}

func (c *curve) packedTableLookup(slots []*point, s1digits, s2digits []frontend.Variable) func(i int) *point {
	api, fp := c.api, c.fp
	widths := fp.ReducedWidths()
	nbLimbs := len(widths)
	nbPackedX := (nbLimbs + packedXGroup - 1) / packedXGroup
	nbPackedY := (nbLimbs + c.packedYGroup() - 1) / c.packedYGroup()
	table := lookup.New(api, nbPackedX+nbPackedY)
	for idx := 0; idx < 16; idx++ {
		// The radix-four selector lists each scalar's low bit first. The
		// joint ladder's slot ordering lists the high bits first instead.
		bitIndex := (idx>>1)&1 | ((idx>>3)&1)<<1 | (idx&1)<<2 | ((idx>>2)&1)<<3
		sx := bitIndex
		if bitIndex >= 8 {
			sx = 15 - bitIndex
		}
		slot := slots[sx]
		if !slot.X.IsReduced(widths) || !slot.Y.IsReduced(widths) {
			panic("table points must be reduced")
		}
		y := slot.Y
		if bitIndex&1 == 0 {
			y = fp.Neg(y)
		}
		row := append(c.packedCoordinate(slot.X, packedXGroup), c.packedCoordinate(y, c.packedYGroup())...)
		table.Insert(row)
	}
	return func(i int) *point {
		digit := (i - 2) / 2
		selector := api.Add(s1digits[digit], api.Mul(s2digits[digit], 4))
		cols := table.Lookup(selector)
		x := c.unpackedCoordinate(cols[:nbPackedX], packedXGroup, false)
		if i == 2 {
			// The final guarded addition compares reduced X coordinates.
			x = fp.Eval(T(1, x))
		}
		return &point{X: x, Y: c.unpackedCoordinate(cols[nbPackedX:nbPackedX+nbPackedY], c.packedYGroup(), true)}
	}
}

func (c *curve) muxSlot(slots []*point, b0, b1, b2, b3 frontend.Variable) *point {
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
	xs := mux(func(i int) []frontend.Variable { return slots[i].X.Limbs() })
	packed := mux(func(i int) []frontend.Variable { return c.packedCoordinate(slots[i].Y, c.packedYGroup()) })
	sign := api.Sub(api.Mul(b0, 2), 1)
	for g := range packed {
		packed[g] = api.Mul(sign, packed[g])
	}
	return &point{X: fp.Reduced(xs), Y: c.unpackedCoordinate(packed, c.packedYGroup(), true)}
}

// Keep packed Y below half the native field width because additions square it.
func (c *curve) packedYGroup() int { return min(3, 120/c.lay.LimbBits) }
