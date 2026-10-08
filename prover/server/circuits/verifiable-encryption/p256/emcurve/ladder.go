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

const (
	halfScalarBits = 129
	packedYGroup   = 3
)

func (c *curve) scalarMulChecked(inputPoint *point, scalar *frElement) *point {
	fr, fp, api := c.fr, c.fp, c.api
	// 1. Constrain the signed rational decomposition and its nonzero denominator.
	decomposition, err := api.Compiler().NewHint(p256DecomposeScalarHint, 1+2*halfScalarBits, c.limbHintInputs(scalar.Limbs())...)
	if err != nil {
		panic(fmt.Sprintf("decompose hint: %v", err))
	}
	for _, b := range decomposition {
		api.AssertIsBoolean(b)
	}
	negateResult := decomposition[0]
	numeratorBits := decomposition[1 : 1+halfScalarBits]
	denominatorBits := decomposition[1+halfScalarBits:]
	numerator := c.scalarFromBits(numeratorBits)
	denominator := c.scalarFromBits(denominatorBits)
	signedDenominator := fr.Select(negateResult, fr.Neg(denominator), denominator)
	fr.AssertZero(T(1, scalar, signedDenominator), T(1, numerator))
	api.AssertIsDifferent(api.Add(denominatorBits[0], denominatorBits[1], denominatorBits[2:]...), 0)

	// 2. Obtain a candidate product and constrain it to the curve.
	hinted := fp.Hint(p256ScalarMulHint, 2, nil, inputPoint.X, inputPoint.Y, scalar)
	product := &point{X: hinted[0], Y: hinted[1]}
	c.assertOnCurve(product)

	// 3. Build signed multiples and reject the exceptional x-coordinate collisions.
	tripledInput := c.triple(inputPoint)
	signedProduct := &point{X: product.X, Y: fp.Select(negateResult, fp.Neg(product.Y), product.Y)}
	tripledProduct := c.triple(signedProduct)
	c.assertDistinctX(product.X, inputPoint.X)
	c.assertDistinctX(product.X, tripledInput.X)
	c.assertDistinctX(tripledProduct.X, inputPoint.X)
	negatedInput := c.neg(inputPoint)
	negatedProduct := c.neg(signedProduct)

	// 4. Build the joint multiplication table and select entries two bits at a time.
	acc := c.add(inputPoint, signedProduct)
	tripledInputPlusTripledProduct := c.add(tripledInput, tripledProduct)
	tripledInputPlusProduct := c.add(tripledInput, signedProduct)
	inputPlusTripledProduct := c.add(inputPoint, tripledProduct)
	inputMinusProduct := c.add(negatedProduct, inputPoint)
	negatedTripledProduct := c.neg(tripledProduct)
	slots := []*point{
		tripledInputPlusTripledProduct,
		c.add(inputPoint, negatedTripledProduct),
		c.add(tripledInput, negatedProduct),
		acc,
		inputPlusTripledProduct,
		c.add(tripledInput, negatedTripledProduct),
		inputMinusProduct,
		tripledInputPlusProduct,
	}
	decompositionBits := halfScalarBits + 1
	halfTangentSlopes := make([]frontend.Variable, len(slots))
	for i, slot := range slots {
		halfTangentSlopes[i] = c.nativeValue(c.halfTangentSlope(slot))
	}
	lookup := func(i int, natives []frontend.Variable) (*point, frontend.Variable) {
		return c.muxSlot(slots, natives, numeratorBits[i], denominatorBits[i], numeratorBits[i-1], denominatorBits[i-1])
	}
	if c.layout.Lookups {
		lookup = c.packedTableLookup(slots, halfTangentSlopes, numeratorBits, denominatorBits)
	}
	// 5. Check the ladder relation, then account for the two low bits.
	for i := decompositionBits - 2; i > 2; i -= 2 {
		selectedPoint, halfTangentSlope := lookup(i, halfTangentSlopes)
		acc = c.quadrupleAndAddLazy(acc, selectedPoint, halfTangentSlope)
	}
	last, _ := lookup(2, nil)
	acc = c.quadrupleAndAddLazy(acc, c.guardedAdd(last, tripledProduct), nil)
	acc = &point{X: fp.Eval(T(1, acc.X)), Y: acc.Y}

	acc = c.selectPoint(numeratorBits[0], acc, c.guardedAddReducing(negatedInput, acc, true, false))
	acc = c.selectPoint(denominatorBits[0], acc, c.guardedAddReducing(negatedProduct, acc, false, false))
	// 6. Require the final relation to bind the hinted product to the input scalar.
	c.assertEqual(acc, tripledProduct)
	return product
}

func (c *curve) quadrupleAndAddLazy(accumulator, selectedPoint *point, halfSlope frontend.Variable) *point {
	fp := c.fp
	tangentSlope := c.tangent(accumulator)
	doubledX := fp.Lazy(T(1, tangentSlope, tangentSlope), T(-2, accumulator.X))
	doubledY := fp.Lazy(T(1, tangentSlope, fp.Sub(accumulator.X, doubledX)), T(-1, accumulator.Y))
	xDifference := fp.Sub(selectedPoint.X, doubledX)
	chordSlope := c.hintSlope(p256ImplicitChordHint, 1, nil, tangentSlope, accumulator.X, doubledX, accumulator.Y, selectedPoint.X, selectedPoint.Y)[0]
	fp.AssertZero(T(1, chordSlope, xDifference), T(-1, selectedPoint.Y), T(1, doubledY))
	if halfSlope != nil {
		c.assertDistinctSlope(tangentSlope, halfSlope)
	} else {
		xSum := fp.Add(doubledX, selectedPoint.X)
		fp.AssertZero(T(1, chordSlope, fp.Add(doubledY, selectedPoint.Y)), T(-1, xSum, xSum), T(1, doubledX, selectedPoint.X), T(-1, c.a))
	}
	intermediateX := fp.Lazy(T(1, chordSlope, chordSlope), T(-1, doubledX), T(-1, selectedPoint.X))
	secondSlope := c.hintSlope(p256ImplicitSecondSlopeHint, 1, nil, tangentSlope, accumulator.X, doubledX, accumulator.Y, intermediateX)[0]
	fp.AssertZero(T(1, secondSlope, fp.Sub(intermediateX, doubledX)), T(2, chordSlope, xDifference), T(-2, selectedPoint.Y))
	sumX := fp.Lazy(T(1, secondSlope, fp.Lin([]int64{1, 2}, secondSlope, chordSlope)), T(1, selectedPoint.X))
	sumY := fp.Lazy(T(1, fp.Add(chordSlope, secondSlope), fp.Sub(sumX, doubledX)), T(1, chordSlope, xDifference), T(-1, selectedPoint.Y))
	return &point{X: sumX, Y: sumY}
}

func (c *curve) guardedAdd(p, q *point) *point {
	c.assertDistinctX(p.X, q.X)
	return c.add(p, q)
}

func (c *curve) guardedAddReducing(p, q *point, reduceX, reduceY bool) *point {
	c.assertDistinctX(p.X, q.X)
	return c.addReducing(p, q, reduceX, reduceY)
}

func (c *curve) scalarFromBits(bits []frontend.Variable) *frElement {
	var limbs []frontend.Variable
	var widths []int
	for i := 0; i < len(bits); i += c.layout.LimbBits {
		end := min(len(bits), i+c.layout.LimbBits)
		chunk := bits[i:end]
		limbs = append(limbs, c.api.FromBinary(chunk...))
		widths = append(widths, len(chunk))
	}
	return c.fr.Bounded(limbs, widths)
}

func (c *curve) packedTableLookup(slots []*point, halfTangentSlopes []frontend.Variable, numeratorBits, denominatorBits []frontend.Variable) func(i int, natives []frontend.Variable) (*point, frontend.Variable) {
	api, fp := c.api, c.fp
	widths := fp.ReducedWidths()
	nbLimbs := len(widths)
	packedYCount := (nbLimbs + packedYGroup - 1) / packedYGroup
	table := newRowTable(api, nbLimbs+packedYCount+1)
	for idx := 0; idx < 16; idx++ {
		slotIndex := idx
		if idx >= 8 {
			slotIndex = 15 - idx
		}
		slot := slots[slotIndex]
		if !slot.X.IsReduced(widths) || !slot.Y.IsReduced(widths) {
			panic("table points must be reduced")
		}
		y := slot.Y
		if idx&1 == 0 {
			y = fp.Neg(y)
		}
		row := append(append([]frontend.Variable{}, slot.X.Limbs()...), c.packedY(y)...)
		table.insert(append(row, halfTangentSlopes[slotIndex]))
	}
	return func(i int, _ []frontend.Variable) (*point, frontend.Variable) {
		selector := api.Add(numeratorBits[i], api.Mul(denominatorBits[i], 2), api.Mul(numeratorBits[i-1], 4), api.Mul(denominatorBits[i-1], 8))
		columns := table.lookup(selector)
		packedYEnd := nbLimbs + packedYCount
		xLimbs := columns[:nbLimbs]
		packedYLimbs := columns[nbLimbs:packedYEnd]
		halfTangentSlope := columns[packedYEnd]
		return &point{X: fp.Reduced(xLimbs), Y: c.unpackedY(packedYLimbs)}, halfTangentSlope
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
	selectorBits := []frontend.Variable{api.Xor(b0, b3), api.Xor(b1, b3), api.Xor(b2, b3)}
	mux := func(column func(int) []frontend.Variable) []frontend.Variable {
		level := make([][]frontend.Variable, len(slots))
		for i := range slots {
			level[i] = column(i)
		}
		for _, bit := range selectorBits {
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
	xLimbs := mux(func(i int) []frontend.Variable {
		if natives == nil {
			return slots[i].X.Limbs()
		}
		return append(append([]frontend.Variable{}, slots[i].X.Limbs()...), natives[i])
	})
	var native frontend.Variable
	if natives != nil {
		native, xLimbs = xLimbs[len(xLimbs)-1], xLimbs[:len(xLimbs)-1]
	}
	packedYLimbs := mux(func(i int) []frontend.Variable { return c.packedY(slots[i].Y) })
	sign := api.Sub(api.Mul(b0, 2), 1)
	for g := range packedYLimbs {
		packedYLimbs[g] = api.Mul(sign, packedYLimbs[g])
	}
	return &point{X: fp.Reduced(xLimbs), Y: c.unpackedY(packedYLimbs)}, native
}

func (c *curve) packedY(y *fpElement) []frontend.Variable {
	api := c.api
	limbs := y.Limbs()
	var packedLimbs []frontend.Variable
	for g := 0; g < len(limbs); g += packedYGroup {
		sum := frontend.Variable(0)
		for j := g; j < min(g+packedYGroup, len(limbs)); j++ {
			sum = api.Add(sum, api.Mul(limbs[j], pow2(c.layout.LimbBits*(j-g))))
		}
		packedLimbs = append(packedLimbs, sum)
	}
	return packedLimbs
}

func (c *curve) unpackedY(packed []frontend.Variable) *fpElement {
	widths := c.fp.ReducedWidths()
	limbCount := len(widths)
	yLimbs := make([]frontend.Variable, limbCount)
	lowerBounds, upperBounds := make([]*big.Int, limbCount), make([]*big.Int, limbCount)
	for j := range yLimbs {
		yLimbs[j] = 0
		lowerBounds[j], upperBounds[j] = new(big.Int), new(big.Int)
		if j%packedYGroup != 0 {
			continue
		}
		bits := 0
		for _, w := range widths[j:min(j+packedYGroup, limbCount)] {
			bits += w
		}
		yLimbs[j] = packed[j/packedYGroup]
		upperBounds[j].Sub(pow2(bits), big.NewInt(1))
		lowerBounds[j].Neg(upperBounds[j])
	}
	return c.fp.WithBounds(yLimbs, lowerBounds, upperBounds)
}

func (c *curve) halfTangentSlope(t *point) *fpElement {
	fp := c.fp
	lambda := c.hintSlope(p256HalfTangentHint, 1, nil, t.X, t.Y)[0]
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

func (c *curve) assertDistinctX(p, q *fpElement) {
	c.api.AssertIsDifferent(c.distinctProduct(p, q), 0)
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

func (c *curve) nativeValue(e *fpElement) frontend.Variable {
	sum := frontend.Variable(0)
	for i, l := range e.Limbs() {
		sum = c.api.Add(sum, c.api.Mul(l, pow2(c.layout.LimbBits*i)))
	}
	return sum
}

func p256DecomposeScalarHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(outputs) != 1+2*halfScalarBits {
		return errors.New("expecting the sign and bit outputs")
	}
	scalar := limbHintValue(inputs)
	groupOrder := GroupOrder()
	fraction := lattice.NewReconstructor(groupOrder).RationalReconstruct(scalar.Mod(scalar, groupOrder))
	numerator, denominator := new(big.Int).Set(fraction[0]), new(big.Int).Set(fraction[1])
	if numerator.Sign() < 0 {
		numerator.Neg(numerator)
		denominator.Neg(denominator)
	}
	outputs[0].SetUint64(0)
	if denominator.Sign() > 0 {
		outputs[0].SetUint64(1)
	}
	denominator.Abs(denominator)
	for i := 0; i < halfScalarBits; i++ {
		outputs[1+i].SetUint64(uint64(numerator.Bit(i)))
		outputs[1+halfScalarBits+i].SetUint64(uint64(denominator.Bit(i)))
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

func modRatio(p, numerator, denominator *big.Int) *big.Int {
	inverseDenominator := new(big.Int).Mod(denominator, p)
	if inverseDenominator.Sign() == 0 {
		return new(big.Int)
	}
	inverseDenominator.ModInverse(inverseDenominator, p)
	return inverseDenominator.Mul(inverseDenominator, numerator).Mod(inverseDenominator, p)
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

func init() {
	solver.RegisterHint(p256DecomposeScalarHint, p256ScalarMulHint, p256ImplicitChordHint, p256ImplicitSecondSlopeHint, p256HalfTangentHint)
}
