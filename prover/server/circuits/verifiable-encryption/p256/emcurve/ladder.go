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
	packedXGroup   = 2
	packedYGroup   = 3
)

func (c *curve) scalarMulChecked(inputPoint *point, scalar *frElement) *point {
	// 1. Canonicalize the scalar so limb comparisons are integer-exact.
	scalar = c.fr.Eval(T(1, scalar))
	c.fr.AssertCanonical(scalar)
	groupOrder := GroupOrder()
	inverseThree := new(big.Int).ModInverse(big.NewInt(3), groupOrder)

	// 2. Identify the ladder's six exceptional residues: ±1, ±3, and ±1/3.
	var exceptional frontend.Variable = 0
	for _, positive := range []*big.Int{big.NewInt(1), big.NewInt(3), inverseThree} {
		negative := new(big.Int).Sub(groupOrder, positive)
		for _, residue := range []*big.Int{positive, negative} {
			residueLimbs := c.fr.Const(residue).Limbs()
			var differenceSquares frontend.Variable = 0
			for i, scalarLimb := range scalar.Limbs() {
				difference := c.api.Sub(scalarLimb, residueLimbs[i])
				differenceSquares = c.api.Add(differenceSquares, c.api.Mul(difference, difference))
			}
			exceptional = c.api.Add(exceptional, c.api.IsZero(differenceSquares))
		}
	}

	// 3. For those residues, prove [s/2](2Q) = [s]Q with a nonexceptional scalar.
	inverseTwo := c.fr.Const(new(big.Int).ModInverse(big.NewInt(2), groupOrder))
	halfScalar := c.fr.Eval(T(1, scalar, inverseTwo))
	doubledInput := c.double(inputPoint)
	ladderInput := c.selectPoint(exceptional, doubledInput, inputPoint)
	ladderScalar := c.fr.Select(exceptional, halfScalar, scalar)
	return c.scalarMulLadder(ladderInput, ladderScalar)
}

func (c *curve) scalarMulLadder(inputPoint *point, scalar *frElement) *point {
	fr, fp, api := c.fr, c.fp, c.api
	// 1. Constrain the signed rational decomposition and its nonzero denominator.
	decomposition, err := api.Compiler().NewHint(p256DecomposeScalarHint, 1+2*halfScalarBits, c.limbHintInputs(scalar.Limbs())...)
	if err != nil {
		panic(fmt.Sprintf("decompose hint: %v", err))
	}
	negateResult := decomposition[0]
	api.AssertIsBoolean(negateResult)
	numeratorBits := decomposition[1 : 1+halfScalarBits]
	denominatorBits := decomposition[1+halfScalarBits:]
	// Rational reconstruction returns halves below 2^128 (reconstruction_test.go),
	// so bit 128 is zero and the top digit is bit 127 alone.
	// Bits above bit 0 are consumed only through their radix-four digits,
	// so bounding each digit suffices; its two bits need not be Boolean.
	numeratorDigits := c.radixFourDigits(numeratorBits)
	denominatorDigits := c.radixFourDigits(denominatorBits)
	numeratorTop, denominatorTop := numeratorDigits[len(numeratorDigits)-1], denominatorDigits[len(denominatorDigits)-1]
	numerator := c.scalarFromRadixFour(numeratorBits[0], numeratorDigits)
	denominator := c.scalarFromRadixFour(denominatorBits[0], denominatorDigits)
	api.AssertIsDifferent(api.Add(denominatorBits[0], denominatorDigits[0], denominatorDigits[1:]...), 0)
	signedDenominator := fr.Select(negateResult, fr.Neg(denominator), denominator)
	fr.AssertZero(T(1, scalar, signedDenominator), T(1, numerator))

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
	negatedProduct := c.neg(signedProduct)

	// 4. Build the joint multiplication table and select entries two bits at a time.
	inputPlusProduct := c.add(inputPoint, signedProduct)
	tripledInputPlusTripledProduct := c.add(tripledInput, tripledProduct)
	tripledInputPlusProduct := c.add(tripledInput, signedProduct)
	inputPlusTripledProduct := c.add(inputPoint, tripledProduct)
	inputMinusProduct := c.add(negatedProduct, inputPoint)
	negatedTripledProduct := c.neg(tripledProduct)
	slots := []*point{
		tripledInputPlusTripledProduct,
		c.add(inputPoint, negatedTripledProduct),
		c.add(tripledInput, negatedProduct),
		inputPlusProduct,
		inputPlusTripledProduct,
		c.add(tripledInput, negatedTripledProduct),
		inputMinusProduct,
		tripledInputPlusProduct,
	}
	// From Q + R, the leading step over bits 128 and 127 is
	// 4(Q+R) + (2·n127-3)Q + (2·d127-3)R = (1+2·n127)Q + (1+2·d127)R, one of
	// the checked table points.
	acc := c.selectPoint(denominatorTop,
		c.selectPoint(numeratorTop, tripledInputPlusTripledProduct, inputPlusTripledProduct),
		c.selectPoint(numeratorTop, tripledInputPlusProduct, inputPlusProduct))
	lookup := c.packedTableLookup(slots, numeratorDigits, denominatorDigits)
	// 5. Check the ladder relation, then account for the two low bits.
	for i := halfScalarBits - 3; i > 2; i -= 2 {
		acc = c.quadrupleAndAddLazy(acc, lookup(i))
	}
	acc = c.quadrupleAndAddLazy(acc, c.guardedAdd(lookup(2), tripledProduct))
	acc = &point{X: fp.Eval(T(1, acc.X)), Y: acc.Y}

	// 6. Require acc = 3R + (1-d)R + (1-n)Q, assembled on the target side. When
	// n = 1 the discarded sum adds R, which is x-distinct from 3R and 4R for every
	// nonzero R, so the guard on the unselected branch is always satisfiable.
	// The target is built from checked additions of on-curve points, so this
	// equality is the final curve check on the uncorrected ladder output: with
	// each step's output guard it certifies every step (ladder-soundness.md).
	fourTimesProduct := c.guardedAdd(tripledProduct, signedProduct)
	target := c.selectPoint(denominatorBits[0], tripledProduct, fourTimesProduct)
	addend := c.selectPoint(numeratorBits[0], signedProduct, inputPoint)
	target = c.selectPoint(numeratorBits[0], target, c.guardedAdd(addend, target))
	c.assertEqual(acc, target)
	return product
}

func (c *curve) quadrupleAndAddLazyConstrained(accumulator, selectedPoint *point) *point {
	fp := c.fp
	tangentSlope := c.tangent(accumulator)
	doubledX := fp.Lazy(T(1, tangentSlope, tangentSlope), T(-2, accumulator.X))
	xDifference := fp.Sub(selectedPoint.X, doubledX)
	chordSlope := c.hintSlope(p256ImplicitChordHint, 1, nil, tangentSlope, accumulator.X, doubledX, accumulator.Y, selectedPoint.X, selectedPoint.Y)[0]
	chordRise := fp.Lazy(T(1, chordSlope, xDifference))
	fp.AssertZeroProjected(T(1, chordRise), T(1, tangentSlope, fp.Sub(accumulator.X, doubledX)), T(-1, accumulator.Y), T(-1, selectedPoint.Y))
	intermediateX := fp.Lazy(T(1, chordSlope, chordSlope), T(-1, doubledX), T(-1, selectedPoint.X))
	secondSlope := c.hintSlope(p256ImplicitSecondSlopeHint, 1, nil, tangentSlope, accumulator.X, doubledX, accumulator.Y, intermediateX)[0]
	fp.AssertZeroProjected(T(1, secondSlope, fp.Sub(intermediateX, doubledX)), T(2, chordSlope, xDifference), T(-2, selectedPoint.Y))
	c.assertLadderOutputDistinct(chordSlope, secondSlope)
	slopeSum := fp.Add(chordSlope, secondSlope)
	sumX := fp.Lazy(T(1, slopeSum, slopeSum), T(-1, chordSlope, chordSlope), T(1, selectedPoint.X))
	sumY := fp.Lazy(T(1, slopeSum, fp.Sub(sumX, doubledX)), T(1, chordRise), T(-1, selectedPoint.Y))
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

func (c *curve) packedTableLookup(slots []*point, numeratorDigits, denominatorDigits []frontend.Variable) func(i int) *point {
	api, fp := c.api, c.fp
	widths := fp.ReducedWidths()
	nbLimbs := len(widths)
	packedXCount := (nbLimbs + packedXGroup - 1) / packedXGroup
	packedYCount := (nbLimbs + packedYGroup - 1) / packedYGroup
	table := newRowTable(api, packedXCount+packedYCount)
	for idx := 0; idx < 16; idx++ {
		// The selector lists each half's low bit first; the slot order lists
		// the high bits first.
		bitIndex := (idx>>1)&1 | ((idx>>3)&1)<<1 | (idx&1)<<2 | ((idx>>2)&1)<<3
		slotIndex := bitIndex
		if bitIndex >= 8 {
			slotIndex = 15 - bitIndex
		}
		slot := slots[slotIndex]
		if !slot.X.IsReduced(widths) || !slot.Y.IsReduced(widths) {
			panic("table points must be reduced")
		}
		y := slot.Y
		if bitIndex&1 == 0 {
			y = fp.Neg(y)
		}
		table.insert(append(c.packedCoordinate(slot.X, packedXGroup), c.packedCoordinate(y, packedYGroup)...))
	}
	return func(i int) *point {
		digit := (i - 2) / 2
		selector := api.Add(numeratorDigits[digit], api.Mul(denominatorDigits[digit], 4))
		columns := table.lookup(selector)
		x := c.unpackedCoordinate(columns[:packedXCount], packedXGroup, false)
		if i == 2 {
			// The last table point feeds a guarded addition on reduced x.
			x = fp.Eval(T(1, x))
		}
		return &point{X: x, Y: c.unpackedCoordinate(columns[packedXCount:], packedYGroup, true)}
	}
}

// packedCoordinate sums each run of group limbs into one value.
func (c *curve) packedCoordinate(e *fpElement, group int) []frontend.Variable {
	api := c.api
	limbs := e.Limbs()
	var packedLimbs []frontend.Variable
	for g := 0; g < len(limbs); g += group {
		sum := frontend.Variable(0)
		for j := g; j < min(g+group, len(limbs)); j++ {
			sum = api.Add(sum, api.Mul(limbs[j], pow2(c.layout.LimbBits*(j-g))))
		}
		packedLimbs = append(packedLimbs, sum)
	}
	return packedLimbs
}

// unpackedCoordinate places each packed value at the first limb of its run,
// bounded by the run's reduced width, and negated too when signed.
func (c *curve) unpackedCoordinate(packed []frontend.Variable, group int, signed bool) *fpElement {
	widths := c.fp.ReducedWidths()
	limbCount := len(widths)
	limbs := make([]frontend.Variable, limbCount)
	lowerBounds, upperBounds := make([]*big.Int, limbCount), make([]*big.Int, limbCount)
	for j := range limbs {
		limbs[j] = 0
		lowerBounds[j], upperBounds[j] = new(big.Int), new(big.Int)
		if j%group != 0 {
			continue
		}
		bits := 0
		for _, w := range widths[j:min(j+group, limbCount)] {
			bits += w
		}
		limbs[j] = packed[j/group]
		upperBounds[j].Sub(pow2(bits), big.NewInt(1))
		if signed {
			lowerBounds[j].Neg(upperBounds[j])
		}
	}
	return c.fp.WithBounds(limbs, lowerBounds, upperBounds)
}

// radixFourDigits returns d_i = b_(2i+1) + 2·b_(2i+2), each range-checked to
// two bits and the top one to one bit, after checking that b_0 is Boolean.
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

// scalarFromRadixFour returns low + 2·sum_i d_i·4^i with the digit bounds as
// limb widths.
func (c *curve) scalarFromRadixFour(low frontend.Variable, digits []frontend.Variable) *frElement {
	if c.layout.LimbBits%2 != 0 {
		panic("radix-four scalar limbs need an even width")
	}
	digitsPerLimb := c.layout.LimbBits / 2
	var limbs []frontend.Variable
	var widths []int
	for i := 0; i < len(digits); i += digitsPerLimb {
		chunk := digits[i:min(len(digits), i+digitsPerLimb)]
		sum := frontend.Variable(0)
		for j, digit := range chunk {
			sum = c.api.Add(sum, c.api.Mul(digit, pow2(2*j)))
		}
		limbs = append(limbs, sum)
		width := 2 * len(chunk)
		if i+len(chunk) == len(digits) {
			width--
		}
		widths = append(widths, width)
	}
	high := c.fr.Lin([]int64{2}, c.fr.Bounded(limbs, widths))
	return c.fr.Add(high, c.fr.Bounded([]frontend.Variable{low}, []int{1}))
}

// assertLadderOutputDistinctConstrained proves mu*(mu+2*lambda) != 0 modulo
// p, which keeps the step output x-coordinate away from the table point.
// Both slopes come from HintBalanced, so |mu| <= M < p and
// |mu+2*lambda| <= 3M < 2p: the integer representatives of zero modulo p are
// 0 for mu and -p, 0, p for the sum. The native polynomial vanishes on all of
// them, aliases modulo the native field included. A native-field collision
// can reject an honest witness but cannot admit a zero modulo p.
func (c *curve) assertLadderOutputDistinctConstrained(chordSlope, secondSlope *fpElement) {
	balancedBound := new(big.Int)
	for i, w := range c.fp.ReducedWidths() {
		balancedBound.Add(balancedBound, new(big.Int).Lsh(pow2(w-1), uint(c.layout.LimbBits*i)))
	}
	p := c.fp.Modulus()
	if balancedBound.Cmp(p) >= 0 || new(big.Int).Mul(balancedBound, big.NewInt(3)).Cmp(new(big.Int).Lsh(p, 1)) >= 0 {
		panic("ladder output guard needs balanced slope bounds")
	}
	api := c.api
	second := c.nativeValue(secondSlope)
	slopeSum := api.Add(second, api.Mul(c.nativeValue(chordSlope), 2))
	pSquared := new(big.Int).Mul(p, p)
	sumFactor := api.Mul(slopeSum, api.Sub(api.Mul(slopeSum, slopeSum), pSquared))
	api.AssertIsDifferent(api.Mul(second, sumFactor), 0)
}

func (c *curve) assertDistinctXConstrained(p, q *fpElement) {
	c.api.AssertIsDifferent(c.xDifferenceSquares(p, q), 0)
}

// xDifferenceSquares compares canonical 32-bit limbs without reducing a
// 256-bit coordinate into the native field. The sum is below 2^67, so it is
// zero exactly when every limb matches.
func (c *curve) xDifferenceSquares(p, q *fpElement) frontend.Variable {
	widths := c.fp.ReducedWidths()
	if !p.IsReduced(widths) || !q.IsReduced(widths) {
		panic("distinct-x guard needs reduced coordinates")
	}
	c.fp.AssertCanonical(p)
	c.fp.AssertCanonical(q)
	var sum frontend.Variable = 0
	for i, pLimb := range p.Limbs() {
		difference := c.api.Sub(pLimb, q.Limbs()[i])
		sum = c.api.Add(sum, c.api.Mul(difference, difference))
	}
	return sum
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
		xDifference := new(big.Int).Sub(in[4], in[2])
		yDifference := new(big.Int).Sub(in[5], yD)
		if new(big.Int).Mod(xDifference, p).Sign() == 0 && new(big.Int).Mod(yDifference, p).Sign() == 0 {
			// The final curve check pins the tangent in this equal-point case.
			num := new(big.Int).Mul(in[2], in[2])
			num.Sub(num, big.NewInt(1)).Mul(num, big.NewInt(3))
			out[0].Set(modRatio(p, num, new(big.Int).Lsh(yD, 1)))
			return nil
		}
		out[0].Set(modRatio(p, yDifference, xDifference))
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

func init() {
	solver.RegisterHint(p256DecomposeScalarHint, p256ScalarMulHint, p256ImplicitChordHint, p256ImplicitSecondSlopeHint)
}
