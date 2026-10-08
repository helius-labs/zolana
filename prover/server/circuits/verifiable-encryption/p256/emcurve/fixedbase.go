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

type combAffine struct {
	x, y *big.Int
}

type combData struct {
	windowBits, windowCount, scalarBits, topWindowBits int
	windows                                            [][][2]*big.Int
	topEven                                            [][2]*big.Int
}

var (
	combMu     sync.Mutex
	combCached = map[int]*combData{}
)

func (c *curve) scalarMulBase(scalar *frElement) *point {
	// 1. Constrain the parity bit and signed-window recoding of the scalar.
	table := p256Comb(combWindowFor(c.layout))
	api := c.api
	bits, err := api.Compiler().NewHint(p256CombRecodeHint, 1+table.scalarBits, c.limbHintInputs(scalar.Limbs())...)
	if err != nil {
		panic(fmt.Sprintf("recode hint: %v", err))
	}
	for _, b := range bits {
		api.AssertIsBoolean(b)
	}
	parityBit := bits[0]
	recodedBits := bits[1:]
	recodedScalar := c.scalarFromBits(recodedBits)
	c.fr.AssertZero(T(2, recodedScalar), T(1, c.fr.Bounded([]frontend.Variable{parityBit}, []int{1})), T(-1, scalar), T(-1, c.fr.Const(pow2(table.scalarBits))))

	// 2. Select each constant window point and fold the parity correction into the top window.
	windowBits, windowCount := table.windowBits, table.windowCount
	windowPoints := make([]*point, windowCount)
	for t := 0; t < windowCount-1; t++ {
		start := t * windowBits
		end := start + windowBits
		windowPoints[t] = c.combSelect(table.windows[t], recodedBits[start:end], true)
	}
	stacked := append(append([][2]*big.Int{}, table.topEven...), table.windows[windowCount-1]...)
	topBits := append(append([]frontend.Variable{}, recodedBits[(windowCount-1)*windowBits:]...), parityBit)
	windowPoints[windowCount-1] = c.combSelect(stacked, topBits, false)

	// 3. Check the addition chain while deferring intermediate y-coordinates.
	fp := c.fp
	zero := fp.Const(big.NewInt(0))
	x := windowPoints[0].X
	previousSlope, previousWindowX, previousWindowY := zero, windowPoints[0].X, fp.Neg(windowPoints[0].Y)
	for t := 1; t < windowCount-1; t++ {
		windowPoint := windowPoints[t]
		slope := c.hintSlope(p256CombChainHint, 1, nil, previousSlope, x, previousWindowX, previousWindowY, windowPoint.X, windowPoint.Y)[0]
		if t == 1 {
			fp.AssertZero(T(1, slope, fp.Sub(windowPoint.X, x)), T(-1, windowPoint.Y), T(1, windowPoints[0].Y))
		} else {
			fp.AssertZero(T(1, slope, fp.Sub(windowPoint.X, x)), T(1, previousSlope, fp.Sub(previousWindowX, x)), T(-1, windowPoint.Y), T(-1, previousWindowY))
		}
		x = fp.Lazy(T(1, slope, slope), T(-1, x), T(-1, windowPoint.X))
		previousSlope, previousWindowX, previousWindowY = slope, windowPoint.X, windowPoint.Y
	}
	// 4. Recover the accumulated point and add the top window with a doubling-aware check.
	x = fp.Eval(T(1, x))
	y := fp.Eval(T(1, previousSlope, fp.Sub(previousWindowX, x)), T(-1, previousWindowY))
	return c.completeAdd(&point{X: x, Y: y}, windowPoints[windowCount-1])
}

// completeAdd handles distinct points and doubling, but rejects inverse
// points: when x-coordinates match, it also requires matching y-coordinates.
func (c *curve) completeAdd(p, q *point) *point {
	fp, api := c.fp, c.api
	inputs := c.limbHintInputs(append(append([]frontend.Variable{}, p.X.Limbs()...), q.X.Limbs()...))
	hinted, err := api.Compiler().NewHint(p256XEqualHint, 2, inputs...)
	if err != nil {
		panic(err)
	}
	sameX, inverseDifferenceProduct := hinted[0], hinted[1]
	api.AssertIsBoolean(sameX)
	api.AssertIsEqual(api.Mul(c.distinctProduct(p.X, q.X), inverseDifferenceProduct), api.Sub(1, sameX))
	sameXElement := fp.Bounded([]frontend.Variable{sameX}, []int{1})
	xDifference := fp.Sub(q.X, p.X)
	yDifference := fp.Sub(q.Y, p.Y)
	fp.AssertZero(T(1, sameXElement, xDifference))
	fp.AssertZero(T(1, sameXElement, yDifference))
	slope := c.hintSlope(p256UnifiedSlopeHint, 1, nil, p.X, p.Y, q.X, q.Y)[0]
	fp.AssertZero(T(1, slope, xDifference), T(2, slope, sameXElement, p.Y), T(-3, sameXElement, p.X, p.X), T(-1, sameXElement, c.a), T(-1, yDifference))
	x := fp.Eval(T(1, slope, slope), T(-1, p.X), T(-1, q.X))
	y := fp.Eval(T(1, slope, fp.Sub(p.X, x)), T(-1, p.Y))
	return &point{X: x, Y: y}
}

func (c *curve) combSelect(table [][2]*big.Int, selectorBits []frontend.Variable, packY bool) *point {
	nbLimbs := c.layout.NbLimbs
	limbBits := c.layout.LimbBits
	selectorBitCount := len(selectorBits)
	if len(table) != 1<<selectorBitCount {
		panic("table size mismatch")
	}
	oneHotCost := func(k int) int {
		if k <= 1 {
			return 0
		}
		return 1<<k - 2
	}
	rowBitCount, bestCost := 0, oneHotCost(selectorBitCount)
	for candidateRowBits := 1; candidateRowBits <= selectorBitCount; candidateRowBits++ {
		if cost := oneHotCost(candidateRowBits) + oneHotCost(selectorBitCount-candidateRowBits) + (1<<candidateRowBits)*2*nbLimbs; cost < bestCost {
			bestCost, rowBitCount = cost, candidateRowBits
		}
	}
	rowSelectors := oneHot(c.api, selectorBits[:rowBitCount])
	columnSelectors := oneHot(c.api, selectorBits[rowBitCount:])
	mask := new(big.Int).Sub(pow2(limbBits), big.NewInt(1))
	limb := func(v *big.Int, i int) *big.Int {
		return new(big.Int).And(new(big.Int).Rsh(v, uint(limbBits*i)), mask)
	}
	selectCoordinate := func(value func(e int) *big.Int) frontend.Variable {
		inner := make([]frontend.Variable, len(rowSelectors))
		for i := range rowSelectors {
			sum := frontend.Variable(0)
			for j := range columnSelectors {
				sum = c.api.Add(sum, c.api.Mul(columnSelectors[j], value(i+(j<<rowBitCount))))
			}
			inner[i] = sum
		}
		if len(rowSelectors) == 1 {
			return inner[0]
		}
		sum := frontend.Variable(0)
		for i := range rowSelectors {
			sum = c.api.Add(sum, c.api.Mul(rowSelectors[i], inner[i]))
		}
		return sum
	}
	xLimbs := make([]frontend.Variable, nbLimbs)
	yLimbs := make([]frontend.Variable, nbLimbs)
	for l := 0; l < nbLimbs; l++ {
		xLimbs[l] = selectCoordinate(func(e int) *big.Int { return limb(table[e][0], l) })
	}
	if !packY {
		for l := 0; l < nbLimbs; l++ {
			yLimbs[l] = selectCoordinate(func(e int) *big.Int { return limb(table[e][1], l) })
		}
		return &point{X: c.fp.Reduced(xLimbs), Y: c.fp.Reduced(yLimbs)}
	}
	widths := c.fp.ReducedWidths()
	lowerBounds, upperBounds := make([]*big.Int, nbLimbs), make([]*big.Int, nbLimbs)
	for g := 0; g < nbLimbs; g++ {
		yLimbs[g], lowerBounds[g], upperBounds[g] = 0, new(big.Int), new(big.Int)
		if g%packedYGroup != 0 {
			continue
		}
		end := min(g+packedYGroup, nbLimbs)
		mask := new(big.Int).Sub(pow2(limbBits*(end-g)), big.NewInt(1))
		yLimbs[g] = selectCoordinate(func(e int) *big.Int {
			return new(big.Int).And(new(big.Int).Rsh(table[e][1], uint(limbBits*g)), mask)
		})
		bits := 0
		for _, limbWidth := range widths[g:end] {
			bits += limbWidth
		}
		upperBounds[g].Sub(pow2(bits), big.NewInt(1))
	}
	return &point{X: c.fp.Reduced(xLimbs), Y: c.fp.WithBounds(yLimbs, lowerBounds, upperBounds)}
}

func oneHot(api frontend.API, selectorBits []frontend.Variable) []frontend.Variable {
	flags := []frontend.Variable{1}
	for _, bit := range selectorBits {
		next := make([]frontend.Variable, 2*len(flags))
		if len(flags) == 1 {
			next[0] = api.Sub(1, bit)
			next[1] = bit
		} else {
			for j := range flags {
				selectedHigh := api.Mul(flags[j], bit)
				next[j] = api.Sub(flags[j], selectedHigh)
				next[j+len(flags)] = selectedHigh
			}
		}
		flags = next
	}
	return flags
}

func combWindowFor(layout emfield.Layout) int {
	if layout.Lookups {
		return 5
	}
	return 8
}

func p256Comb(windowBits int) *combData {
	combMu.Lock()
	defer combMu.Unlock()
	if table, ok := combCached[windowBits]; ok {
		return table
	}
	params := elliptic.P256().Params()
	a := new(big.Int).Sub(params.P, big.NewInt(3))
	table, err := computeCombData(params.Gx, params.Gy, a, params.P, params.N, windowBits)
	if err != nil {
		panic(fmt.Sprintf("comb data: %v", err))
	}
	combCached[windowBits] = table
	return table
}

func computeCombData(gx, gy, a, prime, groupOrder *big.Int, windowBits int) (*combData, error) {
	scalarBits := groupOrder.BitLen()
	windowCount := (scalarBits + windowBits - 1) / windowBits
	topWindowBits := scalarBits - windowBits*(windowCount-1)
	for t := windowCount - 2; t >= 1; t-- {
		if new(big.Int).Lsh(big.NewInt(1), uint(windowBits*(t+1))).Cmp(groupOrder) > 0 {
			return nil, errors.New("only the top window may reach the group order")
		}
	}
	generator := &combAffine{x: new(big.Int).Set(gx), y: new(big.Int).Set(gy)}
	windows := make([][][2]*big.Int, windowCount)
	windowBase := generator
	var err error
	for t := 0; t < windowCount; t++ {
		if t > 0 {
			for k := 0; k < windowBits; k++ {
				if windowBase, err = combDouble(windowBase, a, prime); err != nil {
					return nil, err
				}
			}
		}
		width := windowBits
		if t == windowCount-1 {
			width = topWindowBits
		}
		windowStep, err := combDouble(windowBase, a, prime)
		if err != nil {
			return nil, err
		}
		positiveCount := 1 << (width - 1)
		odd := make([]*combAffine, positiveCount)
		odd[0] = windowBase
		for m := 1; m < positiveCount; m++ {
			if odd[m], err = combAdd(odd[m-1], windowStep, prime); err != nil {
				return nil, err
			}
		}
		windowPoints := make([][2]*big.Int, 1<<width)
		for j := range windowPoints {
			signedDigit := 2*j - (1 << width) + 1
			var multiple *combAffine
			if signedDigit > 0 {
				multiple = odd[(signedDigit-1)/2]
			} else {
				multiple = combNeg(odd[(-signedDigit-1)/2], prime)
			}
			windowPoints[j] = [2]*big.Int{multiple.x, multiple.y}
		}
		windows[t] = windowPoints
	}
	negatedGenerator := combNeg(generator, prime)
	topEven := make([][2]*big.Int, 1<<topWindowBits)
	for j := range topEven {
		q := &combAffine{x: windows[windowCount-1][j][0], y: windows[windowCount-1][j][1]}
		evenPoint, err := combAdd(q, negatedGenerator, prime)
		if err != nil {
			return nil, fmt.Errorf("parity-fold table: %w", err)
		}
		topEven[j] = [2]*big.Int{evenPoint.x, evenPoint.y}
	}
	return &combData{windowBits: windowBits, windowCount: windowCount, scalarBits: scalarBits, topWindowBits: topWindowBits, windows: windows, topEven: topEven}, nil
}

func combNeg(p *combAffine, prime *big.Int) *combAffine {
	return &combAffine{x: p.x, y: new(big.Int).Sub(prime, p.y)}
}

func combAdd(p, q *combAffine, prime *big.Int) (*combAffine, error) {
	inverseXDifference := new(big.Int).Sub(q.x, p.x)
	inverseXDifference.Mod(inverseXDifference, prime)
	if inverseXDifference.Sign() == 0 {
		return nil, errors.New("x-coordinate collision in comb table computation")
	}
	inverseXDifference.ModInverse(inverseXDifference, prime)
	slope := new(big.Int).Sub(q.y, p.y)
	slope.Mul(slope, inverseXDifference).Mod(slope, prime)
	sumX := new(big.Int).Mul(slope, slope)
	sumX.Sub(sumX, p.x).Sub(sumX, q.x).Mod(sumX, prime)
	sumY := new(big.Int).Sub(p.x, sumX)
	sumY.Mul(sumY, slope).Sub(sumY, p.y).Mod(sumY, prime)
	return &combAffine{x: sumX, y: sumY}, nil
}

func combDouble(p *combAffine, a, prime *big.Int) (*combAffine, error) {
	if p.y.Sign() == 0 {
		return nil, errors.New("doubling a 2-torsion point in comb table computation")
	}
	inverseDenominator := new(big.Int).Lsh(p.y, 1)
	inverseDenominator.Mod(inverseDenominator, prime)
	inverseDenominator.ModInverse(inverseDenominator, prime)
	slope := new(big.Int).Mul(p.x, p.x)
	slope.Mul(slope, big.NewInt(3)).Add(slope, a)
	slope.Mul(slope, inverseDenominator).Mod(slope, prime)
	doubledX := new(big.Int).Mul(slope, slope)
	doubledX.Sub(doubledX, p.x).Sub(doubledX, p.x).Mod(doubledX, prime)
	doubledY := new(big.Int).Sub(p.x, doubledX)
	doubledY.Mul(doubledY, slope).Sub(doubledY, p.y).Mod(doubledY, prime)
	return &combAffine{x: doubledX, y: doubledY}, nil
}

func p256CombRecodeHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(outputs) < 2 {
		return errors.New("expecting at least two outputs")
	}
	scalar := limbHintValue(inputs)
	scalarBits := len(outputs) - 1
	scalar.Mod(scalar, GroupOrder())
	parity := scalar.Bit(0)
	oddScalar := new(big.Int).Set(scalar)
	if parity == 0 {
		oddScalar.Add(oddScalar, big.NewInt(1))
	}
	recodedScalar := new(big.Int).Lsh(big.NewInt(1), uint(scalarBits))
	recodedScalar.Sub(recodedScalar, big.NewInt(1)).Add(recodedScalar, oddScalar).Rsh(recodedScalar, 1)
	outputs[0].SetUint64(uint64(parity))
	for i := 0; i < scalarBits; i++ {
		outputs[1+i].SetUint64(uint64(recodedScalar.Bit(i)))
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

func init() {
	solver.RegisterHint(p256CombRecodeHint, p256CombChainHint, p256XEqualHint, p256UnifiedSlopeHint)
}
