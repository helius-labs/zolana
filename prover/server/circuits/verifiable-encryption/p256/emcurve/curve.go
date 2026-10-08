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
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

type fpElement = emfield.Element

type frElement = emfield.Element

var T = emfield.T

type point struct {
	X, Y *fpElement
}

type curve struct {
	api    frontend.API
	layout emfield.Layout
	fp     *emfield.Field
	fr     *emfield.Field
	a      *fpElement
	b      *fpElement
}

func newCurve(api frontend.API) *curve {
	return newCurveFor(api, true)
}

func newCurveFor(api frontend.API, lookups bool) *curve {
	params := elliptic.P256().Params()
	layout := emfield.LayoutFor(lookups)
	fr := emfield.NewFor(api, params.N, layout)
	fp := emfield.NewFor(api, params.P, layout)
	return &curve{
		api:    api,
		layout: layout,
		fp:     fp,
		fr:     fr,
		a:      fp.Const(new(big.Int).Sub(params.P, big.NewInt(3))),
		b:      fp.Const(params.B),
	}
}

func (c *curve) assertOnCurve(p *point) {
	x2 := c.evalOrLazy(false, T(1, p.X, p.X))
	c.fp.AssertZero(T(1, x2, p.X), T(1, c.a, p.X), T(1, c.b), T(-1, p.Y, p.Y))
}

func (c *curve) assertEqual(p, q *point) {
	c.fp.AssertZero(T(1, p.X), T(-1, q.X))
	c.fp.AssertZero(T(1, p.Y), T(-1, q.Y))
}

func (c *curve) neg(p *point) *point {
	return &point{X: p.X, Y: c.fp.Neg(p.Y)}
}

// add uses incomplete affine addition; callers must establish distinct x-coordinates.
func (c *curve) add(p, q *point) *point {
	fp := c.fp
	coordinates := fp.Hint(p256AddHint, 2, nil, p.X, p.Y, q.X, q.Y)
	xDifference := fp.Sub(q.X, p.X)
	yDifference := fp.Sub(q.Y, p.Y)
	xDifferenceSquared := fp.Lazy(T(1, xDifference, xDifference))
	sumX, sumY := coordinates[0], coordinates[1]
	xCoordinateSum := fp.Lin([]int64{1, 1, 1}, sumX, p.X, q.X)
	fp.AssertZero(T(1, xCoordinateSum, xDifferenceSquared), T(-1, yDifference, yDifference))
	sumXDifference := fp.Sub(sumX, p.X)
	sumYPlusInputY := fp.Add(sumY, p.Y)
	fp.AssertZero(T(1, yDifference, sumXDifference), T(1, sumYPlusInputY, xDifference))
	return &point{X: coordinates[0], Y: coordinates[1]}
}

func (c *curve) addReducing(p, q *point, reduceX, reduceY bool) *point {
	yDifference := c.fp.Sub(q.Y, p.Y)
	xDifference := c.fp.Sub(q.X, p.X)
	slope := c.ratio(yDifference, xDifference)
	x := c.evalOrLazy(reduceX, T(1, slope, slope), T(-1, p.X), T(-1, q.X))
	y := c.evalOrLazy(reduceY, T(1, slope, c.fp.Sub(p.X, x)), T(-1, p.Y))
	return &point{X: x, Y: y}
}

func (c *curve) triple(p *point) *point {
	tangentSlope := c.tangent(p)
	doubledX := c.evalOrLazy(false, T(1, tangentSlope, tangentSlope), T(-2, p.X))
	returnSlope := c.fp.Sub(c.ratio(c.fp.MulConst(p.Y, 2), c.fp.Sub(p.X, doubledX)), tangentSlope)
	x := c.fp.Eval(T(1, returnSlope, returnSlope), T(-1, p.X), T(-1, doubledX))
	y := c.fp.Eval(T(1, returnSlope, c.fp.Sub(p.X, x)), T(-1, p.Y))
	return &point{X: x, Y: y}
}

func (c *curve) selectPoint(b frontend.Variable, p, q *point) *point {
	return &point{X: c.fp.Select(b, p.X, q.X), Y: c.fp.Select(b, p.Y, q.Y)}
}

func (c *curve) evalOrLazy(reduce bool, terms ...emfield.Term) *fpElement {
	if reduce {
		return c.fp.Eval(terms...)
	}
	return c.fp.Lazy(terms...)
}

func (c *curve) ratio(numerator, denominator *fpElement) *fpElement {
	slope := c.hintSlope(p256RatioHint, 1, nil, numerator, denominator)[0]
	c.fp.AssertZero(T(1, slope, denominator), T(-1, numerator))
	return slope
}

func (c *curve) tangent(p *point) *fpElement {
	slope := c.hintSlope(p256TangentHint, 1, nil, p.X, p.Y)[0]
	c.fp.AssertZero(T(2, slope, p.Y), T(-3, p.X, p.X), T(-1, c.a))
	return slope
}

// hintSlope returns bounded candidate slopes. Each caller adds the equation
// that ties the hinted slope to its input coordinates.
func (c *curve) hintSlope(fn solver.Hint, nbOutputs int, natives []frontend.Variable, elems ...*fpElement) []*fpElement {
	return c.fp.HintBalanced(fn, nbOutputs, natives, elems...)
}

func p256RatioHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 2 || len(out) != 1 {
			return errors.New("expecting two inputs and one output")
		}
		out[0].Set(modRatio(p, in[0], in[1]))
		return nil
	})
}

func p256AddHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 4 || len(out) != 2 {
			return errors.New("expecting two points and two outputs")
		}
		lambda := modRatio(p, new(big.Int).Sub(in[3], in[1]), new(big.Int).Sub(in[2], in[0]))
		out[0].Mul(lambda, lambda).Sub(out[0], in[0]).Sub(out[0], in[2]).Mod(out[0], p)
		out[1].Sub(in[0], out[0]).Mul(out[1], lambda).Sub(out[1], in[1]).Mod(out[1], p)
		return nil
	})
}

func p256TangentHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		if len(in) != 2 || len(out) != 1 {
			return errors.New("expecting two inputs and one output")
		}
		num := new(big.Int).Mul(in[0], in[0])
		num.Sub(num, big.NewInt(1)).Mul(num, big.NewInt(3))
		out[0].Set(modRatio(p, num, new(big.Int).Lsh(in[1], 1)))
		return nil
	})
}

func init() {
	solver.RegisterHint(p256RatioHint, p256TangentHint, p256AddHint)
}
