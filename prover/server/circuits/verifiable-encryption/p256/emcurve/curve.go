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
	api frontend.API
	lay emfield.Layout
	fp  *emfield.Field
	fr  *emfield.Field
	a   *fpElement
	b   *fpElement
}

func init() {
	solver.RegisterHint(p256RatioHint, p256TangentHint, p256AddHint)
}

func newCurve(api frontend.API) *curve {
	return newCurveFor(api, true)
}

func newCurveFor(api frontend.API, lookups bool) *curve {
	params := elliptic.P256().Params()
	lay := emfield.LayoutFor(lookups)
	fr := emfield.NewFor(api, params.N, lay)
	fp := emfield.NewFor(api, params.P, lay)
	return &curve{
		api: api,
		lay: lay,
		fp:  fp,
		fr:  fr,
		a:   fp.Const(new(big.Int).Sub(params.P, big.NewInt(3))),
		b:   fp.Const(params.B),
	}
}

func (c *curve) neg(p *point) *point {
	return &point{X: p.X, Y: c.fp.Neg(p.Y)}
}

func (c *curve) assertOnCurve(p *point) {
	x2 := c.evalOrLazy(false, T(1, p.X, p.X))
	c.fp.AssertZero(T(1, x2, p.X), T(1, c.a, p.X), T(1, c.b), T(-1, p.Y, p.Y))
}

func (c *curve) slope(fn solver.Hint, nbOutputs int, natives []frontend.Variable, elems ...*fpElement) []*fpElement {
	return c.fp.HintBalanced(fn, nbOutputs, natives, elems...)
}

func (c *curve) ratio(num, den *fpElement) *fpElement {
	lambda := c.slope(p256RatioHint, 1, nil, num, den)[0]
	c.fp.AssertZero(T(1, lambda, den), T(-1, num))
	return lambda
}

func (c *curve) tangent(p *point) *fpElement {
	lambda := c.slope(p256TangentHint, 1, nil, p.X, p.Y)[0]
	c.fp.AssertZero(T(2, lambda, p.Y), T(-3, p.X, p.X), T(-1, c.a))
	return lambda
}

func (c *curve) add(p, q *point) *point {
	fp := c.fp
	s := fp.Hint(p256AddHint, 2, nil, p.X, p.Y, q.X, q.Y)
	dx := fp.Sub(q.X, p.X)
	dy := fp.Sub(q.Y, p.Y)
	dx2 := fp.Lazy(T(1, dx, dx))
	fp.AssertZero(T(1, fp.Lin([]int64{1, 1, 1}, s[0], p.X, q.X), dx2), T(-1, dy, dy))
	fp.AssertZero(T(1, dy, fp.Sub(s[0], p.X)), T(1, fp.Add(s[1], p.Y), dx))
	return &point{X: s[0], Y: s[1]}
}

func (c *curve) addReducing(p, q *point, reduceX, reduceY bool) *point {
	lambda := c.ratio(c.fp.Sub(q.Y, p.Y), c.fp.Sub(q.X, p.X))
	x := c.evalOrLazy(reduceX, T(1, lambda, lambda), T(-1, p.X), T(-1, q.X))
	y := c.evalOrLazy(reduceY, T(1, lambda, c.fp.Sub(p.X, x)), T(-1, p.Y))
	return &point{X: x, Y: y}
}

func (c *curve) evalOrLazy(reduce bool, terms ...emfield.Term) *fpElement {
	if reduce {
		return c.fp.Eval(terms...)
	}
	return c.fp.Lazy(terms...)
}

func (c *curve) triple(p *point) *point {
	lambda1 := c.tangent(p)
	x2 := c.evalOrLazy(false, T(1, lambda1, lambda1), T(-2, p.X))
	lambda2 := c.fp.Sub(c.ratio(c.fp.MulConst(p.Y, 2), c.fp.Sub(p.X, x2)), lambda1)
	x := c.fp.Eval(T(1, lambda2, lambda2), T(-1, p.X), T(-1, x2))
	y := c.fp.Eval(T(1, lambda2, c.fp.Sub(p.X, x)), T(-1, p.Y))
	return &point{X: x, Y: y}
}

func (c *curve) selectPoint(b frontend.Variable, p, q *point) *point {
	return &point{X: c.fp.Select(b, p.X, q.X), Y: c.fp.Select(b, p.Y, q.Y)}
}

func (c *curve) assertEqual(p, q *point) {
	c.fp.AssertZero(T(1, p.X), T(-1, q.X))
	c.fp.AssertZero(T(1, p.Y), T(-1, q.Y))
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
