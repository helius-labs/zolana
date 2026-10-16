// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0 (the "License").
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
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
)

type fpElement = emfield.Element
type frElement = emfield.Element

var T = emfield.T

type point struct {
	X, Y *fpElement
}

type curve struct {
	api         frontend.API
	lay         emfield.Layout
	fp          *emfield.Field
	fr          *emfield.Field
	a           *fpElement
	b           *fpElement
	diffSquares map[[2]*fpElement]*fpElement
	twist       frontend.Variable
	outputU     *emfield.Element
	frTwist     *emfield.Field
}

// init registers untrusted affine-operation hints. Each consumer must impose
// the stated equations and its denominator preconditions.
func init() {
	solver.RegisterHint(shortRatioHint, shortTangentHint, shortAddHint)
}

// neg returns the affine inverse by negating Y modulo p. It preserves curve
// and subgroup membership already established for the input.
func (c *curve) neg(p *point) *point {
	return &point{X: p.X, Y: c.fp.Neg(p.Y)}
}

// assertOnCurve enforces Y^2=X^3+a*X+b over the emulated base field.
// It establishes curve membership only, not prime-subgroup membership.
func (c *curve) assertOnCurve(p *point) {
	// 1. Form the bounded square needed by the cubic equation.
	x2 := c.evalOrLazy(false, T(1, p.X, p.X))
	// 2. Enforce the full curve equation modulo p.
	c.fp.AssertZeroProjected(T(1, x2, p.X), T(1, c.a, p.X), T(1, c.b), T(-1, p.Y, p.Y))
}

// slope allocates a hinted slope with checked balanced signed limbs.
// Bounds alone do not bind it to a point. The caller must constrain its equation.
func (c *curve) slope(fn solver.Hint, nbOutputs int, natives []frontend.Variable, elems ...*fpElement) []*fpElement {
	return c.fp.HintBalanced(fn, nbOutputs, natives, elems...)
}

// ratio constrains lambda*den=num modulo p. The caller must establish den!=0
// for a unique quotient. This helper alone permits arbitrary lambda at 0/0.
func (c *curve) ratio(num, den *fpElement) *fpElement {
	// 1. Obtain a bounded candidate quotient.
	lambda := c.slope(shortRatioHint, 1, nil, num, den)[0]
	// 2. Bind it by multiplication under the caller's nonzero-denominator contract.
	c.fp.AssertZeroProjected(T(1, lambda, den), T(-1, num))
	return lambda
}

// tangent constrains 2*lambda*Y=3*X^2+a. A nonidentity prime-subgroup
// input has Y!=0 and hence a unique tangent. Lazy ladder inputs rely on the
// final target equality and backwards argument to establish that precondition.
func (c *curve) tangent(p *point) *fpElement {
	// 1. Obtain a balanced candidate tangent.
	lambda := c.slope(shortTangentHint, 1, nil, p.X, p.Y, c.a)[0]
	// 2. Enforce its tangent equation, with nonzero Y justified by the caller.
	c.fp.AssertZeroProjected(T(2, lambda, p.Y), T(-3, p.X, p.X), T(-1, c.a))
	return lambda
}

// add constrains affine addition using denominator-cleared equations.
// Both inputs must be on the selected curve and have distinct X coordinates
// modulo p. The caller must prove or structurally guarantee that distinction.
func (c *curve) add(p, q *point) *point {
	// 1. Obtain candidate coordinates and form the chord differences.
	fp := c.fp
	s := fp.Hint(shortAddHint, 2, nil, p.X, p.Y, q.X, q.Y)
	dx := fp.Sub(q.X, p.X)
	dy := fp.Sub(q.Y, p.Y)
	// 2. Reuse the bounded squared X difference when the input pair repeats.
	if c.diffSquares == nil {
		c.diffSquares = make(map[[2]*fpElement]*fpElement)
	}
	key := [2]*fpElement{p.X, q.X}
	dx2 := c.diffSquares[key]
	if dx2 == nil {
		dx2 = c.diffSquares[[2]*fpElement{q.X, p.X}]
	}
	if dx2 == nil {
		// Reversing the two X coordinates changes the sign of dx but
		// leaves its square, folded coefficients and interval bounds equal.
		dx2 = fp.Lazy(T(1, dx, dx))
		c.diffSquares[key] = dx2
	}
	// 3. Bind X and Y to the affine formulas using the nonzero X difference.
	fp.AssertZeroProjected(T(1, fp.Lin([]int64{1, 1, 1}, s[0], p.X, q.X), dx2), T(-1, dy, dy))
	fp.AssertZeroProjected(T(1, dy, fp.Sub(s[0], p.X)), T(1, fp.Add(s[1], p.Y), dx))
	return &point{X: s[0], Y: s[1]}
}

// evalOrLazy either reduces a polynomial or retains its bounded expression.
// Lazy evaluation does not establish curve membership. Emulated arithmetic
// checks that coefficient intervals fit before using native-field operations.
func (c *curve) evalOrLazy(reduce bool, terms ...emfield.Term) *fpElement {
	if reduce {
		return c.fp.EvalProjected(terms...)
	}
	return c.fp.Lazy(terms...)
}

// triple computes 3P for a nonidentity point in either prime subgroup.
// Orders greater than three exclude Y=0 and x(P)=x(2P), making both slopes
// unique. The caller must establish subgroup membership first.
func (c *curve) triple(p *point) *point {
	// 1. Compute the tangent and doubled X coordinate.
	lambda1 := c.tangent(p)
	x2 := c.evalOrLazy(false, T(1, lambda1, lambda1), T(-2, p.X))
	// 2. Bind the chord joining P and 2P and compute the reduced coordinates.
	lambda2 := c.fp.Sub(c.ratio(c.fp.Lin([]int64{2}, p.Y), c.fp.Sub(p.X, x2)), lambda1)
	x := c.fp.EvalProjected(T(1, lambda2, lambda2), T(-1, p.X), T(-1, x2))
	y := c.fp.EvalProjected(T(1, lambda2, c.fp.Sub(p.X, x)), T(-1, p.Y))
	return &point{X: x, Y: y}
}

// double computes 2P for a nonidentity prime-subgroup point.
// The odd prime orders exclude Y=0, so its tangent is unique and result finite.
func (c *curve) double(p *point) *point {
	// 1. Bind the tangent using the input's nonzero Y coordinate.
	lambda := c.tangent(p)
	// 2. Compute both reduced affine coordinates from that tangent.
	x := c.fp.Eval(T(1, lambda, lambda), T(-2, p.X))
	y := c.fp.Eval(T(1, lambda, c.fp.Sub(p.X, x)), T(-1, p.Y))
	return &point{X: x, Y: y}
}

// selectPoint selects one of two points coordinatewise using a Boolean bit.
// Selection preserves membership only if both candidate points were validated.
func (c *curve) selectPoint(b frontend.Variable, p, q *point) *point {
	return &point{X: c.fp.Select(b, p.X, q.X), Y: c.fp.Select(b, p.Y, q.Y)}
}

// assertEqual binds both affine coordinates modulo p. In the lazy ladder it
// also transfers membership from the checked target to the final accumulator.
func (c *curve) assertEqual(p, q *point) {
	// Bind both coordinates, since an X-only equality would also allow negation.
	c.fp.AssertZero(T(1, p.X), T(-1, q.X))
	c.fp.AssertZero(T(1, p.Y), T(-1, q.Y))
}

// shortRatioHint proposes a field quotient. ratio checks its product equation,
// while the caller must exclude a zero denominator. The hint is untrusted.
func shortRatioHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		// 1. Validate the solver interface shape.
		if len(in) != 2 || len(out) != 1 {
			return errors.New("expecting two inputs and one output")
		}
		// 2. Propose a quotient for the caller's constrained product equation.
		out[0].Set(modRatio(p, in[0], in[1]))
		return nil
	})
}

// shortAddHint proposes an affine sum. add binds both coordinates through
// two equations under its caller's distinct-X guarantee. The hint is untrusted.
func shortAddHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		// 1. Validate the solver interface shape.
		if len(in) != 4 || len(out) != 2 {
			return errors.New("expecting two points and two outputs")
		}
		// 2. Compute the affine chord and propose both result coordinates.
		lambda := modRatio(p, new(big.Int).Sub(in[3], in[1]), new(big.Int).Sub(in[2], in[0]))
		out[0].Mul(lambda, lambda).Sub(out[0], in[0]).Sub(out[0], in[2]).Mod(out[0], p)
		out[1].Sub(in[0], out[0]).Mul(out[1], lambda).Sub(out[1], in[1]).Mod(out[1], p)
		return nil
	})
}

// shortTangentHint proposes a tangent slope. tangent constrains its equation,
// and the caller establishes nonzero Y. The hint is untrusted.
func shortTangentHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
		// 1. Validate the solver interface shape.
		if len(in) != 3 || len(out) != 1 {
			return errors.New("expecting three inputs and one output")
		}
		// 2. Propose the tangent quotient, whose equation is checked in circuit.
		num := new(big.Int).Mul(in[0], in[0])
		num.Mul(num, big.NewInt(3)).Add(num, in[2])
		out[0].Set(modRatio(p, num, new(big.Int).Lsh(in[1], 1)))
		return nil
	})
}
