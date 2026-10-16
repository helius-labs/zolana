package shortchecker

import (
	"errors"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/internal/emfield"
	"math/big"
)

// prime returns a fresh copy of p = 2^255 - 19 for public curve arithmetic.
func prime() *big.Int { return new(big.Int).Sub(pow2(255), big.NewInt(19)) }

// order returns the prime subgroup order of Curve25519 or its quadratic twist.
// These fixed orders are used only after cofactor clearing or subgroup checks.
func order(twist bool) *big.Int {
	if twist {
		c, _ := new(big.Int).SetString("55484635554744707071703875581767296995", 10)
		return new(big.Int).Sub(pow2(253), c)
	}
	c, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	return new(big.Int).Add(pow2(252), c)
}

// offset returns A/3 modulo p for the Montgomery-to-Weierstrass translation.
// The fixed denominator three is invertible in the base field.
func offset() *big.Int { return modRatio(prime(), big.NewInt(486662), big.NewInt(3)) }

// coefficients computes the public Weierstrass parameters for X=B(u+A/3).
// B is one on Curve25519 and two on its twist. The coordinate scaling gives
// a=B^2(1-A^2/3) and b=B^3(2A^3/27-A/3), over the same base field.
func coefficients(twist bool) (a, b *big.Int) {
	// 1. Translate the Montgomery equation with A/3 to remove its quadratic term.
	p := prime()
	A := big.NewInt(486662)
	a = new(big.Int).Mul(A, A)
	a.Mul(a, new(big.Int).ModInverse(big.NewInt(3), p))
	a.Sub(big.NewInt(1), a)
	b = new(big.Int).Exp(A, big.NewInt(3), p)
	b.Lsh(b, 1).Mul(b, new(big.Int).ModInverse(big.NewInt(27), p))
	b.Sub(b, offset())
	// 2. Scale X by two and Y by the corresponding twist map when selected.
	if twist {
		a.Lsh(a, 2)
		b.Lsh(b, 3)
	}
	return a.Mod(a, p), b.Mod(b, p)
}

// MultiplyScalar proves the Montgomery coordinate [8*s]P for input u(P).
// The caller must bound u below 2^255 and s=k/8 in [2^251,2^252).
// Three checked doublings clear both the curve's cofactor eight and the twist's
// cofactor four. The checked lift and ladder bind the output to the appropriate
// prime subgroup. Inputs that double to infinity cannot satisfy the equations.
// The caller must canonicalize the returned coordinate before encoding it.
func MultiplyScalar(api frontend.API, f *emfield.Field, u, s *emfield.Element) *emfield.Element {
	// 1. Clear both cofactors with three checked finite doublings.
	for i := 0; i < 3; i++ {
		u = xDouble(f, u)
	}
	// 2. Obtain a Boolean class selector and choose matching curve and scalar fields.
	raw, err := api.Compiler().NewHint(curveClassHint, 1, append([]frontend.Variable{f.Layout().LimbBits}, u.Limbs()...)...)
	if err != nil {
		panic(err)
	}
	twist := raw[0]
	api.AssertIsBoolean(twist)
	a0, b0 := coefficients(false)
	a1, b1 := coefficients(true)
	c := &curve{api: api, lay: f.Layout(), fp: f, fr: emfield.NewFor(api, order(false), f.Layout()), frTwist: emfield.NewFor(api, order(true), f.Layout()), a: f.Select(twist, f.Const(a1), f.Const(a0)), b: f.Select(twist, f.Const(b1), f.Const(b0)), twist: twist}
	// 3. Translate and lift the cleared coordinate, proving the selected curve equation.
	B := f.Bounded([]frontend.Variable{api.Add(1, twist)}, []int{2})
	X := f.EvalProjected(T(1, B, f.Add(u, f.Const(offset()))))
	Y := f.Hint(liftHint, 1, []frontend.Variable{twist}, u)[0]
	q := &point{X, Y}
	c.assertOnCurve(q)
	// 4. Prove the scalar product and result subgroup membership.
	c.scalarMulChecked(q, s)
	return c.outputU
}

// scalarZero enforces a scalar congruence modulo the selected subgroup order.
// The twist selector must be Boolean. Gating each relation with that selector
// activates exactly one modulus and prevents mixing curve and twist orders.
func (c *curve) scalarZero(ts ...emfield.Term) {
	// Gate the same relation into each modulus with complementary Boolean flags.
	for i, f := range []*emfield.Field{c.fr, c.frTwist} {
		flag := c.twist
		if i == 0 {
			flag = c.api.Sub(1, flag)
		}
		gate := f.Bounded([]frontend.Variable{flag}, []int{1})
		gated := make([]emfield.Term, len(ts))
		for j, t := range ts {
			gated[j] = emfield.Term{Coef: t.Coef, Factors: append([]*emfield.Element{gate}, t.Factors...)}
		}
		f.AssertZero(gated...)
	}
}

// assertSubgroup proves that an already on-curve affine result lies in the
// selected prime subgroup, then records its Montgomery coordinate as outputU.
// An eightfold preimage removes all cofactor torsion. Checked finite doublings
// preserve curve or twist class, so an arbitrary hinted root cannot bypass it.
func (c *curve) assertSubgroup(r *point) {
	// 1. Bind the result X coordinate to its Montgomery coordinate.
	f := c.fp
	u := f.Hint(montUHint, 1, []frontend.Variable{c.twist}, r.X)[0]
	B := f.Bounded([]frontend.Variable{c.api.Add(1, c.twist)}, []int{2})
	f.AssertZeroProjected(T(1, B, f.Add(u, f.Const(offset()))), T(-1, r.X))
	// 2. Certify an eightfold preimage with checked doublings and exact equality.
	w := f.Hint(rootHint, 1, []frontend.Variable{c.twist}, r.X, r.Y)[0]
	for i := 0; i < 3; i++ {
		w = xDouble(f, w)
	}
	f.AssertZeroProjected(T(1, w), T(-1, u))
	// 3. Expose only the coordinate bound to the validated subgroup result.
	c.outputU = u
}

// xDouble proves finite Montgomery doubling on the curve or its twist.
// The equations t*x=x^2+1 and 4*r*(t+A)=t^2-4 force x and t+A nonzero
// because A^2 != 4. Thus low-order inputs cannot exploit a zero denominator.
func xDouble(f *emfield.Field, x *emfield.Element) *emfield.Element {
	// 1. Obtain candidate result r and t=x+1/x.
	o := f.Hint(xDoubleHint, 2, nil, x)
	r, t := o[0], o[1]
	one := f.Const(big.NewInt(1))
	// 2. Enforce both rational identities without leaving zero denominators free.
	f.AssertZeroProjected(T(1, t, x), T(-1, x, x), T(-1, one))
	f.AssertZeroProjected(T(4, r, f.Add(t, f.Const(big.NewInt(486662)))), T(-1, t, t), T(4, one))
	return r
}

// init registers untrusted curve witnesses. Their consumers constrain the
// curve class, lift, subgroup preimage and doubling relations independently.
func init() { solver.RegisterHint(curveClassHint, liftHint, montUHint, rootHint, xDoubleHint) }

// curveClassHint proposes the curve or twist class using a Legendre symbol.
// MultiplyScalar constrains the flag to a bit and validates the corresponding
// nonzero lift, so the hint itself is not a trusted membership test.
func curveClassHint(_ *big.Int, in, out []*big.Int) error {
	// 1. Check the hint shape and reconstruct the bounded input coordinate.
	if len(in) < 2 || len(out) != 1 {
		return errors.New("class shape")
	}
	u := limbHintValue(in)
	p := prime()
	// 2. Evaluate u^3+A*u^2+u and propose its quadratic-residue class.
	v := new(big.Int).Mul(u, u)
	v.Add(v, new(big.Int).Mul(big.NewInt(486662), u)).Add(v, big.NewInt(1)).Mul(v, u).Mod(v, p)
	out[0].SetInt64(0)
	if big.Jacobi(v, p) < 0 {
		out[0].SetInt64(1)
	}
	return nil
}

// liftHint proposes a Weierstrass Y coordinate for the chosen class.
// The caller checks the curve equation. Either square-root sign is allowed
// because the public result is a Montgomery u coordinate.
func liftHint(q *big.Int, in, out []*big.Int) error {
	return emfield.Unwrap(q, in, out, func(p *big.Int, n, v, o []*big.Int) error {
		// 1. Check the public hint shape.
		if len(n) != 1 || len(v) != 1 || len(o) != 1 {
			return errors.New("lift shape")
		}
		// 2. Compute the selected Y^2 and propose a square root for the curve check.
		u := v[0]
		h := new(big.Int).Mul(u, u)
		h.Add(h, new(big.Int).Mul(big.NewInt(486662), u)).Add(h, big.NewInt(1)).Mul(h, u)
		if n[0].Sign() != 0 {
			h.Lsh(h, 3)
		}
		h.Mod(h, p)
		if o[0].ModSqrt(h, p) == nil {
			return errors.New("no lift")
		}
		return nil
	})
}

// montUHint proposes the inverse coordinate map u=X/B-A/3.
// assertSubgroup enforces that map with B fixed by the Boolean twist selector.
func montUHint(q *big.Int, in, out []*big.Int) error {
	return emfield.Unwrap(q, in, out, func(p *big.Int, n, v, o []*big.Int) error {
		// 1. Check the public hint shape.
		if len(n) != 1 || len(v) != 1 || len(o) != 1 {
			return errors.New("u shape")
		}
		// 2. Undo the selected scaling and translation modulo p.
		o[0].Set(v[0])
		if n[0].Sign() != 0 {
			o[0].Mul(o[0], new(big.Int).ModInverse(big.NewInt(2), p))
		}
		o[0].Sub(o[0], offset()).Mod(o[0], p)
		return nil
	})
}

// rootHint proposes an eightfold preimage using the selected prime order.
// This host computation is untrusted. assertSubgroup proves three finite
// doublings of the returned coordinate equal the claimed result coordinate.
func rootHint(q *big.Int, in, out []*big.Int) error {
	return emfield.Unwrap(q, in, out, func(p *big.Int, n, v, o []*big.Int) error {
		// 1. Check the public hint shape.
		if len(n) != 1 || len(v) != 2 || len(o) != 1 {
			return errors.New("root shape")
		}
		// 2. Multiply by the inverse of eight in the selected prime subgroup.
		twist := n[0].Sign() != 0
		a, _ := coefficients(twist)
		r := hostMul(hostPoint{v[0], v[1]}, new(big.Int).ModInverse(big.NewInt(8), order(twist)), a)
		if r.x == nil {
			return errors.New("root infinity")
		}
		// 3. Convert the candidate preimage back to a Montgomery coordinate.
		o[0].Set(r.x)
		if twist {
			o[0].Mul(o[0], new(big.Int).ModInverse(big.NewInt(2), p))
		}
		o[0].Sub(o[0], offset()).Mod(o[0], p)
		return nil
	})
}

// xDoubleHint proposes the doubled coordinate and reciprocal expression.
// xDouble constrains both outputs, including the exceptional denominators.
func xDoubleHint(q *big.Int, in, out []*big.Int) error {
	return emfield.Unwrap(q, in, out, func(p *big.Int, _, v, o []*big.Int) error {
		// 1. Check the hint shape.
		if len(v) != 1 || len(o) != 2 {
			return errors.New("x double shape")
		}
		// 2. Compute the doubling denominator and reject infinity for honest witnesses.
		x := v[0]
		xx := new(big.Int).Mul(x, x)
		h := new(big.Int).Add(xx, new(big.Int).Mul(big.NewInt(486662), x))
		h.Add(h, big.NewInt(1)).Lsh(h, 2)
		inv := new(big.Int).Mul(x, h)
		inv.Mod(inv, p)
		if inv.ModInverse(inv, p) == nil {
			return errors.New("double infinity")
		}
		// 3. Propose r and t for the two equations in xDouble.
		num := new(big.Int).Sub(xx, big.NewInt(1))
		o[0].Mul(num, num).Mul(o[0], inv).Mod(o[0], p)
		o[1].Mul(h, inv).Add(o[1], x).Mod(o[1], p)
		return nil
	})
}

type hostPoint struct{ x, y *big.Int }

// hostAdd computes affine addition for witness generation and public tables.
// Inputs must be canonical points on the same selected curve. A nil x denotes
// infinity. This variable-time host helper adds no circuit constraints.
func hostAdd(p, q hostPoint, a *big.Int) hostPoint {
	// 1. Handle identity inputs before affine formulas.
	if p.x == nil {
		return q
	}
	if q.x == nil {
		return p
	}
	// 2. Select the chord or tangent, handling opposite points as infinity.
	mod := prime()
	var num, den *big.Int
	if p.x.Cmp(q.x) == 0 {
		if p.y.Cmp(q.y) != 0 || p.y.Sign() == 0 {
			return hostPoint{}
		}
		num = new(big.Int).Mul(p.x, p.x)
		num.Mul(num, big.NewInt(3)).Add(num, a)
		den = new(big.Int).Lsh(p.y, 1)
	} else {
		num = new(big.Int).Sub(q.y, p.y)
		den = new(big.Int).Sub(q.x, p.x)
	}
	// 3. Compute the affine sum modulo p for the witness or constant table.
	l := modRatio(mod, num, den)
	x := new(big.Int).Mul(l, l)
	x.Sub(x, p.x).Sub(x, q.x).Mod(x, mod)
	y := new(big.Int).Sub(p.x, x)
	y.Mul(y, l).Sub(y, p.y).Mod(y, mod)
	return hostPoint{x, y}
}
