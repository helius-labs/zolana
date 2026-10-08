package emcurve

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

func init() {
	solver.RegisterHint(p256ScalarInverseHint, p256OrderWrapHint)
}

type ECDSAInputs struct {
	LimbBits   int
	PublicKeyX []frontend.Variable
	PublicKeyY []frontend.Variable
	R          []frontend.Variable
	S          []frontend.Variable
	Message    []frontend.Variable
}

func VerifyECDSA(api frontend.API, in ECDSAInputs) [32]frontend.Variable {
	return VerifyECDSAFor(api, in, true)
}

func VerifyECDSAFor(api frontend.API, in ECDSAInputs, lookups bool) [32]frontend.Variable {
	c := newCurveFor(api, lookups)
	pub := &point{
		X: c.fp.Reduced(c.relimb(in.PublicKeyX, in.LimbBits)),
		Y: c.fp.Reduced(c.relimb(in.PublicKeyY, in.LimbBits)),
	}
	var publicKeyX [32]frontend.Variable
	copy(publicKeyX[:], c.toBytes(pub.X))
	c.fp.AssertCanonical(pub.Y)
	c.assertOnCurve(pub)

	r := c.nonZeroScalar(in.R, in.LimbBits)
	s := c.nonZeroScalar(in.S, in.LimbBits)
	h := c.fr.Reduced(c.relimb(in.Message, in.LimbBits))

	fr := c.fr
	sInv := fr.Hint(p256ScalarInverseHint, 1, nil, s)[0]
	fr.AssertZero(T(1, s, sInv), T(-1, fr.Const(big.NewInt(1))))
	u1 := fr.Eval(T(1, h, sInv))
	u2 := fr.Eval(T(1, r, sInv))

	q := c.completeAdd(c.scalarMulBase(u1), c.scalarMulChecked(pub, u2))
	c.assertXModOrder(q.X, r)
	return publicKeyX
}

func (c *curve) relimb(limbs []frontend.Variable, limbBits int) []frontend.Variable {
	width := c.lay.LimbBits
	if limbBits <= 0 || limbBits%width != 0 || len(limbs)*limbBits != c.lay.NbLimbs*width {
		panic("limbs do not tile the field layout")
	}
	rc := c.rangeChecker()
	var out []frontend.Variable
	for _, limb := range limbs {
		if limbBits == width {
			rc.Check(limb, width)
			out = append(out, limb)
			continue
		}
		rest := limb
		for w := limbBits; w > width; w -= width {
			high, low := c.splitLowBits(rest, width, w)
			out = append(out, low)
			rest = high
		}
		out = append(out, rest)
	}
	return out
}

func (c *curve) nonZeroScalar(limbs []frontend.Variable, limbBits int) *frElement {
	e := c.fr.Reduced(c.relimb(limbs, limbBits))
	c.fr.AssertCanonical(e)
	c.api.AssertIsDifferent(c.api.Add(0, 0, e.Limbs()...), 0)
	return e
}

func (c *curve) assertXModOrder(x *fpElement, r *frElement) {
	api := c.api
	xl := c.canonicalLimbs(x)
	rl := r.Limbs()
	hinted, err := api.Compiler().NewHint(p256OrderWrapHint, 1, c.limbHintInputs(xl)...)
	if err != nil {
		panic(err)
	}
	wrap := hinted[0]
	api.AssertIsBoolean(wrap)
	half := c.lay.NbLimbs / 2
	shift := c.lay.LimbBits * half
	order := GroupOrder()
	orderLow := new(big.Int).And(order, new(big.Int).Sub(pow2(shift), big.NewInt(1)))
	orderHigh := new(big.Int).Rsh(order, uint(shift))
	pack := func(limbs []frontend.Variable) frontend.Variable {
		sum := frontend.Variable(0)
		for i, l := range limbs {
			sum = api.Add(sum, api.Mul(l, pow2(c.lay.LimbBits*i)))
		}
		return sum
	}
	inverseShift := new(big.Int).ModInverse(pow2(shift), api.Compiler().Field())
	carry := api.Mul(api.Sub(api.Add(pack(rl[:half]), api.Mul(wrap, orderLow)), pack(xl[:half])), inverseShift)
	api.AssertIsBoolean(carry)
	api.AssertIsEqual(api.Add(pack(rl[half:]), api.Mul(wrap, orderHigh), carry), pack(xl[half:]))
}

func p256ScalarInverseHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(n *big.Int, _, in, out []*big.Int) error {
		if len(in) != 1 || len(out) != 1 {
			return errors.New("expecting one scalar")
		}
		s := new(big.Int).Mod(in[0], n)
		if s.Sign() == 0 {
			return nil
		}
		out[0].ModInverse(s, n)
		return nil
	})
}

func p256OrderWrapHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(outputs) != 1 {
		return errors.New("expecting one output")
	}
	outputs[0].SetUint64(0)
	if limbHintValue(inputs).Cmp(GroupOrder()) >= 0 {
		outputs[0].SetUint64(1)
	}
	return nil
}
