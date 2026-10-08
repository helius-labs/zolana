package emcurve

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

type ECDSAInputs struct {
	LimbBits   int
	PublicKeyX []frontend.Variable
	PublicKeyY []frontend.Variable
	R          []frontend.Variable
	S          []frontend.Variable
	Message    []frontend.Variable
}

func VerifyECDSA(api frontend.API, signature ECDSAInputs) [32]frontend.Variable {
	return VerifyECDSAFor(api, signature, true)
}

func VerifyECDSAFor(api frontend.API, signature ECDSAInputs, lookups bool) [32]frontend.Variable {
	c := newCurveFor(api, lookups)
	// 1. Decode and validate the canonical public-key coordinates.
	publicPoint := &point{
		X: c.fp.Reduced(c.relimb(signature.PublicKeyX, signature.LimbBits)),
		Y: c.fp.Reduced(c.relimb(signature.PublicKeyY, signature.LimbBits)),
	}
	var publicKeyX [32]frontend.Variable
	copy(publicKeyX[:], c.toBytes(publicPoint.X))
	c.fp.AssertCanonical(publicPoint.Y)
	c.assertOnCurve(publicPoint)

	// 2. Require canonical nonzero signature scalars and decode the message.
	r := c.nonZeroScalar(signature.R, signature.LimbBits)
	s := c.nonZeroScalar(signature.S, signature.LimbBits)
	messageScalar := c.fr.Reduced(c.relimb(signature.Message, signature.LimbBits))

	// 3. Check the hinted inverse of s and compute the two ECDSA multipliers.
	fr := c.fr
	inverseS := fr.Hint(p256ScalarInverseHint, 1, nil, s)[0]
	fr.AssertZero(T(1, s, inverseS), T(-1, fr.Const(big.NewInt(1))))
	generatorScalar := fr.Eval(T(1, messageScalar, inverseS))
	publicKeyScalar := fr.Eval(T(1, r, inverseS))

	// 4. Constrain [message/s]G + [r/s]Q and require its x-coordinate modulo n to equal r.
	generatorContribution := c.scalarMulBase(generatorScalar)
	publicKeyContribution := c.scalarMulChecked(publicPoint, publicKeyScalar)
	verificationPoint := c.completeAdd(generatorContribution, publicKeyContribution)
	c.assertXModOrder(verificationPoint.X, r)
	return publicKeyX
}

func (c *curve) nonZeroScalar(limbs []frontend.Variable, limbBits int) *frElement {
	scalar := c.fr.Reduced(c.relimb(limbs, limbBits))
	c.fr.AssertCanonical(scalar)
	c.api.AssertIsDifferent(c.api.Add(0, 0, scalar.Limbs()...), 0)
	return scalar
}

func (c *curve) relimb(limbs []frontend.Variable, limbBits int) []frontend.Variable {
	layoutLimbBits := c.layout.LimbBits
	if limbBits <= 0 || limbBits%layoutLimbBits != 0 || len(limbs)*limbBits != c.layout.NbLimbs*layoutLimbBits {
		panic("limbs do not tile the field layout")
	}
	rangeChecker := c.rangeChecker()
	var fieldLimbs []frontend.Variable
	for _, limb := range limbs {
		if limbBits == layoutLimbBits {
			rangeChecker.Check(limb, layoutLimbBits)
			fieldLimbs = append(fieldLimbs, limb)
			continue
		}
		remainingLimb := limb
		for remainingBits := limbBits; remainingBits > layoutLimbBits; remainingBits -= layoutLimbBits {
			high, low := c.splitLowBits(remainingLimb, layoutLimbBits, remainingBits)
			fieldLimbs = append(fieldLimbs, low)
			remainingLimb = high
		}
		fieldLimbs = append(fieldLimbs, remainingLimb)
	}
	return fieldLimbs
}

func (c *curve) assertXModOrder(x *fpElement, r *frElement) {
	api := c.api
	xLimbs := c.canonicalLimbs(x)
	rLimbs := r.Limbs()
	// 1. Hint whether canonical x equals r or r + n, and constrain the choice to a bit.
	hinted, err := api.Compiler().NewHint(p256OrderWrapHint, 1, c.limbHintInputs(xLimbs)...)
	if err != nil {
		panic(err)
	}
	wrap := hinted[0]
	api.AssertIsBoolean(wrap)
	// 2. Split the comparison into two halves that fit the native field.
	halfLimbCount := c.layout.NbLimbs / 2
	halfBits := c.layout.LimbBits * halfLimbCount
	order := GroupOrder()
	orderLow := new(big.Int).And(order, new(big.Int).Sub(pow2(halfBits), big.NewInt(1)))
	orderHigh := new(big.Int).Rsh(order, uint(halfBits))
	pack := func(limbs []frontend.Variable) frontend.Variable {
		sum := frontend.Variable(0)
		for i, limb := range limbs {
			sum = api.Add(sum, api.Mul(limb, pow2(c.layout.LimbBits*i)))
		}
		return sum
	}
	// 3. Constrain the carry from the low half, then check the high half.
	inverseShift := new(big.Int).ModInverse(pow2(halfBits), api.Compiler().Field())
	rLow := pack(rLimbs[:halfLimbCount])
	wrappedOrderLow := api.Mul(wrap, orderLow)
	expectedLow := api.Add(rLow, wrappedOrderLow)
	xLow := pack(xLimbs[:halfLimbCount])
	lowDifference := api.Sub(expectedLow, xLow)
	carry := api.Mul(lowDifference, inverseShift)
	api.AssertIsBoolean(carry)
	rHigh := pack(rLimbs[halfLimbCount:])
	wrappedOrderHigh := api.Mul(wrap, orderHigh)
	expectedHigh := api.Add(rHigh, wrappedOrderHigh, carry)
	xHigh := pack(xLimbs[halfLimbCount:])
	api.AssertIsEqual(expectedHigh, xHigh)
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

func init() {
	solver.RegisterHint(p256ScalarInverseHint, p256OrderWrapHint)
}
