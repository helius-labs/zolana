package emcurve

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(p256LimbBytesHint)
}

func GroupOrder() *big.Int {
	return new(big.Int).Set(emulated.P256Fr{}.Modulus())
}

func PointOnCurve(api frontend.API, publicKey [65]frontend.Variable) {
	PointOnCurveFor(api, publicKey, true)
}

func PointOnCurveFor(api frontend.API, publicKey [65]frontend.Variable, lookups bool) {
	c := newCurveFor(api, lookups)
	c.assertOnCurve(c.parseKey(publicKey))
}

func (c *curve) parseKey(publicKey [65]frontend.Variable) *point {
	return &point{X: c.fp.FromLimbs(c.fieldLimbs(publicKey[1:33])), Y: c.fp.FromLimbs(c.fieldLimbs(publicKey[33:65]))}
}

func (c *curve) toBytes(e *fpElement) []frontend.Variable {
	limbs := c.canonicalLimbs(e)
	widths := c.fp.ReducedWidths()
	rc := c.rangeChecker()
	var out []frontend.Variable
	for i := len(limbs) - 1; i >= 0; i-- {
		n := widths[i] / 8
		bytes, err := c.api.Compiler().NewHint(p256LimbBytesHint, n, limbs[i])
		if err != nil {
			panic(err)
		}
		for _, b := range bytes {
			rc.Check(b, 8)
		}
		c.api.AssertIsEqual(limbs[i], bigEndianSum(c.api, bytes))
		out = append(out, bytes...)
	}
	return out
}

func ScalarMul(api frontend.API, scalar [32]frontend.Variable, pointIn [65]frontend.Variable) [65]frontend.Variable {
	return ScalarMulFor(api, scalar, pointIn, true)
}

func ScalarMulFor(api frontend.API, scalar [32]frontend.Variable, pointIn [65]frontend.Variable, lookups bool) [65]frontend.Variable {
	c := newCurveFor(api, lookups)
	q := c.parseKey(pointIn)
	c.assertOnCurve(q)
	result := c.scalarMulChecked(q, c.fr.FromLimbs(c.fieldLimbs(scalar[:])))
	var out [65]frontend.Variable
	out[0] = frontend.Variable(0x04)
	copy(out[1:33], c.toBytes(result.X))
	copy(out[33:65], c.toBytes(result.Y))
	return out
}

func p256LimbBytesHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return errors.New("expecting one limb")
	}
	v := new(big.Int).Set(inputs[0])
	for i := len(outputs) - 1; i >= 0; i-- {
		outputs[i].And(v, big.NewInt(0xff))
		v.Rsh(v, 8)
	}
	return nil
}
