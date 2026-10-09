package emcurve

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

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

func ScalarMulGenerator(api frontend.API, scalar [32]frontend.Variable) [65]frontend.Variable {
	return ScalarMulGeneratorFor(api, scalar, true)
}

func ScalarMulGeneratorFor(api frontend.API, scalar [32]frontend.Variable, lookups bool) [65]frontend.Variable {
	c := newCurveFor(api, lookups)
	publicPoint := c.scalarMulBase(c.parseScalar(scalar))
	var encodedPoint [65]frontend.Variable
	encodedPoint[0] = frontend.Variable(0x04)
	copy(encodedPoint[1:33], c.toBytes(publicPoint.X))
	copy(encodedPoint[33:65], c.toBytes(publicPoint.Y))
	return encodedPoint
}

func ScalarMul(api frontend.API, scalar [32]frontend.Variable, pointBytes [65]frontend.Variable) [65]frontend.Variable {
	return ScalarMulFor(api, scalar, pointBytes, true)
}

func ScalarMulFor(api frontend.API, scalar [32]frontend.Variable, pointBytes [65]frontend.Variable, lookups bool) [65]frontend.Variable {
	c := newCurveFor(api, lookups)
	inputPoint := c.parseKey(pointBytes)
	c.assertOnCurve(inputPoint)
	product := c.scalarMulChecked(inputPoint, c.parseScalar(scalar))
	var encodedPoint [65]frontend.Variable
	encodedPoint[0] = frontend.Variable(0x04)
	copy(encodedPoint[1:33], c.toBytes(product.X))
	copy(encodedPoint[33:65], c.toBytes(product.Y))
	return encodedPoint
}

func ECDH(api frontend.API, ephemeralSecretKey [32]frontend.Variable, recipientPubkey [65]frontend.Variable) [32]frontend.Variable {
	return ECDHFor(api, ephemeralSecretKey, recipientPubkey, true)
}

func ECDHFor(api frontend.API, ephemeralSecretKey [32]frontend.Variable, recipientPubkey [65]frontend.Variable, lookups bool) [32]frontend.Variable {
	sharedPointBytes := ScalarMulFor(api, ephemeralSecretKey, recipientPubkey, lookups)
	var sharedX [32]frontend.Variable
	copy(sharedX[:], sharedPointBytes[1:33])
	return sharedX
}

func (c *curve) parseKey(publicKey [65]frontend.Variable) *point {
	c.api.AssertIsEqual(publicKey[0], uncompressedPrefix)
	c.checkBytes(publicKey[1:])
	publicPoint := &point{
		X: c.fp.Reduced(c.fieldLimbs(publicKey[1:33])),
		Y: c.fp.Reduced(c.fieldLimbs(publicKey[33:65])),
	}
	c.fp.AssertCanonical(publicPoint.X)
	c.fp.AssertCanonical(publicPoint.Y)
	return publicPoint
}

func (c *curve) checkBytes(bytes []frontend.Variable) {
	rangeChecker := c.rangeChecker()
	for _, byteValue := range bytes {
		rangeChecker.Check(byteValue, 8)
	}
}

func (c *curve) parseScalar(bytes [32]frontend.Variable) *frElement {
	c.checkBytes(bytes[:])
	return c.fr.Reduced(c.fieldLimbs(bytes[:]))
}

func (c *curve) toBytes(coordinate *fpElement) []frontend.Variable {
	// 1. Constrain the coordinate to its canonical residue.
	limbs := c.canonicalLimbs(coordinate)
	widths := c.fp.ReducedWidths()
	rangeChecker := c.rangeChecker()
	var coordinateBytes []frontend.Variable
	// 2. Decode limbs from most to least significant; bound and recompose every byte group.
	for i := len(limbs) - 1; i >= 0; i-- {
		byteCount := widths[i] / 8
		bytes, err := c.api.Compiler().NewHint(p256LimbBytesHint, byteCount, limbs[i])
		if err != nil {
			panic(err)
		}
		for _, byteValue := range bytes {
			rangeChecker.Check(byteValue, 8)
		}
		c.api.AssertIsEqual(limbs[i], bigEndianSum(c.api, bytes))
		coordinateBytes = append(coordinateBytes, bytes...)
	}
	return coordinateBytes
}

func (c *curve) canonicalLimbs(e *fpElement) []frontend.Variable {
	c.fp.AssertCanonical(e)
	return e.Limbs()
}

func (c *curve) splitLowBits(value frontend.Variable, lowBits, totalBits int) (high, low frontend.Variable) {
	api := c.api
	if lowBits < 0 || lowBits > totalBits || totalBits >= api.Compiler().FieldBitLen() {
		panic("bit split must fit the native field without wraparound")
	}
	// 1. Obtain candidate high and low parts from the hint.
	parts, err := api.Compiler().NewHint(p256SplitLowBitsHint, 2, value, lowBits)
	if err != nil {
		panic(err)
	}
	// 2. Bound both parts and require their weighted sum to recover the input.
	high, low = parts[0], parts[1]
	rangeChecker := c.rangeChecker()
	rangeChecker.Check(high, totalBits-lowBits)
	rangeChecker.Check(low, lowBits)
	weightedHigh := api.Mul(high, pow2(lowBits))
	recomposed := api.Add(weightedHigh, low)
	api.AssertIsEqual(value, recomposed)
	return high, low
}

func p256LimbBytesHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return errors.New("expecting one limb")
	}
	remainingLimb := new(big.Int).Set(inputs[0])
	for i := len(outputs) - 1; i >= 0; i-- {
		outputs[i].And(remainingLimb, big.NewInt(0xff))
		remainingLimb.Rsh(remainingLimb, 8)
	}
	return nil
}

func pow2(n int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(n))
}

func (c *curve) rangeChecker() *emfield.RangeChecker {
	return c.fp.RangeChecker()
}

func p256SplitLowBitsHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 || len(outputs) != 2 {
		return errors.New("expecting a value and a bit count")
	}
	lowBits := uint(inputs[1].Uint64())
	outputs[0].Rsh(inputs[0], lowBits)
	outputs[1].And(inputs[0], new(big.Int).Sub(pow2(int(lowBits)), big.NewInt(1)))
	return nil
}

func (c *curve) limbHintInputs(limbs []frontend.Variable) []frontend.Variable {
	return append([]frontend.Variable{c.layout.LimbBits}, limbs...)
}

func limbHintValue(inputs []*big.Int) *big.Int {
	limbBits := uint(inputs[0].Uint64())
	value := new(big.Int)
	for i := len(inputs) - 1; i >= 1; i-- {
		value.Lsh(value, limbBits).Add(value, inputs[i])
	}
	return value
}

func init() { solver.RegisterHint(p256LimbBytesHint, p256SplitLowBitsHint) }
