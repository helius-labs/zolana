package emcurve

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

func init() {
	solver.RegisterHint(p256SplitLowBitsHint)
}

func pow2(n int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(n))
}

func (c *curve) rangeChecker() *emfield.RangeChecker {
	return c.fp.RangeChecker()
}

func (c *curve) splitLowBits(v frontend.Variable, lowBits, totalBits int) (high, low frontend.Variable) {
	api := c.api
	out, err := api.Compiler().NewHint(p256SplitLowBitsHint, 2, v, lowBits)
	if err != nil {
		panic(err)
	}
	rc := c.rangeChecker()
	rc.Check(out[0], totalBits-lowBits)
	rc.Check(out[1], lowBits)
	api.AssertIsEqual(v, api.Add(api.Mul(out[0], pow2(lowBits)), out[1]))
	return out[0], out[1]
}

func (c *curve) canonicalLimbs(e *fpElement) []frontend.Variable {
	c.fp.AssertCanonical(e)
	return e.Limbs()
}

func p256SplitLowBitsHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 || len(outputs) != 2 {
		return errors.New("expecting a value and a bit count")
	}
	n := uint(inputs[1].Uint64())
	outputs[0].Rsh(inputs[0], n)
	outputs[1].And(inputs[0], new(big.Int).Sub(pow2(int(n)), big.NewInt(1)))
	return nil
}

func (c *curve) limbHintInputs(limbs []frontend.Variable) []frontend.Variable {
	return append([]frontend.Variable{c.lay.LimbBits}, limbs...)
}

func limbHintValue(inputs []*big.Int) *big.Int {
	limbBits := uint(inputs[0].Uint64())
	s := new(big.Int)
	for i := len(inputs) - 1; i >= 1; i-- {
		s.Lsh(s, limbBits).Add(s, inputs[i])
	}
	return s
}
