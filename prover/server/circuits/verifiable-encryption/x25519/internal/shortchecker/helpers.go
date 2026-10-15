package shortchecker

import (
	"math/big"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
)

func pow2(n int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(n))
}

func (c *curve) rangeChecker() *emfield.RangeChecker {
	return c.fp.RangeChecker()
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
