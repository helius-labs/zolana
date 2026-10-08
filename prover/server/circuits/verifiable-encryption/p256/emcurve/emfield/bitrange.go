package emfield

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func init() {
	solver.RegisterHint(LowBitsHint)
}

func LowBitsHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return errors.New("low bits: expecting one input")
	}
	for i, out := range outputs {
		out.SetUint64(uint64(inputs[0].Bit(i)))
	}
	return nil
}

func checkBits(api frontend.API, v frontend.Variable, n int) {
	if n <= 0 {
		api.AssertIsEqual(v, 0)
		return
	}
	if n >= api.Compiler().FieldBitLen() {
		panic(fmt.Sprintf("bit range: %d bits do not fit the field", n))
	}
	if c, ok := api.Compiler().ConstantValue(v); ok {
		if c.Sign() < 0 || c.BitLen() > n {
			panic(fmt.Sprintf("bit range: constant %s exceeds %d bits", c, n))
		}
		return
	}
	if n == 1 {
		api.AssertIsBoolean(v)
		return
	}
	low, err := api.Compiler().NewHint(LowBitsHint, n-1, v)
	if err != nil {
		panic(err)
	}
	sum := frontend.Variable(0)
	for i, b := range low {
		api.AssertIsBoolean(b)
		sum = api.Add(sum, api.Mul(b, pow2(i)))
	}
	inv := new(big.Int).ModInverse(pow2(n-1), api.Compiler().Field())
	top := api.Mul(api.Sub(v, sum), inv)
	api.AssertIsBoolean(top)
}
