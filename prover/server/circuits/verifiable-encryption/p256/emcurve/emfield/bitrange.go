package emfield

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func checkBits(api frontend.API, value frontend.Variable, bitCount int) {
	if bitCount <= 0 {
		api.AssertIsEqual(value, 0)
		return
	}
	if bitCount >= api.Compiler().FieldBitLen() {
		panic(fmt.Sprintf("bit range: %d bits do not fit the field", bitCount))
	}
	if constant, ok := api.Compiler().ConstantValue(value); ok {
		if constant.Sign() < 0 || constant.BitLen() > bitCount {
			panic(fmt.Sprintf("bit range: constant %s exceeds %d bits", constant, bitCount))
		}
		return
	}
	if bitCount == 1 {
		api.AssertIsBoolean(value)
		return
	}
	// 1. Hint and constrain all lower bits.
	lowBits, err := api.Compiler().NewHint(LowBitsHint, bitCount-1, value)
	if err != nil {
		panic(err)
	}
	sum := frontend.Variable(0)
	for i, bit := range lowBits {
		api.AssertIsBoolean(bit)
		sum = api.Add(sum, api.Mul(bit, pow2(i)))
	}
	// 2. Derive the remaining top bit from the input and constrain it to a boolean.
	inverseTopWeight := new(big.Int).ModInverse(pow2(bitCount-1), api.Compiler().Field())
	topBit := api.Mul(api.Sub(value, sum), inverseTopWeight)
	api.AssertIsBoolean(topBit)
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

func init() {
	solver.RegisterHint(LowBitsHint)
}
