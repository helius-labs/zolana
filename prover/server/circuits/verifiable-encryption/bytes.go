package verifiableencryption

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/rangecheck"
)

const byteBits = 8

func init() {
	solver.RegisterHint(LowBytesHint)
}

func LowBytesHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 || len(outputs) < 2 {
		return fmt.Errorf("low bytes: expected one input and at least two outputs, got %d and %d", len(inputs), len(outputs))
	}
	n := len(outputs) - 1
	rest := new(big.Int).Set(inputs[0])
	mask := big.NewInt(0xff)
	for i := n; i >= 1; i-- {
		outputs[i].And(rest, mask)
		rest.Rsh(rest, byteBits)
	}
	outputs[0].Set(rest)
	return nil
}

func BytesToField(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	acc := frontend.Variable(0)
	for _, b := range bytes {
		acc = api.Add(api.Mul(acc, 256), b)
	}
	return acc
}

func BytesBigEndian(api frontend.API, value frontend.Variable, n int) []frontend.Variable {
	out, err := api.Compiler().NewHint(LowBytesHint, n+1, value)
	if err != nil {
		panic(err)
	}
	api.AssertIsEqual(value, BytesToField(api, out[1:]))
	rc := rangecheck.New(api)
	for _, b := range out[1:] {
		rc.Check(b, byteBits)
	}
	return out[1:]
}

func FieldToBytesBE(api frontend.API, v frontend.Variable, nbytes int) []frontend.Variable {
	allBits := bits.ToBinary(api, v, bits.WithNbDigits(nbytes*8))
	out := make([]frontend.Variable, nbytes)
	for i := 0; i < nbytes; i++ {
		start := (nbytes - 1 - i) * 8
		b := frontend.Variable(0)
		for j := 0; j < 8; j++ {
			b = api.Add(b, api.Mul(allBits[start+j], big.NewInt(int64(1<<j))))
		}
		out[i] = b
	}
	return out
}
