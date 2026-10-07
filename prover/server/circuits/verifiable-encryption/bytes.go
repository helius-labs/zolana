package verifiableencryption

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/rangecheck"

	"zolana/prover/circuits/gadget"
)

const (
	byteBits = 8
	// Below 32 bytes the value stays under the BN254 modulus, so the byte
	// decomposition is unique.
	maxBigEndianBytes = 31
)

func init() {
	solver.RegisterHint(LowBytesHint)
}

func LowBytesHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 || len(outputs) == 0 {
		return fmt.Errorf("low bytes: expected one input and at least one output, got %d and %d", len(inputs), len(outputs))
	}
	rest := new(big.Int).Set(inputs[0])
	mask := big.NewInt(0xff)
	for i := len(outputs) - 1; i >= 0; i-- {
		outputs[i].And(rest, mask)
		rest.Rsh(rest, byteBits)
	}
	return nil
}

// BytesBigEndian decomposes value into n range-checked big-endian bytes and so
// also bounds value below 2^(8n).
func BytesBigEndian(api frontend.API, value frontend.Variable, n int) []frontend.Variable {
	if n < 1 || n > maxBigEndianBytes {
		panic(fmt.Sprintf("bytes big endian: %d bytes, want 1 to %d", n, maxBigEndianBytes))
	}
	out, err := api.Compiler().NewHint(LowBytesHint, n, value)
	if err != nil {
		panic(err)
	}
	rc := rangecheck.New(api)
	for _, b := range out {
		rc.Check(b, byteBits)
	}
	api.AssertIsEqual(value, gadget.BytesToField(api, out))
	return out
}

// FieldToBytesBE decomposes v through its bits; at 32 bytes the decomposition
// is the canonical one of the field element.
func FieldToBytesBE(api frontend.API, v frontend.Variable, nbytes int) []frontend.Variable {
	return gadget.BitsToBytesBE(api, bits.ToBinary(api, v, bits.WithNbDigits(nbytes*byteBits)))
}
