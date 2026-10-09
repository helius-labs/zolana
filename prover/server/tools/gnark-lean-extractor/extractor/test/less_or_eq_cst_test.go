package extractor_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/reilabs/gnark-lean-extractor/v3/extractor"
)

type ToBinary256 struct {
	In  frontend.Variable
	Out frontend.Variable `gnark:",public"`
}

func (c *ToBinary256) Define(api frontend.API) error {
	digits := bits.ToBinary(api, c.In, bits.WithNbDigits(256))
	api.AssertIsEqual(digits[0], c.Out)
	return nil
}

func TestToBinary256(t *testing.T) {
	out, err := extractor.CircuitToLean(&ToBinary256{}, ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}
	checkOutput(t, out)
}
