package aes

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type decodeWidthCircuit struct {
	Count int `gnark:"-"`
}

func (c *decodeWidthCircuit) Define(api frontend.API) error {
	newSpreadTables(api).decodeWordSum(0, c.Count)
	return nil
}

func TestDecodeRejectsFieldWrappingWidth(t *testing.T) {
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &decodeWidthCircuit{Count: 13}); err == nil {
		t.Fatal("13-byte spread word compiled despite native-field wraparound")
	}
}
