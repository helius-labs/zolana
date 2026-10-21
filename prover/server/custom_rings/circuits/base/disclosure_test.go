package base_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

type packDisclosureCircuit struct {
	Bytes  [40]frontend.Variable
	Fields [2]frontend.Variable `gnark:",public"`
}

func (c *packDisclosureCircuit) Define(api frontend.API) error {
	for i, field := range base.PackDisclosure(api, c.Bytes[:]) {
		api.AssertIsEqual(field, c.Fields[i])
	}
	return nil
}

// A 40-byte slot fills one chunk and leaves its last 9 bytes first in the second chunk, the zero padding after them.
func TestPackDisclosureLeftAlignsTheTail(t *testing.T) {
	var raw [40]byte
	witness := &packDisclosureCircuit{}
	for i := range raw {
		raw[i] = byte(0xc0 + i)
		witness.Bytes[i] = raw[i]
	}
	witness.Fields[0] = new(big.Int).SetBytes(raw[:31])
	witness.Fields[1] = new(big.Int).Lsh(new(big.Int).SetBytes(raw[31:]), 8*22)
	if err := test.IsSolved(&packDisclosureCircuit{}, witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("left-aligned tail refused: %v", err)
	}
	witness.Fields[1] = new(big.Int).SetBytes(raw[31:])
	if test.IsSolved(&packDisclosureCircuit{}, witness, ecc.BN254.ScalarField()) == nil {
		t.Fatal("right-aligned tail accepted")
	}
}
