package sha512

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type parityWidthCircuit struct {
	Overflow bool `gnark:"-"`
}

func (c *parityWidthCircuit) Define(api frontend.API) error {
	value := new(big.Int).Lsh(big.NewInt(1), 129)
	if c.Overflow {
		value.Lsh(value, 1)
	}
	sha512New(api).extractParity(value)
	return nil
}

func TestParityConstantHasSameWidthAsWitness(t *testing.T) {
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &parityWidthCircuit{}); err != nil {
		t.Fatal(err)
	}
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &parityWidthCircuit{Overflow: true}); err == nil {
		t.Fatal("constant above 130 bits passed the parity gadget")
	}
}
