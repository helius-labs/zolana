package nonnative

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type nativeGapCircuit struct {
	Value   [6]frontend.Variable
	Modulus *big.Int `gnark:"-"`
}

func (c *nativeGapCircuit) Define(api frontend.API) error {
	f := NewFor(api, c.Modulus, edProjectionLayout)
	f.AssertCanonical(fromLimbs(f, c.Value[:]))
	return nil
}

func TestCanonicalNativeGapEdges(t *testing.T) {
	// The native modulus itself needs the split-limb fallback, since one packed
	// native element cannot hold its 254-bit representation.
	for _, modulus := range []*big.Int{edScalarOrder, ecc.BN254.ScalarField()} {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &nativeGapCircuit{Modulus: modulus})
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []*big.Int{
			big.NewInt(0), big.NewInt(1), new(big.Int).Sub(modulus, big.NewInt(1)),
			new(big.Int).Set(modulus), new(big.Int).Add(modulus, big.NewInt(1)),
			new(big.Int).Sub(pow2(modulus.BitLen()), big.NewInt(1)),
		} {
			w := &nativeGapCircuit{Value: edLimbs(value)}
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			err = cs.IsSolved(witness)
			if (err == nil) != (value.Cmp(modulus) < 0) {
				t.Fatalf("modulus %s value %s: %v", modulus, value, err)
			}
		}
	}
}
