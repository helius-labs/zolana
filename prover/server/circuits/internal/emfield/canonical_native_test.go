package emfield

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
	f := NewFor(api, c.Modulus, Layout{NbLimbs: 6, LimbBits: 43, PieceBits: 11, Lookups: true})
	f.AssertCanonical(f.FromLimbs(c.Value[:]))
	return nil
}

func TestCanonicalNativeGapEdges(t *testing.T) {
	low, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	l := new(big.Int).Add(pow2(252), low)
	// The native modulus itself requires the split-limb fallback: packing
	// its 254-bit representation into one native element would lose q.
	for _, modulus := range []*big.Int{l, ecc.BN254.ScalarField()} {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &nativeGapCircuit{Modulus: modulus})
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []*big.Int{
			big.NewInt(0), big.NewInt(1), new(big.Int).Sub(modulus, big.NewInt(1)),
			new(big.Int).Set(modulus), new(big.Int).Add(modulus, big.NewInt(1)),
			new(big.Int).Sub(pow2(modulus.BitLen()), big.NewInt(1)),
		} {
			w := &nativeGapCircuit{}
			lay := Layout{NbLimbs: 6, LimbBits: 43}
			for i, limb := range lay.decompose(value, 6) {
				w.Value[i] = limb
			}
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
