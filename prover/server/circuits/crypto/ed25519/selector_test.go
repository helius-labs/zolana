package ed25519

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type selectorCircuit struct{ Bits, Expected []frontend.Variable }

func (c *selectorCircuit) Define(api frontend.API) error {
	for _, b := range c.Bits {
		api.AssertIsBoolean(b)
	}
	for i, flag := range oneHot(api, c.Bits) {
		api.AssertIsEqual(flag, c.Expected[i])
	}
	return nil
}

func TestOneHotSelectors(t *testing.T) {
	for n := 0; n <= 8; n++ {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &selectorCircuit{
			Bits: make([]frontend.Variable, n), Expected: make([]frontend.Variable, 1<<n),
		})
		if err != nil {
			t.Fatal(err)
		}
		for value := 0; value < 1<<n; value++ {
			w := &selectorCircuit{Bits: make([]frontend.Variable, n), Expected: make([]frontend.Variable, 1<<n)}
			for i := range w.Bits {
				w.Bits[i] = (value >> i) & 1
			}
			for i := range w.Expected {
				w.Expected[i] = 0
			}
			w.Expected[value] = 1
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := cs.IsSolved(witness); err != nil {
				t.Fatalf("%d-bit selector %d: %v", n, value, err)
			}
			if value == 0 {
				w.Expected[0] = 0
				bad, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				if cs.IsSolved(bad) == nil {
					t.Fatal("incorrect selector output accepted")
				}
			}
		}
	}
}
