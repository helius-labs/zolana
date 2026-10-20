package ed25519

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type byteElementCircuit struct {
	Bits           int `gnark:"-"`
	Data, Expected []frontend.Variable
}

func (c *byteElementCircuit) Define(api frontend.API) error {
	curve := newCurve(api)
	e := curve.byteElement(curve.fr, c.Data, c.Bits)
	for i, l := range e.Limbs() {
		api.AssertIsEqual(l, c.Expected[i])
	}
	return nil
}

// Every byte of each supported layout must move the re-limbed integer.
func TestByteElementBindsEveryByte(t *testing.T) {
	for _, bits := range []int{253, 255, 512} {
		n, limbs := (bits+7)/8, (bits+layout.LimbBits-1)/layout.LimbBits
		shape := func() *byteElementCircuit {
			return &byteElementCircuit{Bits: bits, Data: make([]frontend.Variable, n), Expected: make([]frontend.Variable, limbs)}
		}
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, shape())
		if err != nil {
			t.Fatal(err)
		}
		raw := make([]byte, 0, n)
		for len(raw) < n {
			block := sha256.Sum256(append([]byte("byte element"), raw...))
			raw = append(raw, block[:]...)
		}
		raw = raw[:n]
		raw[n-1] &= byte(1<<(bits-8*(n-1)) - 1)
		solve := func(data []byte) error {
			w := shape()
			v := new(big.Int)
			for i := n - 1; i >= 0; i-- {
				v.Lsh(v, 8).Add(v, big.NewInt(int64(raw[i])))
				w.Data[i] = data[i]
			}
			for i := range w.Expected {
				w.Expected[i] = new(big.Int).And(new(big.Int).Rsh(v, uint(layout.LimbBits*i)), new(big.Int).Sub(pow2(layout.LimbBits), big.NewInt(1)))
			}
			wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			return cs.IsSolved(wit)
		}
		if err := solve(raw); err != nil {
			t.Fatalf("%d bits: %v", bits, err)
		}
		for i := range raw {
			changed := append([]byte{}, raw...)
			changed[i] ^= 1
			if solve(changed) == nil {
				t.Fatalf("%d bits: byte %d is not bound", bits, i)
			}
		}
	}
}
