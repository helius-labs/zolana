package gadget_test

import (
	"math/big"
	"math/rand/v2"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"zolana/prover/circuits/gadget"
	"zolana/prover/prover-test/poseidon"
)

type legacyGKRHashes struct {
	Inputs  [][2]frontend.Variable
	Outputs []frontend.Variable
}

func (c *legacyGKRHashes) Define(api frontend.API) error {
	hash, err := gadget.NewGKRCompressor(api)
	if err != nil {
		return err
	}
	for i, pair := range c.Inputs {
		api.AssertIsEqual(hash.Compress(pair[0], pair[1]), c.Outputs[i])
	}
	return nil
}

func TestLegacyGKRHashes(t *testing.T) {
	c := &legacyGKRHashes{Inputs: make([][2]frontend.Variable, 24), Outputs: make([]frontend.Variable, 24)}
	w := &legacyGKRHashes{Inputs: make([][2]frontend.Variable, 24), Outputs: make([]frontend.Variable, 24)}
	rng := rand.New(rand.NewPCG(15, 91))
	randomField := func() *big.Int {
		value := new(big.Int)
		for range 4 {
			value.Lsh(value, 64).Add(value, new(big.Int).SetUint64(rng.Uint64()))
		}
		return value.Mod(value, ecc.BN254.ScalarField())
	}
	for i := range w.Inputs {
		left, right := randomField(), randomField()
		if i == 0 {
			left.SetInt64(0)
			right.Sub(ecc.BN254.ScalarField(), big.NewInt(1))
		}
		w.Inputs[i] = [2]frontend.Variable{left, right}
		result, err := poseidon.Hash([]*big.Int{left, right})
		if err != nil {
			t.Fatal(err)
		}
		w.Outputs[i] = result
	}
	if err := test.IsSolved(c, w, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	w.Outputs[3] = 1
	if err := test.IsSolved(c, w, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("accepted wrong Poseidon output")
	}
}
