package gadget

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	merkletree "zolana/prover/merkle-tree"
)

type poseidon2Circuit struct {
	Left  frontend.Variable
	Right frontend.Variable
	Hash  frontend.Variable `gnark:",public"`
}

func (c *poseidon2Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(NullifierTreeHash(api, c.Left, c.Right), c.Hash)
	return nil
}

// The gadget computes gnark-crypto's compression and costs 3 constraints per
// S-box, nothing else.
func TestPoseidon2CompressMatchesNative(t *testing.T) {
	pMinusOne := new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
	for _, in := range [][2]*big.Int{
		{big.NewInt(0), big.NewInt(0)},
		{big.NewInt(1), big.NewInt(2)},
		{pMinusOne, big.NewInt(0)},
		{pMinusOne, pMinusOne},
	} {
		want := merkletree.TreeHash(in[0], in[1])
		if err := test.IsSolved(&poseidon2Circuit{}, &poseidon2Circuit{Left: in[0], Right: in[1], Hash: want}, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("compress(%s, %s): %v", in[0], in[1], err)
		}
		wrong := new(big.Int).Add(want, big.NewInt(1))
		if err := test.IsSolved(&poseidon2Circuit{}, &poseidon2Circuit{Left: in[0], Right: in[1], Hash: wrong}, ecc.BN254.ScalarField()); err == nil {
			t.Fatalf("compress(%s, %s) accepted a wrong hash", in[0], in[1])
		}
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &poseidon2Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	sboxes := NullifierTreeHashFullRounds*NullifierTreeHashWidth + NullifierTreeHashPartialRounds
	if got, want := cs.GetNbConstraints(), 3*sboxes+1; got != want {
		t.Fatalf("constraints: got %d want %d", got, want)
	}
}
