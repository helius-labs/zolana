package gadget

import (
	"fmt"
	"math/big"
	"testing"

	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type nonZeroHashChainCircuit struct {
	Inputs   []frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *nonZeroHashChainCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(NonZeroHashChain(api, c.Inputs), c.Expected)
	return nil
}

func nonZeroHashChainAssignment(inputs []*big.Int, expected *big.Int) *nonZeroHashChainCircuit {
	assignment := &nonZeroHashChainCircuit{
		Inputs:   make([]frontend.Variable, len(inputs)),
		Expected: expected,
	}
	for i, input := range inputs {
		assignment.Inputs[i] = input
	}
	return assignment
}

func TestNonZeroHashChainMatchesHost(t *testing.T) {
	cases := [][]int64{
		{0},
		{0, 0, 0},
		{7},
		{7, 0},
		{0, 7},
		{3, 0, 5, 0, 0, 9},
		{3, 5, 9, 11},
	}
	for _, values := range cases {
		t.Run(fmt.Sprint(values), func(t *testing.T) {
			inputs := make([]*big.Int, len(values))
			for i, value := range values {
				inputs[i] = big.NewInt(value)
			}
			expected, err := protocol.NonZeroHashChain(inputs)
			if err != nil {
				t.Fatal(err)
			}
			circuit := &nonZeroHashChainCircuit{Inputs: make([]frontend.Variable, len(inputs))}
			if err := test.IsSolved(circuit, nonZeroHashChainAssignment(inputs, expected), ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("circuit differs from host: %v", err)
			}
		})
	}
}

func TestNonZeroHashChainRejectsAZeroCountedAsAnEntry(t *testing.T) {
	inputs := []*big.Int{big.NewInt(3), big.NewInt(0), big.NewInt(5)}
	withZero, err := protocol.HashChain([]*big.Int{big.NewInt(0), big.NewInt(3), big.NewInt(0), big.NewInt(5)})
	if err != nil {
		t.Fatal(err)
	}
	circuit := &nonZeroHashChainCircuit{Inputs: make([]frontend.Variable, len(inputs))}
	if err := test.IsSolved(circuit, nonZeroHashChainAssignment(inputs, withZero), ecc.BN254.ScalarField()); err == nil {
		t.Fatal("a zero entry entered the chain")
	}
}
