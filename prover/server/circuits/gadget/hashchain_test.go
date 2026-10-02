package gadget

import (
	"fmt"
	"math/big"
	"testing"

	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
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

func TestNonZeroHashChainRejectsTheValueOfAChainThatFoldsZeroEntries(t *testing.T) {
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

type constantZeroNonZeroHashChainCircuit struct {
	A, B     frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *constantZeroNonZeroHashChainCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(NonZeroHashChain(api, []frontend.Variable{0, c.A, 0, c.B, 0}), c.Expected)
	return nil
}

func TestNonZeroHashChainSkipsCompileTimeZeros(t *testing.T) {
	withConstants, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &constantZeroNonZeroHashChainCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	withoutConstants, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &nonZeroHashChainCircuit{Inputs: make([]frontend.Variable, 2)})
	if err != nil {
		t.Fatal(err)
	}
	if withConstants.GetNbConstraints() != withoutConstants.GetNbConstraints() {
		t.Fatalf("constant zeros cost constraints: %d != %d", withConstants.GetNbConstraints(), withoutConstants.GetNbConstraints())
	}
	for _, values := range [][2]int64{{3, 5}, {0, 5}, {3, 0}, {0, 0}} {
		expected, err := protocol.NonZeroHashChain([]*big.Int{big.NewInt(0), big.NewInt(values[0]), big.NewInt(0), big.NewInt(values[1]), big.NewInt(0)})
		if err != nil {
			t.Fatal(err)
		}
		assignment := &constantZeroNonZeroHashChainCircuit{A: values[0], B: values[1], Expected: expected}
		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := withConstants.IsSolved(witness); err != nil {
			t.Fatalf("%v: compiled circuit differs from host: %v", values, err)
		}
	}
}
