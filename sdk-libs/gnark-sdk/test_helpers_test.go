package gnarksdk_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func compile(t *testing.T, circuit frontend.Circuit) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func solve(t *testing.T, cs constraint.ConstraintSystem, assignment frontend.Circuit) error {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return cs.IsSolved(witness)
}

func assertAccepted(t *testing.T, cs constraint.ConstraintSystem, assignment frontend.Circuit) {
	t.Helper()
	if err := solve(t, cs, assignment); err != nil {
		t.Fatalf("valid assignment rejected: %v", err)
	}
}

func assertRejected(t *testing.T, cs constraint.ConstraintSystem, assignment frontend.Circuit) {
	t.Helper()
	if solve(t, cs, assignment) == nil {
		t.Fatal("invalid assignment accepted")
	}
}

func plusOne(value *big.Int) *big.Int {
	return new(big.Int).Add(value, big.NewInt(1))
}

// must(t)(protocol.X(...)) unwraps a native protocol value.
func must(t *testing.T) func(*big.Int, error) *big.Int {
	return func(value *big.Int, err error) *big.Int {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
}
