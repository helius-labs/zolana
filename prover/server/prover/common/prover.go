package common

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// Prover runs Groth16 on the assignment assign builds.
type Prover func(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, assign func() (frontend.Circuit, error)) (groth16.Proof, error)

// Run proves with p, or with gnark's CPU prover when p is nil.
func (p Prover) Run(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, assign func() (frontend.Circuit, error)) (groth16.Proof, error) {
	if p != nil {
		return p(ccs, pk, assign)
	}
	assignment, err := assign()
	if err != nil {
		return nil, err
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}
	proof, err := groth16.Prove(ccs, pk, full)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	return proof, nil
}
