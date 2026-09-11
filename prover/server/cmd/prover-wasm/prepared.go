package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	native "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"zolana/prover/prover/common"
)

// Adapt Mopro's prepared arithmetic bridge to Zolana's bundled proving system.
// The circuit, keys, witness assignment and proof JSON remain Zolana's formats.
type preparedCircuit struct {
	cs     *cs.R1CS
	pk     groth16.ProvingKey
	kernel proofKernel
}

type parameters interface {
	ValidateShape() error
	CreateWitness() (frontend.Circuit, error)
}

func assignmentWitness(params parameters) (witness.Witness, error) {
	if err := params.ValidateShape(); err != nil {
		return nil, err
	}
	assignment, err := params.CreateWitness()
	if err != nil {
		return nil, fmt.Errorf("create assignment: %w", err)
	}
	return frontend.NewWitness(assignment, ecc.BN254.ScalarField())
}

func (c *preparedCircuit) prove(params parameters) (*common.Proof, error) {
	started := profileStart()
	w, err := assignmentWitness(params)
	profileEnd("witness", started)
	if err != nil {
		return nil, err
	}
	var proof groth16.Proof
	if c.kernel == nil {
		proof, err = groth16.Prove(c.cs, c.pk, w)
	} else {
		proof, err = proveAccelerated(c.cs, c.pk.(*native.ProvingKey), c.kernel, w)
	}
	if err != nil {
		return nil, err
	}
	return &common.Proof{Proof: proof}, nil
}
