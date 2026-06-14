package transfereddsaonly

import (
	"fmt"

	txcircuit "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func (p *TransferParameters) ValidateShape() error {
	if len(p.Inputs) != int(p.NInputs) {
		return fmt.Errorf("wrong number of inputs: %d, expected: %d", len(p.Inputs), p.NInputs)
	}
	if len(p.Outputs) != int(p.NOutputs) {
		return fmt.Errorf("wrong number of outputs: %d, expected: %d", len(p.Outputs), p.NOutputs)
	}
	for i := range p.Inputs {
		if got := len(p.Inputs[i].StatePathElements); got != txcircuit.StateTreeHeight {
			return fmt.Errorf("input %d: wrong state path length: got %d, expected %d", i, got, txcircuit.StateTreeHeight)
		}
		if got := len(p.Inputs[i].NullifierLowPathElements); got != txcircuit.NullifierTreeHeight {
			return fmt.Errorf("input %d: wrong nullifier path length: got %d, expected %d", i, got, txcircuit.NullifierTreeHeight)
		}
	}
	return nil
}

func ProveTransfer(ps *common.TransferProofSystem, params *TransferParameters) (*common.Proof, error) {
	if params == nil {
		panic("params cannot be nil")
	}

	if err := params.ValidateShape(); err != nil {
		return nil, err
	}

	assignment, err := params.CreateWitness()
	if err != nil {
		return nil, fmt.Errorf("error creating circuit: %v", err)
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("error creating witness: %v", err)
	}

	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
	if err != nil {
		return nil, fmt.Errorf("error proving: %v", err)
	}

	return &common.Proof{Proof: proof}, nil
}
