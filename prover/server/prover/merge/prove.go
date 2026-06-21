package merge

import (
	"fmt"

	mergecircuit "zolana/prover/circuits/spp_merge"
	transaction "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// ValidateShape checks the parameter arity matches the fixed 8-in/1-out merge
// shape and the Merkle path heights before witness assignment.
func (p *MergeParameters) ValidateShape() error {
	if len(p.Inputs) != mergecircuit.MergeInputs {
		return fmt.Errorf("merge: wrong number of inputs: got %d, expected %d", len(p.Inputs), mergecircuit.MergeInputs)
	}
	if got := len(p.UserViewingPubkey); got != 65 {
		return fmt.Errorf("merge: user viewing pubkey must be 65 bytes, got %d", got)
	}
	for i := range p.Inputs {
		if got := len(p.Inputs[i].StatePathElements); got != transaction.StateTreeHeight {
			return fmt.Errorf("merge: input %d state path length: got %d, expected %d", i, got, transaction.StateTreeHeight)
		}
		if got := len(p.Inputs[i].NullifierLowPathElements); got != transaction.NullifierTreeHeight {
			return fmt.Errorf("merge: input %d nullifier path length: got %d, expected %d", i, got, transaction.NullifierTreeHeight)
		}
	}
	return nil
}

func ProveMerge(ps *common.TransferProofSystem, params *MergeParameters) (*common.Proof, error) {
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
