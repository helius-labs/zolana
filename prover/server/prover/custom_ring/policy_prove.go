package custom_ring

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"zolana/prover/prover/backend"

	"zolana/prover/prover/common"
)

func ProvePolicy(ps *common.RingProofSystem, params *PolicyParameters) (*common.Proof, error) {
	assignment, err := params.CreateWitness()
	if err != nil {
		return nil, err
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}
	proof, err := backend.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	return &common.Proof{Proof: proof}, nil
}
