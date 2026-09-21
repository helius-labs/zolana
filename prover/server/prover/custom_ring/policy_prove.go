package custom_ring

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/prover/common"
	"zolana/prover/prover/timing"
)

type PolicyProof struct {
	System     *common.RingProofSystem
	Parameters *PolicyParameters
	Timing     *timing.Trace
}

func ProvePolicy(ps *common.RingProofSystem, params *PolicyParameters) (*common.Proof, error) {
	return (PolicyProof{System: ps, Parameters: params}).Prove()
}

func (request PolicyProof) Prove() (*common.Proof, error) {
	ps, params := request.System, request.Parameters
	finishWitness := request.Timing.Start("witness")
	defer finishWitness()
	assignment, err := params.CreateWitness()
	if err != nil {
		return nil, err
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}
	finishWitness()
	finishProve := request.Timing.Start("prove")
	defer finishProve()
	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
	finishProve()
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	return &common.Proof{Proof: proof}, nil
}
