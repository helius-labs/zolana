package custom_ring

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/prover/common"
)

const policyCircuitType = common.CustomRingPolicyCircuitType

func ProveCustomRingPolicy(ps *common.RingProofSystem, params *CustomRingPolicyParameters) (*common.Proof, error) {
	assignment, err := params.CreateWitness()
	if err != nil {
		return nil, err
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}
	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	return &common.Proof{Proof: proof}, nil
}

func ProveCustomRingAudit(ps *common.RingProofSystem, params *CustomRingAuditParameters) (*common.Proof, error) {
	assignment, err := params.CreateWitness()
	if err != nil {
		return nil, err
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}
	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	return &common.Proof{Proof: proof}, nil
}
