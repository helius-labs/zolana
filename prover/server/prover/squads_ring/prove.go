package squadszone

import (
	"fmt"
	"github.com/consensys/gnark/backend/groth16"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

func (p *ZoneParameters) ValidateShape() error {
	if p.NOutputs != 1 && p.NOutputs != 2 {
		return fmt.Errorf("squads zone: NOutputs must be 1 (withdrawal) or 2 (transfer), got %d", p.NOutputs)
	}
	if len(p.Inputs) != int(p.NInputs) {
		return fmt.Errorf("wrong number of inputs: %d, expected: %d", len(p.Inputs), p.NInputs)
	}
	if len(p.Outputs) != int(p.NOutputs) {
		return fmt.Errorf("wrong number of outputs: %d, expected: %d", len(p.Outputs), p.NOutputs)
	}
	if len(p.InputsDummy) != 0 && len(p.InputsDummy) != int(p.NInputs)-1 {
		return fmt.Errorf("wrong number of dummy flags: %d, expected: %d", len(p.InputsDummy), int(p.NInputs)-1)
	}
	return nil
}

func ProveZone(ps *common.SquadsZoneProofSystem, params *ZoneParameters) (*common.Proof, error) {
	if ps == nil {
		return nil, fmt.Errorf("zone proving system is not loaded")
	}
	if params == nil {
		return nil, fmt.Errorf("zone parameters are missing")
	}

	if err := params.ValidateShape(); err != nil {
		return nil, err
	}

	assignment, err := params.CreateWitness()
	if err != nil {
		return nil, fmt.Errorf("circuit: %w", err)
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness: %w", err)
	}

	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}

	return &common.Proof{Proof: proof}, nil
}
