package squads_ring_fold

import (
	"fmt"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark/backend/groth16"
)

// SetupFold runs trusted setup for one fold proving system.
//
// The outer circuit compiles in the inner verifying key, so the inner key must
// already exist and an inner key rotation invalidates every fold key built from
// it.
func SetupFold(p Params, inner *common.SquadsRingProofSystem) (*common.SquadsRingFoldProofSystem, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if inner == nil {
		return nil, fmt.Errorf("fold setup needs the inner proving system")
	}
	if inner.NInputs != p.NInputs || inner.NOutputs != p.NOutputs {
		return nil, fmt.Errorf(
			"inner system is %dx%d, params name %dx%d",
			inner.NInputs, inner.NOutputs, p.NInputs, p.NOutputs,
		)
	}

	fmt.Printf("Setting up squads ring fold: %d legs of %dx%d\n", p.Legs, p.NInputs, p.NOutputs)
	ccs, err := R1CSFold(p, inner.ConstraintSystem, inner.VerifyingKey)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	fmt.Printf("Fold constraints: %d\n", ccs.GetNbConstraints())

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("setup: %w", err)
	}
	return &common.SquadsRingFoldProofSystem{
		NInputs:          p.NInputs,
		NOutputs:         p.NOutputs,
		Legs:             p.Legs,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}
