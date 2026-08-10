package squadsring

import (
	"fmt"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark/backend/groth16"
)

func SetupRing(nInputs uint32, nOutputs uint32) (*common.SquadsRingProofSystem, error) {
	fmt.Println("Setting up squads ring: nInputs", nInputs, "nOutputs", nOutputs)
	ccs, err := R1CSRing(nInputs, nOutputs)
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &common.SquadsRingProofSystem{
		CircuitType:      common.SquadsRingCircuitType,
		NInputs:          nInputs,
		NOutputs:         nOutputs,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}
