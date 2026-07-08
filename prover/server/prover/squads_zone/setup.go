package squadszone

import (
	"fmt"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark/backend/groth16"
)

// SetupZone runs trusted setup for the squads zone circuit shape and returns a
// ZoneProofSystem for proof generation and verification.
func SetupZone(nInputs uint32, nOutputs uint32) (*common.SquadsZoneProofSystem, error) {
	fmt.Println("Setting up squads zone: nInputs", nInputs, "nOutputs", nOutputs)
	ccs, err := R1CSZone(nInputs, nOutputs)
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &common.SquadsZoneProofSystem{
		CircuitType:      common.SquadsZoneCircuitType,
		NInputs:          nInputs,
		NOutputs:         nOutputs,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}
