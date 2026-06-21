package merge

import (
	"fmt"

	mergecircuit "zolana/prover/circuits/spp_merge"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

// MergeNInputs and MergeNOutputs are the single supported merge shape.
const (
	MergeNInputs  uint32 = mergecircuit.MergeInputs
	MergeNOutputs uint32 = 1
)

// SetupMerge runs trusted setup for the merge circuit and returns a proof system
// (reusing common.TransferProofSystem as the generic Groth16 holder).
func SetupMerge() (*common.TransferProofSystem, error) {
	fmt.Println("Setting up merge: nInputs", MergeNInputs, "nOutputs", MergeNOutputs)
	ccs, err := R1CSMerge()
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return mergeSystem(pk, vk, ccs), nil
}

func mergeSystem(pk groth16.ProvingKey, vk groth16.VerifyingKey, ccs constraint.ConstraintSystem) *common.TransferProofSystem {
	return &common.TransferProofSystem{
		CircuitType:      common.MergeCircuitType,
		NInputs:          MergeNInputs,
		NOutputs:         MergeNOutputs,
		RequiresP256:     true,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}
}
