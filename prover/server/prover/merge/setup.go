package merge

import (
	"fmt"

	mergeshared "zolana/prover/circuits/spp_merge/shared"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

const MergeNOutputs uint32 = 1

func SupportedNInputs() []uint32 {
	counts := make([]uint32, 0, len(mergeshared.SupportedInputCounts))
	for _, n := range mergeshared.SupportedInputCounts {
		counts = append(counts, uint32(n))
	}
	return counts
}

func IsSupportedNInputs(nInputs uint32) bool {
	return mergeshared.IsSupportedInputCount(int(nInputs))
}

func SetupMerge(nInputs uint32) (*common.TransferProofSystem, error) {
	if !IsSupportedNInputs(nInputs) {
		return nil, fmt.Errorf("merge: unsupported input count %d, want one of %v", nInputs, SupportedNInputs())
	}
	fmt.Println("Setting up merge: nInputs", nInputs, "nOutputs", MergeNOutputs)
	ccs, err := R1CSMerge(int(nInputs))
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return mergeSystem(common.MergeCircuitType, nInputs, pk, vk, ccs), nil
}

func SetupMergeRing(nInputs uint32) (*common.TransferProofSystem, error) {
	if !IsSupportedNInputs(nInputs) {
		return nil, fmt.Errorf("merge-ring: unsupported input count %d, want one of %v", nInputs, SupportedNInputs())
	}
	fmt.Println("Setting up merge-ring: nInputs", nInputs, "nOutputs", MergeNOutputs)
	ccs, err := R1CSMergeRing(int(nInputs))
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return mergeSystem(common.MergeRingCircuitType, nInputs, pk, vk, ccs), nil
}

func mergeSystem(circuitType common.CircuitType, nInputs uint32, pk groth16.ProvingKey, vk groth16.VerifyingKey, ccs constraint.ConstraintSystem) *common.TransferProofSystem {
	return &common.TransferProofSystem{
		CircuitType:      circuitType,
		NInputs:          nInputs,
		NOutputs:         MergeNOutputs,
		RequiresP256:     circuitType == common.MergeCircuitType,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}
}
