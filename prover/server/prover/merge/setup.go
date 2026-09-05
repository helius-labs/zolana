package merge

import (
	"fmt"

	mergeshared "zolana/prover/circuits/spp_merge/shared"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

// MergeNOutputs is fixed: a merge always produces exactly one UTXO. The input
// count is per-shape, see SupportedNInputs.
const MergeNOutputs uint32 = 1

// SupportedNInputs are the merge input counts a proving system exists for,
// smallest first.
func SupportedNInputs() []uint32 {
	counts := make([]uint32, 0, len(mergeshared.SupportedInputCounts))
	for _, n := range mergeshared.SupportedInputCounts {
		counts = append(counts, uint32(n))
	}
	return counts
}

// IsSupportedNInputs reports whether a merge circuit exists for nInputs.
func IsSupportedNInputs(nInputs uint32) bool {
	return mergeshared.IsSupportedInputCount(int(nInputs))
}

// SetupMerge runs trusted setup for the default merge circuit at nInputs inputs
// and returns a proof system (reusing common.TransferProofSystem as the generic
// Groth16 holder).
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

// SetupMergeRing runs trusted setup for the policy-ring merge circuit
// (merge_ring) at nInputs inputs.
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
		RequiresP256:     true,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}
}
