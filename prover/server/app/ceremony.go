package app

import (
	"fmt"

	"github.com/helius-labs/zolana/prover/server/prover/common"
	mergeprover "github.com/helius-labs/zolana/prover/server/prover/merge"
	"github.com/helius-labs/zolana/prover/server/prover/nullifier_tree"
	transfereddsa "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa"

	"github.com/consensys/gnark/constraint"
)

// validateCoreCeremonyShape accepts the default-ring transfer rails and the
// default merge. Custom-ring rails and the batch address-append circuit are
// rejected here; address-append stays on its own r1cs command path.
func validateCoreCeremonyShape(circuit common.CircuitType, nInputs, nOutputs uint32) error {
	switch circuit {
	case common.TransferConfidentialCircuitType,
		common.TransferAnonymousRingEddsaCircuitType,
		common.MergeCircuitType:
	default:
		return fmt.Errorf("%s is outside the core ceremony", circuit)
	}
	if circuit == common.MergeCircuitType && nOutputs == 0 {
		nOutputs = 1
	}
	if !(common.ProofShape{Circuit: circuit, Inputs: nInputs, Outputs: nOutputs}).Supported() {
		return fmt.Errorf("unsupported %s shape %dx%d", circuit, nInputs, nOutputs)
	}
	return nil
}

func compileCeremonyConstraintSystem(circuit common.CircuitType, nInputs, nOutputs, treeHeight, batchSize uint32) (constraint.ConstraintSystem, error) {
	switch circuit {
	case common.BatchAddressAppendCircuitType:
		if treeHeight == 0 || batchSize == 0 {
			return nil, fmt.Errorf("[Batch address append]: tree height and batch size must be provided")
		}
		return nullifiertree.R1CSBatchAddressAppend(treeHeight, batchSize)
	case common.TransferConfidentialCircuitType,
		common.TransferAnonymousRingEddsaCircuitType,
		common.MergeCircuitType:
		if circuit == common.MergeCircuitType && nOutputs == 0 {
			nOutputs = 1
		}
		if err := validateCoreCeremonyShape(circuit, nInputs, nOutputs); err != nil {
			return nil, err
		}
		switch circuit {
		case common.TransferConfidentialCircuitType:
			return transfereddsa.R1CSTransfer(nInputs, nOutputs, transfereddsa.ConfidentialVariant)
		case common.TransferAnonymousRingEddsaCircuitType:
			return transfereddsa.R1CSAnonymousEddsaTransfer(nInputs, nOutputs)
		default:
			return mergeprover.R1CSMerge(int(nInputs))
		}
	default:
		return nil, fmt.Errorf("%s is outside the core ceremony", circuit)
	}
}

// importCoreProvingSystem loads pk/vk extracted from a phase-2 contribution
// and the R1CS that contribution was initialized from, and returns the proving
// system file setup-transfer / setup-merge would have written.
func importCoreProvingSystem(circuit common.CircuitType, nInputs, nOutputs uint32, pkPath, vkPath, r1csPath string) (*common.TransferProofSystem, error) {
	if r1csPath == "" {
		return nil, fmt.Errorf("r1cs is required")
	}
	if circuit == common.MergeCircuitType && nOutputs == 0 {
		nOutputs = 1
	}
	if err := validateCoreCeremonyShape(circuit, nInputs, nOutputs); err != nil {
		return nil, err
	}

	pk, err := common.LoadProvingKey(pkPath)
	if err != nil {
		return nil, err
	}
	vk, err := common.LoadVerifyingKey(vkPath)
	if err != nil {
		return nil, err
	}
	ccs, err := common.LoadConstraintSystem(r1csPath)
	if err != nil {
		return nil, err
	}
	commitments, err := common.BindCeremonyCommitment(pk, vk, ccs)
	if err != nil {
		return nil, err
	}

	ps := &common.TransferProofSystem{
		CircuitType:      circuit,
		NInputs:          nInputs,
		NOutputs:         nOutputs,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}
	switch circuit {
	case common.TransferConfidentialCircuitType:
		if commitments != 0 {
			return nil, fmt.Errorf("transfer-confidential constraint system has %d commitments", commitments)
		}
		ps.Confidential = true
	case common.TransferAnonymousRingEddsaCircuitType:
		if commitments != 1 {
			return nil, fmt.Errorf("transfer-eddsa-ring constraint system has %d commitments, want 1", commitments)
		}
		ps.HasCommitment = true
		ps.Confidential = true
	case common.MergeCircuitType:
		if commitments != 1 {
			return nil, fmt.Errorf("merge constraint system has %d commitments, want 1", commitments)
		}
		ps.HasCommitment = true
		ps.NOutputs = mergeprover.MergeNOutputs
	}
	return ps, nil
}
