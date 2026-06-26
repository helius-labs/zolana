package transfereddsaonly

import (
	"fmt"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark/backend/groth16"
)

// SetupTransferCircuit runs trusted setup for the Solana-only spp_transaction
// circuit. Returns a TransferProofSystem for proof generation and verification.
func SetupTransferCircuit(circuit common.CircuitType, nInputs uint32, nOutputs uint32) (*common.TransferProofSystem, error) {
	switch circuit {
	case common.TransferCircuitType:
		return SetupTransfer(nInputs, nOutputs, false)
	case common.TransferConfidentialCircuitType:
		return SetupTransfer(nInputs, nOutputs, true)
	default:
		return nil, fmt.Errorf("invalid transfer circuit: %s", circuit)
	}
}

func SetupTransfer(nInputs uint32, nOutputs uint32, confidential bool) (*common.TransferProofSystem, error) {
	circuitType := common.TransferCircuitType
	if confidential {
		circuitType = common.TransferConfidentialCircuitType
	}
	fmt.Println("Setting up", circuitType, "(eddsa/solana-only): nInputs", nInputs, "nOutputs", nOutputs)
	ccs, err := R1CSTransfer(nInputs, nOutputs, confidential)
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &common.TransferProofSystem{
		CircuitType:      circuitType,
		NInputs:          nInputs,
		NOutputs:         nOutputs,
		RequiresP256:     false,
		Confidential:     confidential,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}

func ImportTransferSetup(nInputs uint32, nOutputs uint32, pkPath string, vkPath string) (*common.TransferProofSystem, error) {
	fmt.Println("Compiling circuit")
	ccs, err := R1CSTransfer(nInputs, nOutputs, false)
	if err != nil {
		fmt.Println("Error compiling circuit")
		return nil, err
	}
	fmt.Println("Compiled circuit successfully")

	pk, err := common.LoadProvingKey(pkPath)
	if err != nil {
		return nil, err
	}

	vk, err := common.LoadVerifyingKey(vkPath)
	if err != nil {
		return nil, err
	}

	return &common.TransferProofSystem{
		CircuitType:      common.TransferCircuitType,
		NInputs:          nInputs,
		NOutputs:         nOutputs,
		RequiresP256:     false,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}

func ImportTransferSetupWithR1CS(nInputs uint32, nOutputs uint32, pkPath string, vkPath string, r1csPath string) (*common.TransferProofSystem, error) {
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

	return &common.TransferProofSystem{
		CircuitType:      common.TransferCircuitType,
		NInputs:          nInputs,
		NOutputs:         nOutputs,
		RequiresP256:     false,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}
