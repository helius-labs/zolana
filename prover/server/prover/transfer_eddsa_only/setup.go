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
	case common.TransferConfidentialCircuitType:
		return SetupTransfer(nInputs, nOutputs, ConfidentialVariant)
	case common.TransferZoneCircuitType:
		return SetupTransfer(nInputs, nOutputs, ZoneVariant)
	case common.TransferZoneAuthorityCircuitType:
		return SetupTransfer(nInputs, nOutputs, ZoneAuthorityVariant)
	default:
		return nil, fmt.Errorf("invalid transfer circuit: %s", circuit)
	}
}

func SetupTransfer(nInputs uint32, nOutputs uint32, variant Variant) (*common.TransferProofSystem, error) {
	circuitType := variant.CircuitType()
	fmt.Println("Setting up", circuitType, "(eddsa/solana-only): nInputs", nInputs, "nOutputs", nOutputs)
	ccs, err := R1CSTransfer(nInputs, nOutputs, variant)
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
		Confidential:     variant == ConfidentialVariant,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}

func ImportTransferSetup(nInputs uint32, nOutputs uint32, pkPath string, vkPath string) (*common.TransferProofSystem, error) {
	fmt.Println("Compiling circuit")
	ccs, err := R1CSTransfer(nInputs, nOutputs, ConfidentialVariant)
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
		CircuitType:      common.TransferConfidentialCircuitType,
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
		CircuitType:      common.TransferConfidentialCircuitType,
		NInputs:          nInputs,
		NOutputs:         nOutputs,
		RequiresP256:     false,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}
