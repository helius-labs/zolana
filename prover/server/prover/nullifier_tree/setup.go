package nullifiertree

import (
	"fmt"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// SetupBatchOperationCircuit sets up the batch address-append circuit.
// Returns BatchProofSystem for batch proof generation and verification.
func SetupBatchOperationCircuit(circuit common.CircuitType, height uint32, batchSize uint32) (*common.BatchProofSystem, error) {
	switch circuit {
	case common.BatchAddressAppendCircuitType:
		return SetupBatchAddressAppend(height, batchSize)
	default:
		return nil, fmt.Errorf("invalid batch operation circuit: %s", circuit)
	}
}

func SetupBatchAddressAppend(height uint32, batchSize uint32) (*common.BatchProofSystem, error) {
	fmt.Println("Setting up address append batch update: height", height, "batch size", batchSize)
	ccs, err := R1CSBatchAddressAppend(height, batchSize)
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &common.BatchProofSystem{
		CircuitType:      common.BatchAddressAppendCircuitType,
		TreeHeight:       height,
		BatchSize:        batchSize,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs}, nil
}

func ImportBatchAddressAppendSetup(treeHeight uint32, batchSize uint32, pkPath string, vkPath string) (*common.BatchProofSystem, error) {
	circuit := InitBatchAddressTreeAppendCircuit(treeHeight, batchSize)

	fmt.Println("Compiling circuit")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("Error compiling circuit")
		return nil, err
	} else {
		fmt.Println("Compiled circuit successfully")
	}

	pk, err := common.LoadProvingKey(pkPath)
	if err != nil {
		return nil, err
	}

	vk, err := common.LoadVerifyingKey(vkPath)
	if err != nil {
		return nil, err
	}

	return &common.BatchProofSystem{
		CircuitType:      common.BatchAddressAppendCircuitType,
		TreeHeight:       treeHeight,
		BatchSize:        batchSize,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}

func ImportBatchAddressAppendSetupWithR1CS(treeHeight uint32, batchSize uint32, pkPath string, vkPath string, r1csPath string) (*common.BatchProofSystem, error) {
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

	return &common.BatchProofSystem{
		CircuitType:      common.BatchAddressAppendCircuitType,
		TreeHeight:       treeHeight,
		BatchSize:        batchSize,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}
