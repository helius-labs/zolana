package keyencryption

import (
	"fmt"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark/backend/groth16"
)

// SetupKeyEncryption runs trusted setup for the squads key encryption circuit
// and returns a SquadsKeyEncryptionProofSystem.
func SetupKeyEncryption(numKeys uint32) (*common.SquadsKeyEncryptionProofSystem, error) {
	fmt.Println("Setting up squads key encryption: numKeys", numKeys)
	ccs, err := R1CSKeyEncryption(numKeys)
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &common.SquadsKeyEncryptionProofSystem{
		CircuitType:      common.SquadsKeyEncryptionCircuitType,
		NumKeys:          numKeys,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}
