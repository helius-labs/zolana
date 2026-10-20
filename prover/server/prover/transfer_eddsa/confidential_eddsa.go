package transfereddsa

import (
	defaultring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/default"
	txcircuit "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// confidentialEddsaSigners is the number of in-circuit verified owners every
// transfer_confidential_eddsa key proves; CircuitId::ConfidentialEddsa carries one.
const confidentialEddsaSigners = 1

func R1CSConfidentialEddsaTransfer(nInputs uint32, nOutputs uint32) (constraint.ConstraintSystem, error) {
	circuit, err := defaultring.NewDefaultRingConfidentialInCircuitEddsaCircuit(
		txcircuit.Shape{NInputs: int(nInputs), NOutputs: int(nOutputs)},
		confidentialEddsaSigners,
	)
	if err != nil {
		return nil, err
	}
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		circuit,
		frontend.WithCompressThreshold(300),
	)
}

// SetupConfidentialEddsaTransfer runs trusted setup for the default-ring
// confidential transfer authorized by an in-circuit Ed25519 signature.
func SetupConfidentialEddsaTransfer(nInputs uint32, nOutputs uint32) (*common.TransferProofSystem, error) {
	ccs, err := R1CSConfidentialEddsaTransfer(nInputs, nOutputs)
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &common.TransferProofSystem{
		CircuitType:      common.TransferConfidentialEddsaCircuitType,
		NInputs:          nInputs,
		NOutputs:         nOutputs,
		HasCommitment:    true,
		Confidential:     true,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}
