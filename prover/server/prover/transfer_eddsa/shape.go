package transfereddsa

import (
	"fmt"

	customring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/custom"
	txcircuit "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// CircuitShape resolves a proof shape to the circuit it names: a zero
// dimension is the protocol one.
func CircuitShape(shape common.ProofShape) txcircuit.Shape {
	s := txcircuit.NewShape(int(shape.Inputs), int(shape.Outputs))
	if shape.SignerWidth != 0 {
		s.SignerWidth = int(shape.SignerWidth)
	}
	if shape.HiddenOwners != 0 {
		s.NHiddenOwners = int(shape.HiddenOwners)
	}
	return s
}

// ProofShapeOf names the key of a circuit: a dimension equal to the protocol
// value stays zero, so a protocol circuit always names the committed key.
func ProofShapeOf(circuit common.CircuitType, s txcircuit.Shape) common.ProofShape {
	shape := common.ProofShape{Circuit: circuit, Inputs: uint32(s.NInputs), Outputs: uint32(s.NOutputs)}
	if s.SignerWidth != txcircuit.ProtocolSignerWidth(s.NInputs) {
		shape.SignerWidth = uint32(s.SignerWidth)
	}
	if s.NHiddenOwners != 1 {
		shape.HiddenOwners = uint32(s.NHiddenOwners)
	}
	return shape
}

// normalizedProofShape drops request dimensions that equal the protocol ones.
// The ring authority rail sizes no owner signer vector, so it keeps any
// dimension a request names and Supported refuses it.
func normalizedProofShape(raw common.ProofShape) common.ProofShape {
	if raw.Circuit == common.TransferRingAuthorityCircuitType {
		return raw
	}
	return ProofShapeOf(raw.Circuit, CircuitShape(raw))
}

// newShapeCircuit builds the circuit a supported transfer proof shape names.
func newShapeCircuit(shape common.ProofShape) (frontend.Circuit, error) {
	if !shape.Supported() {
		return nil, fmt.Errorf("unsupported transfer shape %s", shape)
	}
	circuit := CircuitShape(shape)
	switch shape.Circuit {
	case common.TransferAnonymousRingEddsaCircuitType:
		return customring.NewCustomRingAnonymousEddsaCircuit(circuit)
	case common.TransferConfidentialCircuitType, common.TransferRingCircuitType, common.TransferRingAuthorityCircuitType:
		return newVariantCircuit(variantFromCircuitType(shape.Circuit), circuit)
	default:
		return nil, fmt.Errorf("invalid transfer circuit: %s", shape.Circuit)
	}
}

// R1CSShape compiles the transfer circuit a proof shape names.
// WithCompressThreshold(300) matches the constraint system the committed
// verifying keys were produced with; do not drop it.
func R1CSShape(shape common.ProofShape) (constraint.ConstraintSystem, error) {
	circuit, err := newShapeCircuit(shape)
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

// SetupShape runs trusted setup for the transfer circuit a proof shape names.
func SetupShape(shape common.ProofShape) (*common.TransferProofSystem, error) {
	ccs, err := R1CSShape(shape)
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	// HasCommitment is a historical key-header bit, set only on the anonymous
	// EdDSA rail's keys.
	anonymous := shape.Circuit == common.TransferAnonymousRingEddsaCircuitType
	return &common.TransferProofSystem{
		CircuitType:      shape.Circuit,
		NInputs:          shape.Inputs,
		NOutputs:         shape.Outputs,
		SignerWidth:      shape.SignerWidth,
		HiddenOwners:     shape.HiddenOwners,
		HasCommitment:    anonymous,
		Confidential:     shape.Circuit != common.TransferRingAuthorityCircuitType,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}

// checkSystem rejects a system for another circuit or shape. Every transfer
// circuit exposes only PublicInputHash, so Groth16 cannot tell them apart.
func checkSystem(system *common.TransferProofSystem, shape common.ProofShape) error {
	if system == nil {
		return fmt.Errorf("no proving system for %s", shape)
	}
	if system.Shape() != shape {
		return fmt.Errorf("%s system for a %s request", system.Shape(), shape)
	}
	return nil
}
