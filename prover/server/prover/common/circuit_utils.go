package common

import (
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

type Proof struct {
	Proof groth16.Proof
}

// ProofWithTiming wraps a proof with timing information for metrics
type ProofWithTiming struct {
	Proof           *Proof `json:"proof"`
	ProofDurationMs int64  `json:"proof_duration_ms"`
}

type MerkleProofSystem struct {
	InclusionTreeHeight                    uint32
	InclusionNumberOfCompressedAccounts    uint32
	NonInclusionTreeHeight                 uint32
	NonInclusionNumberOfCompressedAccounts uint32
	Version                                uint32
	ProvingKey                             groth16.ProvingKey
	VerifyingKey                           groth16.VerifyingKey
	ConstraintSystem                       constraint.ConstraintSystem
}

type BatchProofSystem struct {
	CircuitType      CircuitType
	TreeHeight       uint32
	BatchSize        uint32
	ProvingKey       groth16.ProvingKey
	VerifyingKey     groth16.VerifyingKey
	ConstraintSystem constraint.ConstraintSystem
}

// TransferProofSystem holds the keys and constraints for one spp_transaction
// circuit shape, ownership rail, and confidentiality mode. RequiresP256 selects
// the P256-capable circuit (true) or the Solana-only variant (false);
// Confidential selects the owner-tag-binding variant. It mirrors BatchProofSystem
// but is keyed by (NInputs, NOutputs, RequiresP256, Confidential) instead of
// (TreeHeight, BatchSize).
type TransferProofSystem struct {
	CircuitType      CircuitType
	NInputs          uint32
	NOutputs         uint32
	RequiresP256     bool
	Confidential     bool
	ProvingKey       groth16.ProvingKey
	VerifyingKey     groth16.VerifyingKey
	ConstraintSystem constraint.ConstraintSystem
}
