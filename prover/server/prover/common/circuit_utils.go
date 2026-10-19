package common

import (
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

type Proof struct {
	Resolution *ProofResolution
	Proof      groth16.Proof
	// ProvingKeySha256 is the sha256 of the proving key file the proof was
	// generated with (zero when the system was not loaded from a file). Clients
	// compare it with the proving-key sha256 pinned next to their verifying key.
	ProvingKeySha256 [32]byte
}

// ProofWithTiming wraps a proof with timing information for metrics
type ProofWithTiming struct {
	Proof           *Proof `json:"proof"`
	ProofDurationMs int64  `json:"proofDurationMs"`
}

type BatchProofSystem struct {
	CircuitType      CircuitType
	TreeHeight       uint32
	BatchSize        uint32
	ProvingKey       groth16.ProvingKey
	VerifyingKey     groth16.VerifyingKey
	ConstraintSystem constraint.ConstraintSystem
	// ProvingKeySha256 is the sha256 of the key file this system was read
	// from, computed while reading it (see ReadSystemFromFile).
	ProvingKeySha256 [32]byte
}

type RingProofSystem struct {
	CircuitType      CircuitType
	ProvingKey       groth16.ProvingKey
	VerifyingKey     groth16.VerifyingKey
	ConstraintSystem constraint.ConstraintSystem
	// ProvingKeySha256 is the sha256 of the key file this system was read
	// from, computed while reading it (see ReadSystemFromFile).
	ProvingKeySha256 [32]byte
}

// TransferProofSystem holds the keys and constraints for one transaction shape.
// HasCommitment preserves a legacy key-header bit, not the verifier configuration.
// Confidential selects the owner-tag-binding variant.
type TransferProofSystem struct {
	CircuitType      CircuitType
	NInputs          uint32
	NOutputs         uint32
	HasCommitment    bool
	Confidential     bool
	ProvingKey       groth16.ProvingKey
	VerifyingKey     groth16.VerifyingKey
	ConstraintSystem constraint.ConstraintSystem
	// ProvingKeySha256 is the sha256 of the key file this system was read
	// from, computed while reading it (see ReadSystemFromFile).
	ProvingKeySha256 [32]byte
}
