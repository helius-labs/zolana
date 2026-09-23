package common

import (
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

type Proof struct {
	Proof groth16.Proof
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
	// ProvingKeySha256 is the sha256 of the key file this system was read
	// from, computed while reading it (see ReadSystemFromFile).
	ProvingKeySha256 [32]byte
}
