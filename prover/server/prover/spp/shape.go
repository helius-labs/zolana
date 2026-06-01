package spp

import "fmt"

const (
	StateTreeHeight     = 26
	NullifierTreeHeight = 40
	CompressedProofSize = 192

	// UtxoDomain is the protocol-fixed `domain` separator that every non-dummy
	// UTXO carries in its Poseidon hash preimage (spec "UTXO Hash"). Enforcing
	// it in-circuit prevents a UTXO hash from being reinterpreted as another
	// Poseidon record type.
	//
	// NOTE: the concrete value is not yet pinned by the spec or the on-chain
	// program. This constant MUST be ratified to match the value senders write
	// and that the on-chain program / indexer expect before mainnet; changing
	// it changes the constraint system and invalidates existing proving keys.
	UtxoDomain = 1
)

// Shape identifies one fixed-size SPP circuit. Each supported shape gets one
// constraint system, one proving key, and one verifying key.
type Shape struct {
	NInputs  int
	NOutputs int
}

var SupportedShapes = []Shape{
	{NInputs: 1, NOutputs: 2},
	{NInputs: 1, NOutputs: 8},
	{NInputs: 2, NOutputs: 2},
	{NInputs: 3, NOutputs: 3},
	{NInputs: 5, NOutputs: 3},
}

func NewShape(nInputs, nOutputs int) (Shape, error) {
	shape := Shape{NInputs: nInputs, NOutputs: nOutputs}
	if err := shape.Validate(); err != nil {
		return Shape{}, err
	}
	return shape, nil
}

func (s Shape) Validate() error {
	if s.NInputs < 1 {
		return fmt.Errorf("spp: NInputs must be >= 1, got %d", s.NInputs)
	}
	if s.NOutputs < 1 {
		return fmt.Errorf("spp: NOutputs must be >= 1, got %d", s.NOutputs)
	}
	if !s.IsSupported() {
		return fmt.Errorf("spp: unsupported circuit shape %s", s)
	}
	return nil
}

func (s Shape) IsSupported() bool {
	for _, supported := range SupportedShapes {
		if s == supported {
			return true
		}
	}
	return false
}

func (s Shape) String() string {
	return fmt.Sprintf("%d-%d", s.NInputs, s.NOutputs)
}
