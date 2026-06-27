package protocol

import "fmt"

const (
	StateTreeHeight     = 32
	NullifierTreeHeight = 40
	CompressedProofSize = 192
)

// Shape identifies one fixed-size SPP transaction circuit.
type Shape struct {
	NInputs  int
	NOutputs int
}

// SupportedShapes lists every fixed-size circuit, smallest-capacity first so
// the order doubles as the smallest-fit search order for CanonicalShape and
// mirrors SHAPES in the on-chain verifier (transact/proof.rs canonical_shape).
// This is the single source of truth for the shape set; do not duplicate it.
var SupportedShapes = []Shape{
	{NInputs: 1, NOutputs: 1},
	{NInputs: 1, NOutputs: 2},
	{NInputs: 2, NOutputs: 2},
	{NInputs: 2, NOutputs: 3},
	{NInputs: 3, NOutputs: 3},
	{NInputs: 4, NOutputs: 3},
	{NInputs: 4, NOutputs: 4},
	{NInputs: 5, NOutputs: 3},
	{NInputs: 5, NOutputs: 4},
	{NInputs: 1, NOutputs: 8},
}

// CanonicalShape returns the smallest supported shape that holds the given
// real input/output counts. SPP derives the verifying key and public-input
// padding from the real counts with the same smallest-fit rule, so a proof
// built with any other shape can never verify on-chain.
func CanonicalShape(nInputs, nOutputs int) (Shape, error) {
	if nInputs < 0 || nOutputs < 0 {
		return Shape{}, fmt.Errorf("spp: negative arity %d inputs / %d outputs", nInputs, nOutputs)
	}
	for _, shape := range SupportedShapes {
		if nInputs <= shape.NInputs && nOutputs <= shape.NOutputs {
			return shape, nil
		}
	}
	return Shape{}, fmt.Errorf("spp: no supported shape holds %d inputs and %d outputs", nInputs, nOutputs)
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
