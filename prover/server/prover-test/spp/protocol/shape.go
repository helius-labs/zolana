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

// SupportedShapes lists every fixed-size circuit that has a key, smallest
// capacity first. This is the validation set, mirroring SPP_SUPPORTED_SHAPES in
// program-libs/interface/src/shape.rs. It is the single source of truth for the
// shape set; do not duplicate it.
//
// It is deliberately NOT the smallest-fit search order: see AutoShapes.
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
	// Consolidation shape; sized against the custom-ring path, not a bare
	// transact. See Shape::IN36_OUT2 in program-libs/interface/src/shape.rs.
	{NInputs: 36, NOutputs: 2},
}

// AutoShapes is the smallest-fit search order, mirroring SPP_AUTO_SHAPES in
// program-libs/interface/src/shape.rs. It excludes the large consolidation
// shape: including it would silently route a six-input transfer to a 36-input
// circuit, roughly twenty times the constraints for no benefit. A caller that
// wants that shape names it.
var AutoShapes = SupportedShapes[:10]

// SmallestSupportedShape returns the smallest shape with a key that holds the
// given real input/output counts, searching the full validation set.
//
// Distinct from CanonicalShape: this answers "which shape should a transaction
// with these real counts be padded up to", which must consider every shape a
// key exists for. CanonicalShape answers "which shape should a client pick when
// it declared none", which must not reach the large shapes.
func SmallestSupportedShape(nInputs, nOutputs int) (Shape, error) {
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

// CanonicalShape returns the smallest automatic shape that holds the given
// real input/output counts. SPP derives the verifying key and public-input
// padding from the real counts with the same smallest-fit rule, so a proof
// built with any other shape can never verify on-chain.
func CanonicalShape(nInputs, nOutputs int) (Shape, error) {
	if nInputs < 0 || nOutputs < 0 {
		return Shape{}, fmt.Errorf("spp: negative arity %d inputs / %d outputs", nInputs, nOutputs)
	}
	for _, shape := range AutoShapes {
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
