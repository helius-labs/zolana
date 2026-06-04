package model

import "fmt"

const (
	StateTreeHeight     = 26
	NullifierTreeHeight = 40
	CompressedProofSize = 192
)

// Shape identifies one fixed-size SPP transaction circuit.
type Shape struct {
	NInputs  int
	NOutputs int
}

var SupportedShapes = []Shape{
	{NInputs: 0, NOutputs: 1},
	{NInputs: 0, NOutputs: 2},
	{NInputs: 1, NOutputs: 0},
	{NInputs: 1, NOutputs: 1},
	{NInputs: 2, NOutputs: 2},
	{NInputs: 1, NOutputs: 2},
	{NInputs: 3, NOutputs: 3},
	{NInputs: 5, NOutputs: 3},
	{NInputs: 1, NOutputs: 8},
}

func NewShape(nInputs, nOutputs int) (Shape, error) {
	shape := Shape{NInputs: nInputs, NOutputs: nOutputs}
	if err := shape.Validate(); err != nil {
		return Shape{}, err
	}
	return shape, nil
}

func (s Shape) Validate() error {
	if s.NInputs < 0 {
		return fmt.Errorf("spp: NInputs must be >= 0, got %d", s.NInputs)
	}
	if s.NOutputs < 0 {
		return fmt.Errorf("spp: NOutputs must be >= 0, got %d", s.NOutputs)
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
