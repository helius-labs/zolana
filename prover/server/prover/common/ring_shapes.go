package common

import (
	"fmt"
	"slices"

	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
)

// RingPolicyShape is key metadata. Capacities match the corresponding SPP rail.
type RingPolicyShape struct {
	protocol.Shape
	Anonymous bool
	Delegate  bool
	Subtree   bool
}

func (s RingPolicyShape) CircuitType() CircuitType {
	prefix := "custom-ring-policy"
	if s.Delegate {
		prefix = "custom-ring-delegate-policy"
	}
	name := fmt.Sprintf("%s-%d-%d", prefix, s.NInputs, s.NOutputs)
	if s.Anonymous {
		name += "-anonymous"
	}
	if s.Subtree {
		name += "-subtree"
	}
	return CircuitType(name)
}

// AnonymousRingShapes mirrors ANONYMOUS_RING_SHAPES in custom-rings/interface/src/disclosure.rs.
var AnonymousRingShapes = []protocol.Shape{
	{NInputs: 1, NOutputs: 2},
	{NInputs: 1, NOutputs: 4},
	{NInputs: 2, NOutputs: 2},
	{NInputs: 2, NOutputs: 4},
	{NInputs: 3, NOutputs: 2},
	{NInputs: 3, NOutputs: 4},
	{NInputs: 4, NOutputs: 2},
	{NInputs: 4, NOutputs: 4},
	{NInputs: 5, NOutputs: 2},
	{NInputs: 5, NOutputs: 4},
	{NInputs: 6, NOutputs: 2},
	{NInputs: 6, NOutputs: 4},
	{NInputs: 8, NOutputs: 2},
	{NInputs: 12, NOutputs: 2},
}

var RingPolicyShapes = func() []RingPolicyShape {
	var out []RingPolicyShape
	for rail, shapes := range [][]protocol.Shape{protocol.SupportedShapes, AnonymousRingShapes, {{NInputs: 2, NOutputs: 2}, {NInputs: 4, NOutputs: 4}}} {
		for _, shape := range shapes {
			// Larger shapes exceed the current inline-audit transaction envelope.
			if shape.NOutputs > 4 || shape.NInputs > 16 && !(rail == 0 && shape.NInputs == 24 && shape.NOutputs == 2) {
				continue
			}
			for _, subtree := range []bool{false, true} {
				out = append(out, RingPolicyShape{Shape: shape, Anonymous: rail == 1, Delegate: rail == 2, Subtree: subtree})
			}
		}
	}
	return out
}()

func ParseRingPolicyShape(kind CircuitType) (RingPolicyShape, bool) {
	index := slices.IndexFunc(RingPolicyShapes, func(s RingPolicyShape) bool { return s.CircuitType() == kind })
	if index < 0 {
		return RingPolicyShape{}, false
	}
	return RingPolicyShapes[index], true
}

func init() {
	for _, shape := range RingPolicyShapes {
		RingCircuitTypes = append(RingCircuitTypes, shape.CircuitType())
	}
}
