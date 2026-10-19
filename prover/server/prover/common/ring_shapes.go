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

var RingPolicyShapes = func() []RingPolicyShape {
	var out []RingPolicyShape
	for rail, shapes := range [][]protocol.Shape{protocol.SupportedShapes, protocol.AnonymousRingEd25519Shapes, {{NInputs: 2, NOutputs: 2}, {NInputs: 4, NOutputs: 4}}} {
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
