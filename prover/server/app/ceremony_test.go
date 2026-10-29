package app

import (
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func TestCoreCeremonyShape(t *testing.T) {
	accepted := []struct {
		circuit common.CircuitType
		inputs  uint32
		outputs uint32
	}{
		{common.TransferConfidentialCircuitType, 2, 2},
		{common.TransferAnonymousRingEddsaCircuitType, 49, 2},
		{common.MergeCircuitType, 52, 1},
		{common.MergeCircuitType, 8, 0},
	}
	for _, shape := range accepted {
		if err := validateCoreCeremonyShape(shape.circuit, shape.inputs, shape.outputs); err != nil {
			t.Fatalf("%s %dx%d: %v", shape.circuit, shape.inputs, shape.outputs, err)
		}
	}

	rejected := []common.CircuitType{
		common.TransferRingCircuitType,
		common.TransferRingAuthorityCircuitType,
		common.MergeRingCircuitType,
		common.BatchAddressAppendCircuitType,
	}
	for _, circuit := range rejected {
		if err := validateCoreCeremonyShape(circuit, 2, 2); err == nil {
			t.Fatalf("%s was accepted", circuit)
		}
	}
	if err := validateCoreCeremonyShape(common.TransferConfidentialCircuitType, 2, 3); err == nil {
		t.Fatal("transfer-confidential 2x3 was accepted")
	}
}
