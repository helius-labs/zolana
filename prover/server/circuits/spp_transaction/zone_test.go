package transaction_test

import (
	"math/big"
	"testing"

	. "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func TestZoneCircuitAcceptsDataHashOnOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	inputs, outputs := defaultBalancedUtxos(t, shape)
	outputs[0].DataHash = spptest.Fe(0x99)
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs, big.NewInt(0), big.NewInt(0), spptest.Fe(0))
	refreshZonePublicInputHash(t, assignment)

	circuit, err := NewTransferP256ZoneCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone circuit: %v", err)
	}
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestZoneCircuitRejectsZoneDataHashWithoutZoneProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	inputs, outputs := defaultBalancedUtxos(t, shape)
	outputs[0].ZoneDataHash = spptest.Fe(0x99)
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs, big.NewInt(0), big.NewInt(0), spptest.Fe(0))
	refreshZonePublicInputHash(t, assignment)

	circuit, err := NewTransferP256ZoneCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone circuit: %v", err)
	}
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestZoneCircuitBindsMatchingZoneProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	zoneProgramID := spptest.Fe(0x42)

	inputs, outputs := defaultBalancedUtxos(t, shape)
	for i := range inputs {
		inputs[i].ZoneProgramID = new(big.Int).Set(zoneProgramID)
	}
	for i := range outputs {
		outputs[i].ZoneProgramID = new(big.Int).Set(zoneProgramID)
	}
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs, big.NewInt(0), big.NewInt(0), spptest.Fe(0))
	assignment.ZoneProgramID = zoneProgramID
	refreshZonePublicInputHash(t, assignment)

	circuit, err := NewTransferP256ZoneCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone circuit: %v", err)
	}
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestZoneCircuitRejectsMismatchedZoneProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	zoneProgramID := spptest.Fe(0x42)
	otherZone := spptest.Fe(0x43)

	inputs, outputs := defaultBalancedUtxos(t, shape)
	for i := range inputs {
		inputs[i].ZoneProgramID = new(big.Int).Set(zoneProgramID)
	}
	for i := range outputs {
		outputs[i].ZoneProgramID = new(big.Int).Set(zoneProgramID)
	}
	outputs[0].ZoneProgramID = new(big.Int).Set(otherZone)
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs, big.NewInt(0), big.NewInt(0), spptest.Fe(0))
	assignment.ZoneProgramID = zoneProgramID
	refreshZonePublicInputHash(t, assignment)

	circuit, err := NewTransferP256ZoneCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone circuit: %v", err)
	}
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func refreshZonePublicInputHash(t testing.TB, assignment *Circuit) {
	refreshPublicInputHashVariant(t, assignment, false, false)
}
