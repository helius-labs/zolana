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

// The standalone program_id field is vestigial: program identity lives in the
// owner, so every real UTXO must pin program_id to 0. A non-zero program_id field
// is rejected. (Program data on a program-owned UTXO is covered in
// program_owned_test.go.)
func TestZoneCircuitRejectsNonZeroProgramIDField(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	inputs, outputs := defaultBalancedUtxos(t, shape)
	outputs[0].ProgramID = spptest.Fe(0x1234)
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs, big.NewInt(0), big.NewInt(0), spptest.Fe(0))
	refreshZonePublicInputHash(t, assignment)

	circuit, err := NewTransferP256ZoneCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone circuit: %v", err)
	}
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// A user-owned output cannot carry program data: program data lives only on
// program-owned UTXOs (owner == program_id). A user output with program_data_hash
// set must fail.
func TestZoneCircuitRejectsProgramDataOnUserOutput(t *testing.T) {
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
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// zone_data_hash binds to its zone_program_id the same way: a non-zero
// zone_data_hash with zone_program_id == 0 must fail in the zone variant.
func TestZoneCircuitRejectsZoneDataHashWithoutZoneProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	inputs, outputs := defaultBalancedUtxos(t, shape)
	outputs[0].ZoneDataHash = spptest.Fe(0x99) // zone_data_hash set, zone_program_id stays 0
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs, big.NewInt(0), big.NewInt(0), spptest.Fe(0))
	refreshZonePublicInputHash(t, assignment)

	circuit, err := NewTransferP256ZoneCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone circuit: %v", err)
	}
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// The zone variant binds each non-dummy UTXO's zone_program_id to the public
// ZoneProgramID when set: a transaction whose inputs and outputs all carry the
// same non-zero zone_program_id as the public input solves.
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

// A UTXO whose non-zero zone_program_id differs from the public ZoneProgramID
// violates the if-set binding and the proof fails. Inputs stay in the zone so the
// failure isolates to the output.
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
	outputs[0].ZoneProgramID = new(big.Int).Set(otherZone) // diverges from public ZoneProgramID
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
