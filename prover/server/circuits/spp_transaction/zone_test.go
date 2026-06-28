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

// The zone variant binds each non-dummy UTXO's program_id to the public
// ProgramID when set: a transaction whose inputs and outputs all carry the same
// program_id as the public input solves.
func TestZoneCircuitBindsMatchingProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	programID := spptest.Fe(0x1234)

	assignment := buildZoneAssignment(t, shape, programID, programID, programID)
	circuit, err := NewTransferP256ZoneCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone circuit: %v", err)
	}
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// A UTXO whose non-zero program_id differs from the public ProgramID violates
// the if-set binding and the proof fails.
func TestZoneCircuitRejectsMismatchedProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	programID := spptest.Fe(0x1234)
	otherID := spptest.Fe(0x5678)

	// Output 0 carries a different program_id than the public ProgramID.
	assignment := buildZoneAssignment(t, shape, programID, programID, otherID)
	circuit, err := NewTransferP256ZoneCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone circuit: %v", err)
	}
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// program_data_hash may be non-zero only when its governing program_id is set:
// the circuit forces a non-zero program_data_hash to name a non-zero program_id
// (which bindIfSet then pins to the public ProgramID), so only the owning program
// can create a UTXO carrying data under its id. An output with program_data_hash
// != 0 and program_id == 0 must fail.
func TestZoneCircuitRejectsProgramDataHashWithoutProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	inputs, outputs := defaultBalancedUtxos(t, shape)
	outputs[0].DataHash = spptest.Fe(0x99) // program_data_hash set, program_id stays 0
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs, big.NewInt(0), big.NewInt(0), spptest.Fe(0))
	refreshZonePublicInputHash(t, assignment)

	circuit, err := NewTransferP256ZoneCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone circuit: %v", err)
	}
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// With the governing program_id set and bound to the public ProgramID, a non-zero
// program_data_hash on every UTXO is allowed.
func TestZoneCircuitAllowsProgramDataHashWithProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	programID := spptest.Fe(0x1234)

	inputs, outputs := defaultBalancedUtxos(t, shape)
	for i := range inputs {
		inputs[i].ProgramID = new(big.Int).Set(programID)
		inputs[i].DataHash = spptest.Fe(int64(0x70 + i))
	}
	for i := range outputs {
		outputs[i].ProgramID = new(big.Int).Set(programID)
		outputs[i].DataHash = spptest.Fe(int64(0x80 + i))
	}
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs, big.NewInt(0), big.NewInt(0), spptest.Fe(0))
	assignment.ProgramID = programID
	refreshZonePublicInputHash(t, assignment)

	circuit, err := NewTransferP256ZoneCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone circuit: %v", err)
	}
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
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

// buildZoneAssignment builds a balanced assignment whose input UTXOs carry
// inputProgramID and whose output UTXOs carry outputProgramID, and pins the
// public ProgramID to publicProgramID. The public-input hash is recomputed to
// match. ZoneProgramID stays 0 (program-only binding).
func buildZoneAssignment(t testing.TB, shape protocol.Shape, publicProgramID, inputProgramID, outputProgramID *big.Int) *Circuit {
	t.Helper()
	inputs, outputs := defaultBalancedUtxos(t, shape)
	for i := range inputs {
		inputs[i].ProgramID = new(big.Int).Set(inputProgramID)
	}
	for i := range outputs {
		outputs[i].ProgramID = new(big.Int).Set(outputProgramID)
	}
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs, big.NewInt(0), big.NewInt(0), spptest.Fe(0))
	assignment.ProgramID = publicProgramID
	refreshZonePublicInputHash(t, assignment)
	return assignment
}

func refreshZonePublicInputHash(t testing.TB, assignment *Circuit) {
	refreshPublicInputHashVariant(t, assignment, false, false)
}
