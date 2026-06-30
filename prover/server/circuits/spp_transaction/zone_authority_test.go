package transaction_test

import (
	"math/big"
	"testing"

	. "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func zoneAuthorityZone() *big.Int { return spptest.Fe(0x5a) }

func TestZoneAuthorityCircuitSolvesForSupportedShapes(t *testing.T) {
	for _, shape := range protocol.SupportedShapes {
		shape := shape
		t.Run(shape.String(), func(t *testing.T) {
			assert := test.NewAssert(t)
			circuit, err := NewTransferZoneAuthorityCircuit(Shape(shape))
			if err != nil {
				t.Fatalf("new zone-authority circuit: %v", err)
			}
			assignment := buildZoneAuthorityAssignment(t, shape)
			assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
		})
	}
}

func TestZoneAuthorityCircuitProves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 3, NOutputs: 3}
	circuit, err := NewTransferZoneAuthorityCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone-authority circuit: %v", err)
	}
	assignment := buildZoneAuthorityAssignment(t, shape)
	assert.ProverSucceeded(
		circuit,
		assignment,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.NoSerializationChecks(),
	)
}

func TestZoneAuthorityCircuitRejectsWrongNullifierSecret(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit, err := NewTransferZoneAuthorityCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone-authority circuit: %v", err)
	}
	assignment := buildZoneAuthorityAssignment(t, shape)
	assignment.Inputs[0].NullifierSecret = spptest.Fe(12345)
	refreshZoneAuthorityPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestZoneAuthorityCircuitRejectsDefaultZoneInput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit, err := NewTransferZoneAuthorityCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone-authority circuit: %v", err)
	}
	assignment := buildZoneAuthorityAssignmentWithZone(t, shape, zoneAuthorityZone(), big.NewInt(0))

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestZoneAuthorityCircuitRejectsZeroZoneProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit, err := NewTransferZoneAuthorityCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone-authority circuit: %v", err)
	}
	assignment := buildZoneAuthorityAssignmentWithZone(t, shape, big.NewInt(0), big.NewInt(0))

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestZoneAuthorityCircuitRejectsDefaultZoneOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit, err := NewTransferZoneAuthorityCircuit(Shape(shape))
	if err != nil {
		t.Fatalf("new zone-authority circuit: %v", err)
	}
	zone := zoneAuthorityZone()
	assignment := buildZoneAuthorityAssignmentZones(t, shape, zone, zone, big.NewInt(0))

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func buildZoneAuthorityAssignment(t testing.TB, shape protocol.Shape) *Circuit {
	t.Helper()
	zone := zoneAuthorityZone()
	return buildZoneAuthorityAssignmentWithZone(t, shape, zone, zone)
}

func buildZoneAuthorityAssignmentWithZone(t testing.TB, shape protocol.Shape, publicZone, utxoZone *big.Int) *Circuit {
	t.Helper()
	return buildZoneAuthorityAssignmentZones(t, shape, publicZone, utxoZone, utxoZone)
}

func buildZoneAuthorityAssignmentZones(t testing.TB, shape protocol.Shape, publicZone, inputZone, outputZone *big.Int) *Circuit {
	t.Helper()
	inputs, outputs := defaultBalancedUtxos(t, shape)
	for i := range inputs {
		inputs[i].ZoneProgramID = new(big.Int).Set(inputZone)
	}
	for i := range outputs {
		outputs[i].ZoneProgramID = new(big.Int).Set(outputZone)
	}
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs, big.NewInt(0), big.NewInt(0), spptest.Fe(0))
	assignment.ZoneProgramID = new(big.Int).Set(publicZone)
	assignment.P256MessageHashLow = spptest.Fe(0)
	assignment.P256MessageHashHigh = spptest.Fe(0)
	refreshZoneAuthorityPublicInputHash(t, assignment)
	return assignment
}

func refreshZoneAuthorityPublicInputHash(t testing.TB, assignment *Circuit) {
	refreshPublicInputHashVariant(t, assignment, false, true)
}
