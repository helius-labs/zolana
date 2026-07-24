package shared_test

import (
	"math/big"
	"testing"

	customzone "zolana/prover/circuits/spp_transaction/custom"
	. "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func MustNewCustomZoneAuthorityCircuit(shape Shape) *customzone.CustomZoneAuthorityCircuit {
	circuit, err := customzone.NewCustomZoneAuthorityCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

func zoneAuthorityZone() *big.Int { return spptest.Fe(0x5a) }

func TestCustomZoneAuthoritySolvesForSupportedShapes(t *testing.T) {
	for _, shape := range protocol.SupportedShapes {
		shape := shape
		t.Run(shape.String(), func(t *testing.T) {
			assert := test.NewAssert(t)
			circuit := MustNewCustomZoneAuthorityCircuit(Shape(shape))
			assignment := buildZoneAuthorityAssignment(t, shape)
			assert.SolvingSucceeded(circuit, asCustomZoneAuthority(assignment), test.WithCurves(ecc.BN254))
		})
	}
}

func TestCustomZoneAuthorityProves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 3, NOutputs: 3}
	circuit := MustNewCustomZoneAuthorityCircuit(Shape(shape))
	assignment := buildZoneAuthorityAssignment(t, shape)
	assert.ProverSucceeded(
		circuit,
		asCustomZoneAuthority(assignment),
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.NoSerializationChecks(),
	)
}

func TestCustomZoneAuthorityRejectsWrongNullifierSecret(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneAuthorityCircuit(Shape(shape))
	assignment := buildZoneAuthorityAssignment(t, shape)
	assignment.Inputs[0].NullifierSecret = spptest.Fe(12345)
	refreshZoneAuthorityPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomZoneAuthority(assignment), test.WithCurves(ecc.BN254))
}

func TestCustomZoneAuthorityRejectsDefaultZoneInput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneAuthorityCircuit(Shape(shape))
	assignment := buildZoneAuthorityAssignmentWithZone(t, shape, zoneAuthorityZone(), big.NewInt(0))

	assert.SolvingFailed(circuit, asCustomZoneAuthority(assignment), test.WithCurves(ecc.BN254))
}

func TestCustomZoneAuthorityRejectsZeroZoneProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneAuthorityCircuit(Shape(shape))
	assignment := buildZoneAuthorityAssignmentWithZone(t, shape, big.NewInt(0), big.NewInt(0))

	assert.SolvingFailed(circuit, asCustomZoneAuthority(assignment), test.WithCurves(ecc.BN254))
}

func TestCustomZoneAuthorityRejectsDefaultZoneOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneAuthorityCircuit(Shape(shape))
	zone := zoneAuthorityZone()
	assignment := buildZoneAuthorityAssignmentZones(t, shape, zone, zone, big.NewInt(0))

	assert.SolvingFailed(circuit, asCustomZoneAuthority(assignment), test.WithCurves(ecc.BN254))
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
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)
	assignment.ZoneProgramID = new(big.Int).Set(publicZone)
	assignment.P256MessageHashLow = spptest.Fe(0)
	assignment.P256MessageHashHigh = spptest.Fe(0)
	refreshZoneAuthorityPublicInputHash(t, assignment)
	return assignment
}

func refreshZoneAuthorityPublicInputHash(t testing.TB, assignment *Circuit) {
	refreshPublicInputHashVariant(t, assignment, false, true)
}
