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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func MustNewCustomZoneP256Circuit(shape Shape) *customzone.CustomZoneP256Circuit {
	circuit, err := customzone.NewCustomZoneP256Circuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

func TestCustomZoneP256CompilesForSupportedShapes(t *testing.T) {
	for _, shape := range protocol.SupportedShapes {
		shape := shape
		t.Run(shape.String(), func(t *testing.T) {
			circuit := MustNewCustomZoneP256Circuit(Shape(shape))
			if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300)); err != nil {
				t.Fatalf("compile SPP circuit %s: %v", shape, err)
			}
		})
	}
}

func TestCustomZoneP256ProvesForSupportedShapes(t *testing.T) {
	for _, shape := range protocol.SupportedShapes {
		shape := shape
		t.Run(shape.String(), func(t *testing.T) {
			assert := test.NewAssert(t)
			circuit := MustNewCustomZoneP256Circuit(Shape(shape))
			assignment := buildCircuitAssignment(t, shape)

			assert.SolvingSucceeded(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
			assert.ProverSucceeded(
				circuit,
				asCustomZoneP256(assignment),
				test.WithBackends(backend.GROTH16),
				test.WithCurves(ecc.BN254),
				test.NoSerializationChecks(),
			)
		})
	}
}

func TestCustomZoneP256AcceptsDataHashOnOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	inputs, outputs := defaultBalancedUtxos(t, shape)
	outputs[0].DataHash = spptest.Fe(0x99)
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)
	refreshCustomZonePublicInputHash(t, assignment)

	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	assert.SolvingSucceeded(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

// A data-carrying output must be owned by a signer (an input owner); data on
// an output owned by anyone else must not solve.
func TestCustomZoneP256RejectsDataHashOnUnsignedOwnerOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	inputs, outputs := defaultBalancedUtxos(t, shape)
	outputs[0].DataHash = spptest.Fe(0x99)
	outputs[0].Owner = testOwnerHashForNullifierSecret(spptest.Fe(123))
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)
	refreshCustomZonePublicInputHash(t, assignment)

	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	assert.SolvingFailed(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

func TestCustomZoneP256RejectsZoneDataHashWithoutZoneProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	inputs, outputs := defaultBalancedUtxos(t, shape)
	outputs[0].ZoneDataHash = spptest.Fe(0x99)
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)
	refreshCustomZonePublicInputHash(t, assignment)

	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	assert.SolvingFailed(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

func TestCustomZoneP256BindsMatchingZoneProgramID(t *testing.T) {
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
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)
	assignment.ZoneProgramID = zoneProgramID
	refreshCustomZonePublicInputHash(t, assignment)

	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	assert.SolvingSucceeded(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

func TestCustomZoneP256RejectsMismatchedZoneProgramID(t *testing.T) {
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
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)
	assignment.ZoneProgramID = zoneProgramID
	refreshCustomZonePublicInputHash(t, assignment)

	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	assert.SolvingFailed(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

func refreshCustomZonePublicInputHash(t testing.TB, assignment *Circuit) {
	refreshPublicInputHashVariant(t, assignment, false, false)
}
