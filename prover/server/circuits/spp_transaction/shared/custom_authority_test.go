package shared_test

import (
	"fmt"
	"math/big"
	"testing"

	customring "zolana/prover/circuits/spp_transaction/custom"
	. "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func MustNewCustomRingAuthorityCircuit(shape Shape) *customring.CustomRingAuthorityCircuit {
	circuit, err := customring.NewCustomRingAuthorityCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

func ringAuthorityRing() *big.Int { return spptest.Fe(0x5a) }

func TestCustomRingAuthoritySolvesForSupportedShapes(t *testing.T) {
	for _, shape := range protocol.SupportedShapes {
		shape := shape
		t.Run(shape.String(), func(t *testing.T) {
			assert := test.NewAssert(t)
			circuit := MustNewCustomRingAuthorityCircuit(Shape(shape))
			assignment := buildRingAuthorityAssignment(t, shape)
			assert.SolvingSucceeded(circuit, asCustomRingAuthority(assignment), test.WithCurves(ecc.BN254))
		})
	}
}

func TestCustomRingAuthorityProves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 3, NOutputs: 3}
	circuit := MustNewCustomRingAuthorityCircuit(Shape(shape))
	assignment := buildRingAuthorityAssignment(t, shape)
	assert.ProverSucceeded(
		circuit,
		asCustomRingAuthority(assignment),
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.NoSerializationChecks(),
	)
}

func TestCustomRingAuthorityPublicInputHashBindsEveryField(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingAuthorityCircuit(Shape(shape))
	assignment := buildRingAuthorityAssignment(t, shape)
	refreshHash := func() { refreshRingAuthorityPublicInputHash(t, assignment) }

	assertPublicInputHashBindsEveryField(
		t,
		circuit,
		assignment,
		func() frontend.Circuit { return asCustomRingAuthority(assignment) },
		refreshHash,
		publicInputHashBindingOptions{
			includeRingProgramID: true,
			signerWidth:          1,
		},
	)
}

func TestCustomRingAuthorityRejectsWrongNullifierSecret(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingAuthorityCircuit(Shape(shape))
	assignment := buildRingAuthorityAssignment(t, shape)
	assignment.Inputs[0].NullifierSecret = spptest.Fe(12345)
	refreshRingAuthorityPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomRingAuthority(assignment), test.WithCurves(ecc.BN254))
}

func TestCustomRingAuthorityRejectsDefaultRingInput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingAuthorityCircuit(Shape(shape))
	assignment := buildRingAuthorityAssignmentWithRing(t, shape, ringAuthorityRing(), big.NewInt(0))

	assert.SolvingFailed(circuit, asCustomRingAuthority(assignment), test.WithCurves(ecc.BN254))
}

func TestCustomRingAuthorityRejectsZeroRingProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingAuthorityCircuit(Shape(shape))
	assignment := buildRingAuthorityAssignmentWithRing(t, shape, big.NewInt(0), big.NewInt(0))

	assert.SolvingFailed(circuit, asCustomRingAuthority(assignment), test.WithCurves(ecc.BN254))
}

func TestCustomRingAuthorityRejectsDefaultRingOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingAuthorityCircuit(Shape(shape))
	ring := ringAuthorityRing()
	assignment := buildRingAuthorityAssignmentRings(t, shape, ring, ring, big.NewInt(0))

	assert.SolvingFailed(circuit, asCustomRingAuthority(assignment), test.WithCurves(ecc.BN254))
}

func TestCustomRingAuthorityRejectsAddressInputs(t *testing.T) {
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	for addressIndex := range shape.NInputs {
		t.Run(fmt.Sprintf("input-%d", addressIndex), func(t *testing.T) {
			assert := test.NewAssert(t)
			circuit := MustNewCustomRingAuthorityCircuit(Shape(shape))
			assignment := buildRingAuthorityAssignmentWithAddressInput(t, shape, addressIndex)

			assert.SolvingFailed(circuit, asCustomRingAuthority(assignment), test.WithCurves(ecc.BN254))
		})
	}
}

func buildRingAuthorityAssignment(t testing.TB, shape protocol.Shape) *testAssignment {
	t.Helper()
	ring := ringAuthorityRing()
	return buildRingAuthorityAssignmentWithRing(t, shape, ring, ring)
}

func buildRingAuthorityAssignmentWithRing(t testing.TB, shape protocol.Shape, publicRing, utxoRing *big.Int) *testAssignment {
	t.Helper()
	return buildRingAuthorityAssignmentRings(t, shape, publicRing, utxoRing, utxoRing)
}

func buildRingAuthorityAssignmentRings(t testing.TB, shape protocol.Shape, publicRing, inputRing, outputRing *big.Int) *testAssignment {
	t.Helper()
	inputs, outputs := defaultBalancedUtxos(t, shape)
	for i := range inputs {
		inputs[i].RingProgramID = new(big.Int).Set(inputRing)
	}
	for i := range outputs {
		outputs[i].RingProgramID = new(big.Int).Set(outputRing)
	}
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)
	assignment.RingProgramID = new(big.Int).Set(publicRing)
	refreshRingAuthorityPublicInputHash(t, assignment)
	return assignment
}

func buildRingAuthorityAssignmentWithAddressInput(
	t testing.TB,
	shape protocol.Shape,
	addressIndex int,
) *testAssignment {
	t.Helper()
	ring := ringAuthorityRing()
	asset := protocol.SolAsset()
	inputs := []protocol.Utxo{
		sampleUtxoWithAssetAndAmount(10, asset, spptest.Fe(0)),
		sampleUtxoWithAssetAndAmount(20, asset, spptest.Fe(0)),
	}
	inputs[1-addressIndex].Amount = spptest.Fe(100)
	outputs := twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, asset, spptest.Fe(100)))
	for i := range inputs {
		inputs[i].RingProgramID = new(big.Int).Set(ring)
	}
	for i := range outputs {
		outputs[i].RingProgramID = new(big.Int).Set(ring)
	}

	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)
	assignment.RingProgramID = new(big.Int).Set(ring)
	makeAddressSlot(t, assignment, addressIndex, addressOwnerPkHash(t), spptest.Fe(int64(0xABCDEF+addressIndex)))

	inputHashes := make([]*big.Int, shape.NInputs)
	addressHashes := make([]*big.Int, shape.NInputs)
	for i := range assignment.Inputs {
		utxoHash := spptest.MustUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[i].Utxo))
		if i == addressIndex {
			addressHashes[i] = utxoHash
			inputHashes[i] = big.NewInt(0)
		} else {
			inputHashes[i] = utxoHash
			addressHashes[i] = big.NewInt(0)
		}
	}
	assignment.PrivateTxHash = spptest.MustPrivateTxHash(
		t,
		inputHashes,
		spptest.ToBigInts(assignment.OutputHashes()),
		addressHashes,
		spptest.AsBigInt(assignment.ExternalDataHash),
	)
	refreshRingAuthorityPublicInputHash(t, assignment)
	return assignment
}

func refreshRingAuthorityPublicInputHash(t testing.TB, assignment *testAssignment) {
	refreshPublicInputHashVariant(t, assignment, false, true)
}
