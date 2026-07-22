package shared_test

import (
	"math/big"
	"testing"

	defaultzone "zolana/prover/circuits/spp_transaction/default"
	. "zolana/prover/circuits/spp_transaction/shared"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func MustNewDefaultZoneEddsaOnlyCircuit(shape Shape) *defaultzone.DefaultZoneEddsaOnlyCircuit {
	circuit, err := defaultzone.NewDefaultZoneEddsaOnlyCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

// defaultOutputOwnerTag is the (pk_field, nullifier_pk) decomposition of the
// owner sampleUtxo bakes into every default output: OwnerHash(testSolanaPkField,
// NullifierPk(99)).
func defaultOutputOwnerTag(t testing.TB) (*big.Int, *big.Int) {
	t.Helper()
	return testSolanaPkField(t), spptest.MustNullifierPk(t, spptest.Fe(99))
}

// makeDefaultZone turns an anonymous assignment whose outputs all carry the
// default owner into a valid default-zone one: tag every output, set the shared
// P256 signing field, and refresh the default-zone public-input hash.
func makeDefaultZone(t testing.TB, assignment *testAssignment, p256SigningPkField *big.Int) {
	t.Helper()
	if p256SigningPkField == nil {
		p256SigningPkField = spptest.Fe(0)
	}
	assignment.P256SigningPkField = p256SigningPkField
	pkField, nullifierPk := defaultOutputOwnerTag(t)
	for i := range assignment.Outputs {
		assignment.Outputs[i].OwnerPkHash = pkField
		assignment.Outputs[i].NullifierPk = nullifierPk
	}
	refreshDefaultZonePublicInputHash(t, assignment)
}

func refreshDefaultZonePublicInputHash(t testing.TB, assignment *testAssignment) {
	// The shared builder defaults to a nonzero zone id for the custom-zone
	// circuits; the default-zone variants pin it to 0.
	assignment.ZoneProgramID = spptest.Fe(0)
	refreshPublicInputHashVariant(t, assignment, true, false)
}

// emptyOutputUtxo is a dummy output slot (DummyDomain, every field zero except
// the blinding); see spec Empty UTXO.
func emptyOutputUtxo() protocol.Utxo {
	return protocol.Utxo{
		Domain:        spptest.Fe(DummyDomain),
		Owner:         spptest.Fe(0),
		Asset:         spptest.Fe(0),
		Amount:        spptest.Fe(0),
		Blinding:      spptest.Fe(777),
		DataHash:      spptest.Fe(0),
		ZoneDataHash:  spptest.Fe(0),
		ZoneProgramID: spptest.Fe(0),
	}
}

func buildDefaultZoneEddsaOnlyAssignment(t testing.TB, shape protocol.Shape) *testAssignment {
	t.Helper()
	inputs, outputs := defaultBalancedUtxos(t, shape)
	return buildDefaultZoneEddsaOnlyAssignmentFromUtxos(t, shape, inputs, outputs)
}

func buildDefaultZoneEddsaOnlyAssignmentFromUtxos(
	t testing.TB,
	shape protocol.Shape,
	inputUtxos []protocol.Utxo,
	outputUtxos []protocol.Utxo,
) *testAssignment {
	t.Helper()
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputUtxos, outputUtxos)
	assignment.P256MessageHashLow = spptest.Fe(0)
	assignment.P256MessageHashHigh = spptest.Fe(0)
	makeDefaultZone(t, assignment, nil)
	return assignment
}

// The Solana-only default-zone circuit binds every output owner to its public
// pk_field tag and proves end to end.
func TestDefaultZoneEddsaOnlySolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewDefaultZoneEddsaOnlyCircuit(Shape(shape))
	assignment := buildDefaultZoneEddsaOnlyAssignment(t, shape)

	assert.SolvingSucceeded(circuit, asDefaultZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
	assert.ProverSucceeded(
		circuit,
		asDefaultZoneEddsaOnly(assignment),
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.NoSerializationChecks(),
	)
}

// A mistagged output owner (OwnerPkHash that does not recompute the output
// owner_hash) fails the default-zone binding even with a consistent public hash.
func TestDefaultZoneEddsaOnlyRejectsMistaggedOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewDefaultZoneEddsaOnlyCircuit(Shape(shape))
	assignment := buildDefaultZoneEddsaOnlyAssignment(t, shape)
	assignment.Outputs[0].OwnerPkHash = spptest.Fe(424242)
	refreshDefaultZonePublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asDefaultZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// A data-carrying output whose public owner tag is one of the signers solves:
// the signer array holds the input owner tags, and output 0 carries the same one.
func TestDefaultZoneEddsaOnlyAcceptsDataHashOnSignerOwnedOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	inputs, outputs := defaultBalancedUtxos(t, shape)
	outputs[0].DataHash = spptest.Fe(0x99)
	assignment := buildDefaultZoneEddsaOnlyAssignmentFromUtxos(t, shape, inputs, outputs)

	circuit := MustNewDefaultZoneEddsaOnlyCircuit(Shape(shape))
	assert.SolvingSucceeded(circuit, asDefaultZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// The data check is on the signing key, not on the full owner identity: a
// data-carrying output owned by the signer under a different nullifier pubkey
// (a different derived identity of the same signer) solves.
func TestDefaultZoneEddsaOnlyAcceptsDataHashOnSignerOwnedOutputWithOtherNullifierPk(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	pkField := testSolanaPkField(t)
	otherNullifierPk := spptest.MustNullifierPk(t, spptest.Fe(1234))

	inputs, outputs := defaultBalancedUtxos(t, shape)
	outputs[0].DataHash = spptest.Fe(0x99)
	outputs[0].Owner = spptest.MustOwnerHash(t, pkField, otherNullifierPk)
	assignment := buildDefaultZoneEddsaOnlyAssignmentFromUtxos(t, shape, inputs, outputs)
	assignment.Outputs[0].NullifierPk = otherNullifierPk
	refreshDefaultZonePublicInputHash(t, assignment)

	circuit := MustNewDefaultZoneEddsaOnlyCircuit(Shape(shape))
	assert.SolvingSucceeded(circuit, asDefaultZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// A data-carrying output owned by a key that did not sign must not solve, even
// though its public owner tag correctly recomputes the output owner_hash: the
// tag is not in the signer array.
func TestDefaultZoneEddsaOnlyRejectsDataHashOnNonSignerOwnedOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	otherPkField := testSolanaPkFieldSeed(t, 0x43)
	_, nullifierPk := defaultOutputOwnerTag(t)

	inputs, outputs := defaultBalancedUtxos(t, shape)
	outputs[0].DataHash = spptest.Fe(0x99)
	outputs[0].Owner = spptest.MustOwnerHash(t, otherPkField, nullifierPk)
	assignment := buildDefaultZoneEddsaOnlyAssignmentFromUtxos(t, shape, inputs, outputs)
	assignment.Outputs[0].OwnerPkHash = otherPkField
	refreshDefaultZonePublicInputHash(t, assignment)

	circuit := MustNewDefaultZoneEddsaOnlyCircuit(Shape(shape))
	assert.SolvingFailed(circuit, asDefaultZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// A dummy output skips the owner binding, so an arbitrary tag still solves once
// the public hash matches (the output contributes 0 to the private-tx-hash).
func TestDefaultZoneEddsaOnlyDummyOutputUnconstrained(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	solAsset := protocol.SolAsset()
	circuit := MustNewDefaultZoneEddsaOnlyCircuit(Shape(shape))

	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(100))},
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(100)),
			emptyOutputUtxo(),
		},
	)

	assignment.P256SigningPkField = spptest.Fe(0)
	assignment.P256MessageHashLow = spptest.Fe(0)
	assignment.P256MessageHashHigh = spptest.Fe(0)
	pkField, nullifierPk := defaultOutputOwnerTag(t)
	assignment.Outputs[0].OwnerPkHash = pkField
	assignment.Outputs[0].NullifierPk = nullifierPk
	// Dummy slot: an arbitrary tag must not be rejected.
	assignment.Outputs[1].OwnerPkHash = spptest.Fe(424242)
	assignment.Outputs[1].NullifierPk = spptest.Fe(55)

	inputHash := spptest.MustUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[0].Utxo))
	realOutputHash := spptest.AsBigInt(assignment.Outputs[0].Hash)
	privateTxHash := spptest.MustPrivateTxHash(
		t,
		[]*big.Int{inputHash},
		[]*big.Int{realOutputHash, big.NewInt(0)},
		noAddressHashes(1),
		spptest.AsBigInt(assignment.ExternalDataHash),
	)
	assignment.PrivateTxHash = privateTxHash
	refreshDefaultZonePublicInputHash(t, assignment)

	assert.SolvingSucceeded(circuit, asDefaultZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}
