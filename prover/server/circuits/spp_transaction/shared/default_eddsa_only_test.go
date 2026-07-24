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
func makeDefaultZone(t testing.TB, assignment *Circuit, p256SigningPkField *big.Int) {
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

func refreshDefaultZonePublicInputHash(t testing.TB, assignment *Circuit) {
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

func buildDefaultZoneEddsaOnlyAssignment(t testing.TB, shape protocol.Shape) *Circuit {
	t.Helper()
	assignment := buildCircuitAssignment(t, shape)
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
