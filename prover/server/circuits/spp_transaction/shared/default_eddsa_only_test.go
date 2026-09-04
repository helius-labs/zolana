package shared_test

import (
	"math/big"
	"testing"

	defaultring "zolana/prover/circuits/spp_transaction/default"
	. "zolana/prover/circuits/spp_transaction/shared"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func MustNewDefaultRingEddsaOnlyCircuit(shape Shape) *defaultring.DefaultRingEddsaOnlyCircuit {
	circuit, err := defaultring.NewDefaultRingEddsaOnlyCircuit(shape)
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

// makeDefaultRing turns an anonymous assignment whose outputs all carry the
// default owner into a valid default-ring one: tag every output and refresh the
// default-ring public-input hash.
func makeDefaultRing(t testing.TB, assignment *testAssignment) {
	t.Helper()
	pkField, nullifierPk := defaultOutputOwnerTag(t)
	for i := range assignment.Outputs {
		assignment.Outputs[i].OwnerPkHash = pkField
		assignment.Outputs[i].NullifierPk = nullifierPk
	}
	refreshDefaultRingPublicInputHash(t, assignment)
}

func refreshDefaultRingPublicInputHash(t testing.TB, assignment *testAssignment) {
	// The shared builder defaults to a nonzero ring id for the custom-ring
	// circuits; the default-ring variants pin it to 0.
	assignment.RingProgramID = spptest.Fe(0)
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
		RingDataHash:  spptest.Fe(0),
		RingProgramID: spptest.Fe(0),
	}
}

func buildDefaultRingEddsaOnlyAssignment(t testing.TB, shape protocol.Shape) *testAssignment {
	t.Helper()
	inputs, outputs := defaultBalancedUtxos(t, shape)
	return buildDefaultRingEddsaOnlyAssignmentFromUtxos(t, shape, inputs, outputs)
}

func buildDefaultRingEddsaOnlyAssignmentFromUtxos(
	t testing.TB,
	shape protocol.Shape,
	inputUtxos []protocol.Utxo,
	outputUtxos []protocol.Utxo,
) *testAssignment {
	t.Helper()
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputUtxos, outputUtxos)
	makeDefaultRing(t, assignment)
	return assignment
}

// The Solana-only default-ring circuit binds every output owner to its public
// pk_field tag and proves end to end.
func TestDefaultRingEddsaOnlySolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewDefaultRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildDefaultRingEddsaOnlyAssignment(t, shape)

	assert.SolvingSucceeded(circuit, asDefaultRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
	assert.ProverSucceeded(
		circuit,
		asDefaultRingEddsaOnly(assignment),
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.NoSerializationChecks(),
	)
}

func TestDefaultRingEddsaOnlyPublicInputHashBindsEveryField(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewDefaultRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildDefaultRingEddsaOnlyAssignment(t, shape)
	refreshHash := func() { refreshDefaultRingPublicInputHash(t, assignment) }

	assertPublicInputHashBindsEveryField(
		t,
		circuit,
		assignment,
		func() frontend.Circuit { return asDefaultRingEddsaOnly(assignment) },
		refreshHash,
		publicInputHashBindingOptions{
			includeOutputOwnerPkHashes: true,
			signerWidth:                len(assignment.SignerPkHashes),
		},
	)
}

// A mistagged output owner (OwnerPkHash that does not recompute the output
// owner_hash) fails the default-ring binding even with a consistent public hash.
func TestDefaultRingEddsaOnlyRejectsMistaggedOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewDefaultRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildDefaultRingEddsaOnlyAssignment(t, shape)
	assignment.Outputs[0].OwnerPkHash = spptest.Fe(424242)
	refreshDefaultRingPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asDefaultRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// A data-carrying output whose public owner tag is one of the signers solves:
// the signer array holds the input owner tags, and output 0 carries the same one.
func TestDefaultRingEddsaOnlyAcceptsDataHashOnSignerOwnedOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	inputs, outputs := defaultBalancedUtxos(t, shape)
	outputs[0].DataHash = spptest.Fe(0x99)
	assignment := buildDefaultRingEddsaOnlyAssignmentFromUtxos(t, shape, inputs, outputs)

	circuit := MustNewDefaultRingEddsaOnlyCircuit(Shape(shape))
	assert.SolvingSucceeded(circuit, asDefaultRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// The data check is on the signing key, not on the full owner identity: a
// data-carrying output owned by the signer under a different nullifier pubkey
// (a different derived identity of the same signer) solves.
func TestDefaultRingEddsaOnlyAcceptsDataHashOnSignerOwnedOutputWithOtherNullifierPk(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	pkField := testSolanaPkField(t)
	otherNullifierPk := spptest.MustNullifierPk(t, spptest.Fe(1234))

	inputs, outputs := defaultBalancedUtxos(t, shape)
	outputs[0].DataHash = spptest.Fe(0x99)
	outputs[0].Owner = spptest.MustOwnerHash(t, pkField, otherNullifierPk)
	assignment := buildDefaultRingEddsaOnlyAssignmentFromUtxos(t, shape, inputs, outputs)
	assignment.Outputs[0].NullifierPk = otherNullifierPk
	refreshDefaultRingPublicInputHash(t, assignment)

	circuit := MustNewDefaultRingEddsaOnlyCircuit(Shape(shape))
	assert.SolvingSucceeded(circuit, asDefaultRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// A data-carrying output owned by a key that did not sign must not solve, even
// though its public owner tag correctly recomputes the output owner_hash: the
// tag is not in the signer array.
func TestDefaultRingEddsaOnlyRejectsDataHashOnNonSignerOwnedOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	otherPkField := testSolanaPkFieldSeed(t, 0x43)
	_, nullifierPk := defaultOutputOwnerTag(t)

	inputs, outputs := defaultBalancedUtxos(t, shape)
	outputs[0].DataHash = spptest.Fe(0x99)
	outputs[0].Owner = spptest.MustOwnerHash(t, otherPkField, nullifierPk)
	assignment := buildDefaultRingEddsaOnlyAssignmentFromUtxos(t, shape, inputs, outputs)
	assignment.Outputs[0].OwnerPkHash = otherPkField
	refreshDefaultRingPublicInputHash(t, assignment)

	circuit := MustNewDefaultRingEddsaOnlyCircuit(Shape(shape))
	assert.SolvingFailed(circuit, asDefaultRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// A dummy output skips the owner binding, but its public tag must still name
// a transaction participant (AssertDummyTags): a third party's pk_field would
// read as a payment to someone uninvolved in the transaction.
func TestDefaultRingEddsaOnlyRejectsDummyOutputThirdPartyTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := dummyOutputAssignment(t, shape)

	// Dummy slot tagged with a third party's pk_field.
	assignment.Outputs[1].OwnerPkHash = spptest.Fe(424242)
	assignment.Outputs[1].NullifierPk = spptest.Fe(55)
	refreshDummyOutputHashes(t, assignment)

	circuit := MustNewDefaultRingEddsaOnlyCircuit(Shape(shape))
	assert.SolvingFailed(circuit, asDefaultRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// The same dummy output solves when tagged with a signer: the pad then reads as
// a change output, attributing the transaction only to a participant.
func TestDefaultRingEddsaOnlyDummyOutputSignerTagSolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := dummyOutputAssignment(t, shape)

	// Dummy slot tagged with the real input's owner tag (a signer).
	assignment.Outputs[1].OwnerPkHash = assignment.Inputs[0].OwnerPkHash
	assignment.Outputs[1].NullifierPk = spptest.Fe(55)
	refreshDummyOutputHashes(t, assignment)

	circuit := MustNewDefaultRingEddsaOnlyCircuit(Shape(shape))
	assert.SolvingSucceeded(circuit, asDefaultRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// The payer signs but is not a nameable dummy identity: a fee sponsor must not
// be shown as a recipient by a transaction it only paid for.
func TestDefaultRingEddsaOnlyRejectsDummyOutputPayerHashTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := dummyOutputAssignment(t, shape)

	tagDummyOutput(t, assignment, assignment.TransactionSignerPkHashes()[0])
	refreshDefaultRingPublicInputHash(t, assignment)

	circuit := MustNewDefaultRingEddsaOnlyCircuit(Shape(shape))
	assert.SolvingFailed(circuit, asDefaultRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// A self-paying owner reappears through its own change output: once a real
// output publishes the payer identity, a dummy may repeat it.
func TestDefaultRingEddsaOnlyAcceptsDummyOutputPayerTagPublishedByChange(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := dummyOutputAssignment(t, shape)

	payer := testPayerPkHash()
	retagRealOutput(t, assignment, payer)
	tagDummyOutput(t, assignment, payer)
	refreshDefaultRingPublicInputHash(t, assignment)

	circuit := MustNewDefaultRingEddsaOnlyCircuit(Shape(shape))
	assert.SolvingSucceeded(circuit, asDefaultRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// tagDummyOutput sets the dummy slot's public tag of a dummyOutputAssignment
// and recomputes the private-tx hash. Callers refresh the rail's public-input
// hash afterwards.
func tagDummyOutput(t testing.TB, assignment *testAssignment, tag frontend.Variable) {
	t.Helper()
	assignment.Outputs[1].OwnerPkHash = tag
	assignment.Outputs[1].NullifierPk = spptest.Fe(55)
	refreshDummyOutputPrivateTxHash(t, assignment)
}

// retagRealOutput gives the real output of a dummyOutputAssignment the
// recipient pkField and recomputes the output hashes.
func retagRealOutput(t testing.TB, assignment *testAssignment, pkField *big.Int) {
	t.Helper()
	owner, err := protocol.OwnerHash(pkField, spptest.AsBigInt(assignment.Outputs[0].NullifierPk))
	if err != nil {
		t.Fatalf("owner hash: %v", err)
	}
	assignment.Outputs[0].Utxo.Owner = owner
	assignment.Outputs[0].OwnerPkHash = pkField
	refreshDerivedOutputBlindings(t, assignment)
}

func dummyOutputAssignment(t testing.TB, shape protocol.Shape) *testAssignment {
	t.Helper()
	solAsset := protocol.SolAsset()
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(100))},
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(100)),
			emptyOutputUtxo(),
		},
	)

	pkField, nullifierPk := defaultOutputOwnerTag(t)
	assignment.Outputs[0].OwnerPkHash = pkField
	assignment.Outputs[0].NullifierPk = nullifierPk
	return assignment
}

// refreshDummyOutputHashes recomputes the private-tx hash (the dummy
// contributes 0) and the default-ring public-input hash after output tag edits.
func refreshDummyOutputHashes(t testing.TB, assignment *testAssignment) {
	t.Helper()
	refreshDummyOutputPrivateTxHash(t, assignment)
	refreshDefaultRingPublicInputHash(t, assignment)
}

// refreshDummyOutputPrivateTxHash recomputes the private-tx hash of a
// dummyOutputAssignment: the real output's hash enters, the dummy contributes 0.
func refreshDummyOutputPrivateTxHash(t testing.TB, assignment *testAssignment) {
	t.Helper()
	inputHash := spptest.MustUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[0].Utxo))
	realOutputHash := spptest.AsBigInt(assignment.Outputs[0].Hash)
	privateTxHash := spptest.MustPrivateTxHash(
		t,
		[]*big.Int{inputHash},
		[]*big.Int{realOutputHash, big.NewInt(0)},
		noAddressHashes(1),
		spptest.AsBigInt(assignment.ExternalDataHash),
		assignment.privateTxBlinding(t),
	)
	assignment.PrivateTxHash = privateTxHash
}
