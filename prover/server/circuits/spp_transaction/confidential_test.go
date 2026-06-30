package transaction_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"
	. "zolana/prover/circuits/spp_transaction"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func MustNewSolanaConfidentialCircuit(shape Shape) *Circuit {
	circuit, err := NewTransferConfidentialCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

func MustNewP256ConfidentialCircuit(shape Shape) *Circuit {
	circuit, err := NewTransferP256ConfidentialCircuit(shape)
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

func mustP256PkField(t testing.TB, priv *ecdsa.PrivateKey) *big.Int {
	t.Helper()
	compressed := elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	// Owner pk_field is parity-free (matches OwnerPkFieldGadget); the viewing key
	// keeps the parity-folding P256PkField.
	pkField, err := protocol.OwnerPkField(compressed)
	if err != nil {
		t.Fatalf("p256 pk field: %v", err)
	}
	return pkField
}

// makeConfidential turns an anonymous assignment whose outputs all carry the
// default owner into a valid confidential one: tag every output, set the shared
// P256 signing field, and refresh the confidential public-input hash.
func makeConfidential(t testing.TB, assignment *Circuit, p256SigningPkField *big.Int) {
	t.Helper()
	assignment.Confidential = true
	if p256SigningPkField == nil {
		p256SigningPkField = spptest.Fe(0)
	}
	assignment.P256SigningPkField = p256SigningPkField
	pkField, nullifierPk := defaultOutputOwnerTag(t)
	for i := range assignment.Outputs {
		assignment.Outputs[i].OwnerPkHash = pkField
		assignment.Outputs[i].NullifierPk = nullifierPk
	}
	refreshConfidentialPublicInputHash(t, assignment)
}

func refreshConfidentialPublicInputHash(t testing.TB, assignment *Circuit) {
	refreshPublicInputHashVariant(t, assignment, true, false)
}

// emptyOutputUtxo is an unspendable empty UTXO (owner = amount = 0) used as a
// dummy output slot; see spec Empty UTXO.
func emptyOutputUtxo(asset *big.Int) protocol.Utxo {
	return protocol.Utxo{
		Domain:        spptest.Fe(0),
		Owner:         spptest.Fe(0),
		Asset:         new(big.Int).Set(asset),
		Amount:        spptest.Fe(0),
		Blinding:      spptest.Fe(777),
		DataHash:      spptest.Fe(0),
		ZoneDataHash:  spptest.Fe(0),
		ZoneProgramID: spptest.Fe(0),
	}
}

func buildSolanaConfidentialAssignment(t testing.TB, shape protocol.Shape) *Circuit {
	t.Helper()
	assignment := buildCircuitAssignment(t, shape)
	assignment.P256MessageHashLow = spptest.Fe(0)
	assignment.P256MessageHashHigh = spptest.Fe(0)
	makeConfidential(t, assignment, nil)
	return assignment
}

// The Solana-only confidential circuit binds every output owner to its public
// pk_field tag and proves end to end.
func TestConfidentialSolanaSolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewSolanaConfidentialCircuit(Shape(shape))
	assignment := buildSolanaConfidentialAssignment(t, shape)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
	assert.ProverSucceeded(
		circuit,
		assignment,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.NoSerializationChecks(),
	)
}

// A mistagged output owner (OwnerPkHash that does not recompute the output
// owner_hash) fails the confidential binding even with a consistent public hash.
func TestConfidentialRejectsMistaggedOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewSolanaConfidentialCircuit(Shape(shape))
	assignment := buildSolanaConfidentialAssignment(t, shape)
	assignment.Outputs[0].OwnerPkHash = spptest.Fe(424242)
	refreshConfidentialPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// A dummy output skips the owner binding, so an arbitrary tag still solves once
// the public hash matches (the output contributes 0 to the private-tx-hash).
func TestConfidentialDummyOutputUnconstrained(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	solAsset := protocol.SolAsset()
	circuit := MustNewSolanaConfidentialCircuit(Shape(shape))

	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(100))},
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(100)),
			emptyOutputUtxo(solAsset),
		},
		spptest.Fe(0),
		spptest.Fe(0),
		spptest.Fe(0),
	)

	assignment.Confidential = true
	assignment.P256SigningPkField = spptest.Fe(0)
	assignment.P256MessageHashLow = spptest.Fe(0)
	assignment.P256MessageHashHigh = spptest.Fe(0)
	pkField, nullifierPk := defaultOutputOwnerTag(t)
	assignment.Outputs[0].OwnerPkHash = pkField
	assignment.Outputs[0].NullifierPk = nullifierPk
	// Dummy slot: an arbitrary tag must not be rejected.
	assignment.Outputs[1].IsDummy = spptest.Fe(1)
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
	refreshConfidentialPublicInputHash(t, assignment)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// The P256 confidential rail exposes the P256 input owner: input_owner_pk_hashes
// carries the real pk_field, equal to the shared p256_signing_pk_field, and the
// ownership path is selected by that equality.
func TestConfidentialP256ExposesInputOwner(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewP256ConfidentialCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)
	pkField := mustP256PkField(t, priv)
	assignment.Inputs[0].OwnerPkHash = pkField
	makeConfidential(t, assignment, pkField)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// The P256 confidential rail proves end to end (groth16), matching the Solana
// rail's TestConfidentialSolanaSolves and the anonymous P256 prove coverage.
func TestConfidentialP256Solves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewP256ConfidentialCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)
	pkField := mustP256PkField(t, priv)
	assignment.Inputs[0].OwnerPkHash = pkField
	makeConfidential(t, assignment, pkField)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
	assert.ProverSucceeded(
		circuit,
		assignment,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.NoSerializationChecks(),
	)
}

// p256_signing_pk_field must equal the witnessed P256 key: a mismatch routes the
// input off the P256 path and fails the shared-key assertion.
func TestConfidentialP256RejectsWrongSigningPkField(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewP256ConfidentialCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)
	pkField := mustP256PkField(t, priv)
	assignment.Inputs[0].OwnerPkHash = pkField
	makeConfidential(t, assignment, spptest.Fe(424242))

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}
