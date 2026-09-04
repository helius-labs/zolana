package shared_test

import (
	"math/big"
	"testing"

	. "zolana/prover/circuits/spp_transaction/shared"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type outputBlindingDerivationCircuit struct {
	FirstNullifier frontend.Variable
	Seed           frontend.Variable
	Expected       frontend.Variable
}

func (c *outputBlindingDerivationCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Expected, DeriveOutputBlinding(api, c.FirstNullifier, c.Seed, 3))
	return nil
}

func refreshOutputAttackHashes(t testing.TB, assignment *testAssignment) {
	t.Helper()
	inputHashes := make([]*big.Int, len(assignment.Inputs))
	for i := range assignment.Inputs {
		inputHashes[i] = testUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[i].Utxo), assignment.InputTreeID)
	}
	privateOutputHashes := make([]*big.Int, len(assignment.Outputs))
	for i := range assignment.Outputs {
		assignment.Outputs[i].Hash = testUtxoHash(
			t,
			circuitFieldsToUtxo(assignment.Outputs[i].Utxo),
			assignment.OutputTreeID,
		)
		if spptest.AsBigInt(assignment.Outputs[i].Utxo.Domain).Int64() == DummyDomain {
			privateOutputHashes[i] = big.NewInt(0)
		} else {
			privateOutputHashes[i] = spptest.AsBigInt(assignment.Outputs[i].Hash)
		}
	}
	assignment.PrivateTxHash = spptest.MustPrivateTxHash(
		t,
		inputHashes,
		privateOutputHashes,
		noAddressHashes(len(inputHashes)),
		spptest.AsBigInt(assignment.ExternalDataHash),
		assignment.privateTxBlinding(t),
	)
	refreshDefaultRingPublicInputHash(t, assignment)
}

func TestCircuitRejectsBadOutputHash(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Outputs[0].Hash = spptest.Fe(999)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

func TestOutputBlindingDerivationMatchesRustVector(t *testing.T) {
	expected, ok := new(big.Int).SetString(
		"06261540e857febb5f8d59eb742ad3d4d8200ff38ccbf2ea16cd1e0a9085e881",
		16,
	)
	if !ok {
		t.Fatal("parse expected output blinding")
	}
	assignment := outputBlindingDerivationCircuit{
		FirstNullifier: 7,
		Seed:           42,
		Expected:       expected,
	}
	test.NewAssert(t).SolvingSucceeded(
		&outputBlindingDerivationCircuit{},
		&assignment,
		test.WithCurves(ecc.BN254),
	)
}

func TestOutputBlindingDomainIsAsciiTag(t *testing.T) {
	if OutputBlindingDomainV1 != 0x54584f42 {
		t.Fatalf("OutputBlindingDomainV1 = %#x", OutputBlindingDomainV1)
	}
}

func TestCircuitRejectsDuplicateOutputCommitmentWithRefreshedPublicInputs(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := buildDefaultRingEddsaOnlyAssignment(t, shape)
	assignment.Outputs[1].Utxo = assignment.Outputs[0].Utxo
	assignment.Outputs[1].OwnerPkHash = assignment.Outputs[0].OwnerPkHash
	assignment.Outputs[1].NullifierPk = assignment.Outputs[0].NullifierPk
	refreshOutputAttackHashes(t, assignment)

	test.NewAssert(t).SolvingFailed(
		MustNewDefaultRingEddsaOnlyCircuit(Shape(shape)),
		asDefaultRingEddsaOnly(assignment),
		test.WithCurves(ecc.BN254),
	)
}

// TestCircuitRejectsStaleOutputBlindings changes TxSecret and republishes a
// consistent private_tx_hash, so only the output blindings, still derived from
// the old secret, disagree with the circuit.
func TestCircuitRejectsStaleOutputBlindings(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := buildDefaultRingEddsaOnlyAssignment(t, shape)
	assignment.TxSecret = spptest.Fe(4243)
	refreshOutputAttackHashes(t, assignment)

	test.NewAssert(t).SolvingFailed(
		MustNewDefaultRingEddsaOnlyCircuit(Shape(shape)),
		asDefaultRingEddsaOnly(assignment),
		test.WithCurves(ecc.BN254),
	)
}

func TestCircuitRejectsFreelyChosenDummyOutputBlinding(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := dummyOutputAssignment(t, shape)
	assignment.Outputs[1].Utxo.Blinding = spptest.Fe(0xBAD)
	refreshOutputAttackHashes(t, assignment)

	test.NewAssert(t).SolvingFailed(
		MustNewDefaultRingEddsaOnlyCircuit(Shape(shape)),
		asDefaultRingEddsaOnly(assignment),
		test.WithCurves(ecc.BN254),
	)
}
