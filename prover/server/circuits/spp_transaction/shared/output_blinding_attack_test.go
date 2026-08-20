package shared_test

import (
	"math/big"
	"testing"

	. "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func refreshOutputAttackHashes(t testing.TB, assignment *testAssignment) {
	t.Helper()
	inputHashes := make([]*big.Int, len(assignment.Inputs))
	for i := range assignment.Inputs {
		inputHashes[i] = spptest.MustUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[i].Utxo))
	}
	privateOutputHashes := make([]*big.Int, len(assignment.Outputs))
	for i := range assignment.Outputs {
		assignment.Outputs[i].Hash = spptest.MustUtxoHash(
			t,
			circuitFieldsToUtxo(assignment.Outputs[i].Utxo),
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
	)
	refreshDefaultRingPublicInputHash(t, assignment)
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

func TestCircuitRejectsWrongOutputBlindingSeed(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	assignment := buildDefaultRingEddsaOnlyAssignment(t, shape)
	assignment.OutputBlindingSeed = spptest.Fe(4243)

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
