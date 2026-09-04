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

func TestCircuitRejectsExternalDataHashMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.ExternalDataHash = spptest.Fe(301)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// TestCircuitRejectsWrongTxSecret: a different secret invalidates the output
// blindings and the private tx hash at once.
func TestCircuitRejectsWrongTxSecret(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.TxSecret = spptest.Fe(4243)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// TestCircuitRejectsForeignPrivateTxBlinding publishes a private_tx_hash over
// a blinding the circuit did not derive, with the rest of the witness
// consistent, so the derivation check alone rejects it. A prover cannot pick
// the blinding, zero included.
func TestCircuitRejectsForeignPrivateTxBlinding(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	inputHashes := make([]*big.Int, len(assignment.Inputs))
	for i := range assignment.Inputs {
		inputHashes[i] = testUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[i].Utxo), assignment.inputTreeID(i))
	}
	assignment.PrivateTxHash = spptest.MustPrivateTxHash(
		t,
		inputHashes,
		spptest.ToBigInts(assignment.OutputHashes()),
		noAddressHashes(len(inputHashes)),
		spptest.AsBigInt(assignment.ExternalDataHash),
		spptest.Fe(0xB11E),
	)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}
