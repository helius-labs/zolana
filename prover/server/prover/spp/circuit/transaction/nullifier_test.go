package transaction

import (
	"math/big"
	"testing"

	"light/light-prover/prover/spp/internal/spptest"
	"light/light-prover/prover/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

// TestCircuitSolvesWithNullifierAbove248Bits pins the widened tree domain in
// the full circuit: the fixture's nullifier is a raw Poseidon image above
// 2^248 — a value the former 248-bit indexed domain could not hold — bracketed
// against the init witness (low 0, next p-1), and the proof solves.
func TestCircuitSolvesWithNullifierAbove248Bits(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	nullifier := spptest.AsBigInt(assignment.Inputs[0].Nullifier)
	if nullifier.BitLen() <= 248 {
		// Deterministic fixtures make this a stable property — fail loudly so
		// the fixture gets adjusted rather than silently pinning nothing.
		t.Fatal("fixture nullifier fits 248 bits; adjust the fixture so this pins the full-field domain")
	}
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBadNullifierRange(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].NullifierLowValue = assignment.Inputs[0].Nullifier

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBadNullifierSecret(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.NullifierSecret = spptest.Fe(998)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsDuplicateInputWithinTransaction(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assetID := spptest.Fe(7)
	input := sampleUtxoWithAssetAndAmount(10, assetID, spptest.Fe(100))
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{input, input},
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(100, assetID, spptest.Fe(125)),
			sampleUtxoWithAssetAndAmount(110, assetID, spptest.Fe(75)),
		},
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(0),
	)

	// Spending the same UTXO twice yields equal nullifiers; assertDistinctNullifiers
	// rejects it in-circuit so its amount can't be counted twice in the balance.
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}
