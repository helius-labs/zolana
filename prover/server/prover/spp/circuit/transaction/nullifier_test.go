package transaction

import (
	"math/big"
	"testing"

	"light/light-prover/prover/poseidon"
	"light/light-prover/prover/spp/internal/spptest"
	"light/light-prover/prover/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

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

// The nullifier is the Poseidon image truncated to the tree's 248-bit domain
// with a canonical (< p) decomposition. Two values an attacker might try to
// substitute must both fail: the untruncated full image, and the low 248 bits
// of the alias full+p (what a NON-canonical decomposition would yield — the
// double-spend vector the canonical check exists to block).
func TestCircuitRejectsUntruncatedAndAliasNullifier(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)

	inputUtxos, _ := defaultBalancedUtxos(t, shape)
	inputHash := spptest.MustUtxoHash(t, inputUtxos[0])
	full, err := poseidon.HashWithT(4, []*big.Int{inputHash, inputUtxos[0].Blinding, spptest.Fe(99)})
	if err != nil {
		t.Fatal(err)
	}
	if full.BitLen() <= 248 {
		// The fixture's full image happens to fit 248 bits, which would make
		// the untruncated case vacuous. Deterministic fixtures make this a
		// stable property — fail loudly so the fixture gets adjusted.
		t.Fatal("fixture nullifier image fits 248 bits; pick a different fixture")
	}

	untruncated := buildCircuitAssignment(t, shape)
	untruncated.Inputs[0].Nullifier = new(big.Int).Set(full)
	assert.SolvingFailed(circuit, untruncated, test.WithCurves(ecc.BN254))

	alias := buildCircuitAssignment(t, shape)
	aliasFull := new(big.Int).Add(full, poseidon.Modulus)
	alias.Inputs[0].Nullifier = protocol.Truncate248(aliasFull)
	assert.SolvingFailed(circuit, alias, test.WithCurves(ecc.BN254))
}
