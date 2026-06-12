package transaction

import (
	"math/big"
	"testing"

	"light/light-prover/prover/spp/internal/spptest"
	"light/light-prover/prover/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

// buildDummyInputShield builds a valid SOL shield in the {1,2} shape whose only
// input slot is a proper dummy: a public deposit of `deposit` funds two outputs
// summing to `deposit`, with zero real inputs. It is the canonical positive
// baseline for the dummy-slot inertness constraints — the input contributes 0
// to the balance and the transaction-hash chain — so a negative test can flip a
// single inert field and attribute the failure to exactly that constraint.
func buildDummyInputShield(t testing.TB, deposit int64) *Circuit {
	t.Helper()
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	solAsset := protocol.SolAsset()

	// The real input amount is irrelevant: dummifying the slot zeroes it. Outputs
	// must sum to the public deposit since the dummy contributes nothing.
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(50))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(deposit))),
		big.NewInt(deposit),
		big.NewInt(0),
		spptest.Fe(0),
	)

	// Turn input[0] into an inert dummy slot: IsDummy=1 with zero amount, zero
	// nullifier, and zero roots (the exact fields the inertness constraints
	// pin). The remaining witness fields are gated on notDummy and so are
	// ignored.
	in := &assignment.Inputs[0]
	in.IsDummy = spptest.Fe(1)
	in.Utxo.Amount = spptest.Fe(0)
	in.UtxoTreeRoot = spptest.Fe(0)
	in.NullifierTreeRoot = spptest.Fe(0)
	in.Nullifier = spptest.Fe(0)

	// The dummy contributes 0 to the private-tx-hash chain, so recompute it (and
	// the derived P256 message hash) with the input hash zeroed, then refresh the
	// public-input hash from the now-canonical witness.
	outputHashes := spptest.ToBigInts(assignment.outputHashes())
	privateTxHash := spptest.MustPrivateTxHash(
		t,
		[]*big.Int{big.NewInt(0)},
		outputHashes,
		spptest.AsBigInt(assignment.ExternalDataHash),
	)
	assignment.PrivateTxHash = privateTxHash
	assignment.P256MessageHash = spptest.MustP256MessageHash(t, privateTxHash)
	refreshPublicInputHash(t, assignment)
	return assignment
}

// TestDummyInputSlotSolves is the positive baseline: a shield with one inert
// dummy input proves. Without it the negative tests below could pass for the
// wrong reason (an unrelated broken witness).
func TestDummyInputSlotSolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assert.SolvingSucceeded(circuit, buildDummyInputShield(t, 125), test.WithCurves(ecc.BN254))
}

// Shields spend no inputs, so the spec encodes them with owner key 0: the
// P256 path is selected and every ownership check is gated off by the dummy
// slots. This pins that the canonical shield encoding proves.
func TestDummyInputShieldSolvesWithZeroOwnerKey(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildDummyInputShield(t, 125)
	assignment.SolanaOwnerPkHash = spptest.Fe(0)
	refreshPublicInputHash(t, assignment)
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestDummyInputRejectsNonZeroAmount pins the dummy-slot inertness constraint
// (spend.go: assertZeroWhen(IsDummy, Amount)). Amount is not a public
// input and the dummy's UTXO hash is selected to 0, so it does not affect the
// balance or the transcript — flipping it isolates this single constraint as the
// sole reason the witness becomes unsatisfiable.
func TestDummyInputRejectsNonZeroAmount(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildDummyInputShield(t, 125)
	assignment.Inputs[0].Utxo.Amount = spptest.Fe(1)
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestDummyInputRejectsNonZeroNullifier pins assertZeroWhen(IsDummy, Nullifier):
// a dummy slot must publish nullifier 0 so it cannot smuggle a spend into the
// queue.
func TestDummyInputRejectsNonZeroNullifier(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildDummyInputShield(t, 125)
	assignment.Inputs[0].Nullifier = spptest.Fe(7)
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}
