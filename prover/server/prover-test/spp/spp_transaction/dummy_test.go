package spptransaction

import (
	. "light/light-prover/circuits/spp_transaction"
	"math/big"
	"testing"

	"light/light-prover/prover-test/spp/protocol"
	"light/light-prover/prover-test/spp/spptest"

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

	// Turn input[0] into an inert dummy slot: IsDummy=1 with zero amount (the
	// only pinned field). The public columns are zeroed to match the on-chain
	// zero-padded reconstruction; the remaining witness fields are gated on
	// notDummy and so are ignored.
	in := &assignment.Inputs[0]
	in.IsDummy = spptest.Fe(1)
	in.Utxo.Amount = spptest.Fe(0)
	in.UtxoTreeRoot = spptest.Fe(0)
	in.NullifierTreeRoot = spptest.Fe(0)
	in.Nullifier = spptest.Fe(0)
	in.SolanaOwnerPkHash = spptest.Fe(0)

	// The dummy contributes 0 to the private-tx-hash chain, so recompute it (and
	// the derived P256 message hash) with the input hash zeroed, then refresh the
	// public-input hash from the now-canonical witness.
	OutputHashes := spptest.ToBigInts(assignment.OutputHashes())
	privateTxHash := spptest.MustPrivateTxHash(
		t,
		[]*big.Int{big.NewInt(0)},
		OutputHashes,
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
	circuit := MustNewCircuit(Shape(shape))
	assert.SolvingSucceeded(circuit, buildDummyInputShield(t, 125), test.WithCurves(ecc.BN254))
}

// A dummy slot's public columns are unpinned so dummies can mimic real slots
// (arity hiding): a non-zero owner entry, nullifier, and roots on a dummy all
// solve once the public input hash matches. The dummy stays inert — the
// amount pin and the notDummy gating keep it out of the balance and the
// spend checks.
func TestDummyInputAcceptsMimickedPublicColumns(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildDummyInputShield(t, 125)
	assignment.Inputs[0].SolanaOwnerPkHash = testSolanaPkField(t)
	assignment.Inputs[0].Nullifier = spptest.Fe(7)
	assignment.Inputs[0].UtxoTreeRoot = spptest.Fe(8)
	assignment.Inputs[0].NullifierTreeRoot = spptest.Fe(9)
	refreshPublicInputHash(t, assignment)
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestDummyInputRejectsNonZeroAmount pins the dummy-slot inertness constraint
// (spend.go: AssertZeroWhen(IsDummy, Amount)). Amount is not a public
// input and the dummy's UTXO hash is selected to 0, so it does not affect the
// balance or the transcript — flipping it isolates this single constraint as the
// sole reason the witness becomes unsatisfiable.
func TestDummyInputRejectsNonZeroAmount(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildDummyInputShield(t, 125)
	assignment.Inputs[0].Utxo.Amount = spptest.Fe(1)
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}
