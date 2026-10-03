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

// Regression tests for INV-TRANSACT-31/32 (pre-PR164): the old spp_transaction circuit
// left a padding/dummy input's public Nullifier a free witness -- the
// derived-nullifier binding was `assertEqualWhen(api, spendOrAddress, ...)`,
// vacuous for padding, non-inclusion was gated on notDummy, and the ordering
// check was remapped to 0 < 1 < 2 for dummies. The on-chain program queues
// every input slot's nullifier, so an attacker could commit an arbitrary,
// unprovable value (e.g. one already in the nullifier tree, or 0) into the
// strictly-ordered nullifier queue: batch append requires low < value < next
// for every queued value, so one poisoned value halts the queue forever and
// bricks the pool.
//
// Post-PR164 every slot (utxo, address, dummy) goes through checkNonInclusion:
// the in-circuit derived nullifier must equal the public signal, its low-leaf
// Merkle proof must verify against the public root, and
// NullifierLowValue < Nullifier < NullifierNextValue must hold over canonical
// field values. Distinctness covers every nonzero nullifier. The one exception
// is compact padding: a dummy past slot 0 that publishes 0, which SPP never
// queues (compact_test.go).

// refreshNullifierAttackHashes keeps these fixtures' real outputs and transaction
// hashes consistent with a changed first nullifier. inputHashes contains zero
// for each dummy slot and the UTXO hash for each spent input. The P256 caller
// must then authorize the new private transaction hash and refresh its public hash.
func refreshNullifierAttackHashes(t testing.TB, assignment *testAssignment, inputHashes []*big.Int) {
	t.Helper()
	refreshDerivedOutputBlindings(t, assignment)
	assignment.PrivateTxHash = spptest.MustPrivateTxHash(
		t,
		inputHashes,
		spptest.ToBigInts(assignment.OutputHashes()),
		noAddressNullifiers(len(inputHashes)),
		assignment.privateTxBlinding(t),
	)
	refreshPublicInputHash(t, assignment)
}

// TestDummyInputRejectsAttackerChosenNullifier (INV-TRANSACT-31): a dummy slot whose public
// Nullifier is NOT the circuit-derived value must not solve, even with a
// consistent public input hash. The constant 0xF01 stands in for a tree-resident
// poison value; against an empty tree the ordering and Merkle checks would pass
// for it, so the derived-nullifier binding (inputs.go: checkNonInclusion step 1)
// is the sole rejecting constraint. Pre-PR164 this witness solved.
func TestDummyInputRejectsAttackerChosenNullifier(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildDummyInputShield(t, 125)
	assert.SolvingSucceeded(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))

	assignment.Inputs[0].Nullifier = spptest.Fe(0xF01)
	refreshNullifierAttackHashes(t, assignment, []*big.Int{spptest.Fe(0)})

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// TestDummyInputRejectsZeroNullifier (INV-TRANSACT-31): slot 0's nullifier seeds
// the output blindings, so it can never be compact padding. A zero there is
// rejected even on a dummy; later dummy slots may publish 0 (compact_test.go).
// The blindings and hashes are rederived from the zero nullifier, so the
// slot-0 rule is the only rejecting constraint.
func TestDummyInputRejectsZeroNullifier(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildDummyInputShield(t, 125)
	assignment.Inputs[0].Nullifier = spptest.Fe(0)
	refreshNullifierAttackHashes(t, assignment, []*big.Int{spptest.Fe(0)})

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// TestCircuitRejectsSharedNullifierAcrossSlots (INV-TRANSACT-31): two input slots carrying
// the same nullifier must not solve. Slot 1 is an exact copy of slot 0 -- same
// UTXO, same inclusion and non-inclusion witnesses, same derived nullifier --
// and the outputs are rebalanced to the duplicated input sum, so every per-slot
// check passes and the unconditional assertDistinctNullifiers
// (transaction.go) is the sole rejecting constraint. Without it the same UTXO
// would be spent twice in one proof.
func TestCircuitRejectsSharedNullifierAcrossSlots(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)

	// Duplicate slot 0 into slot 1: identical private witness and public signals,
	// so the derived nullifier equals the public one in both slots.
	assignment.Inputs[1] = assignment.Inputs[0]

	// Rebalance: the inputs now contribute 2 * amount0 (100 + 100), so split the
	// outputs 100/100 and recompute their hashes.
	for i := range assignment.Outputs {
		assignment.Outputs[i].Utxo.Amount = spptest.Fe(100)
		assignment.Outputs[i].Hash = testUtxoHash(t, circuitFieldsToUtxo(assignment.Outputs[i].Utxo), assignment.OutputTreeID)
	}

	// Recompute the private tx hash with the duplicated input hash, then refresh
	// the public input hash so distinctness is the only failing constraint.
	inputHash := testUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[0].Utxo), assignment.inputTreeID(0))
	assignment.PrivateTxHash = spptest.MustPrivateTxHash(
		t,
		[]*big.Int{inputHash, inputHash},
		spptest.ToBigInts(assignment.OutputHashes()),
		noAddressNullifiers(2),
		assignment.privateTxBlinding(t),
	)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// TestP256DummyInputRejectsAttackerChosenNullifier (INV-TRANSACT-31, P256 rail):
// a real P256 spend authorizes the transaction alongside a dummy in slot 1.
// Changing the dummy's public nullifier must fail only its derived-nullifier
// binding, with output blindings, transaction hashes, and P256 authorization
// refreshed to agree with the attacker-chosen value.
func TestP256DummyInputRejectsAttackerChosenNullifier(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)

	// Keep the 100-unit spend in slot 0 and replace slot 1 with padding.
	in := &assignment.Inputs[1]
	in.Utxo.Domain = spptest.Fe(DummyDomain)
	in.Utxo.Owner = spptest.Fe(0)
	in.Utxo.Asset = spptest.Fe(0)
	in.Utxo.Amount = spptest.Fe(0)
	in.OwnerPkHash = spptest.Fe(0)
	in.NullifierSecret = spptest.Fe(0)
	for i := range assignment.Outputs {
		assignment.Outputs[i].Utxo.Amount = spptest.Fe(50)
	}

	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	inputHashes := []*big.Int{
		testUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[0].Utxo), assignment.inputTreeID(0)),
		spptest.Fe(0),
	}
	refreshNullifierAttackHashes(t, assignment, inputHashes)
	authorization := authorizeP256(t, assignment, owner, owner)
	assert.SolvingSucceeded(circuit, asCustomRingP256(assignment, authorization), test.WithCurves(ecc.BN254))

	assignment.Inputs[1].Nullifier = spptest.Fe(0xF01)
	refreshNullifierAttackHashes(t, assignment, inputHashes)
	authorization = authorizeP256(t, assignment, owner, owner)

	assert.SolvingFailed(circuit, asCustomRingP256(assignment, authorization), test.WithCurves(ecc.BN254))
}
