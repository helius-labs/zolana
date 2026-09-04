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
// field values. Distinctness across slots is unconditional.

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
	assignment.Inputs[0].Nullifier = spptest.Fe(0xF01)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// TestDummyInputRejectsZeroNullifier (INV-TRANSACT-31): nullifier 0 can never enter the
// indexed nullifier tree -- strict ordering needs NullifierLowValue < 0, which
// no canonical field value satisfies -- so queuing it would brick the pool.
// The derived-nullifier binding also rejects it (a Poseidon-derived nullifier
// is not 0). Pre-PR164 a padding slot could publish 0 freely.
func TestDummyInputRejectsZeroNullifier(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildDummyInputShield(t, 125)
	assignment.Inputs[0].Nullifier = spptest.Fe(0)
	refreshPublicInputHash(t, assignment)

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
		assignment.Outputs[i].Hash = spptest.MustUtxoHash(t, circuitFieldsToUtxo(assignment.Outputs[i].Utxo))
	}

	// Recompute the private tx hash with the duplicated input hash, then refresh
	// the public input hash so distinctness is the only failing constraint.
	inputHash := spptest.MustUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[0].Utxo))
	assignment.PrivateTxHash = spptest.MustPrivateTxHash(
		t,
		[]*big.Int{inputHash, inputHash},
		spptest.ToBigInts(assignment.OutputHashes()),
		noAddressHashes(2),
		spptest.AsBigInt(assignment.ExternalDataHash),
		assignment.privateTxBlinding(t),
	)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// TestP256DummyInputRejectsAttackerChosenNullifier (INV-TRANSACT-31, P256 rail):
// the RingP256 circuit runs the same shared non-inclusion binding -- a dummy
// slot whose public Nullifier is NOT the circuit-derived value must not solve,
// even with a valid P256 authorization and a consistent public input hash.
func TestP256DummyInputRejectsAttackerChosenNullifier(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingP256Circuit(Shape(shape))
	assignment := buildDummyInputShield(t, 125)
	assignment.Inputs[0].Nullifier = spptest.Fe(0xF01)
	owner := spptest.FixedP256Key(t, 11)
	authorization := authorizeP256(t, assignment, owner, owner)

	assert.SolvingFailed(circuit, asCustomRingP256(assignment, authorization), test.WithCurves(ecc.BN254))
}
