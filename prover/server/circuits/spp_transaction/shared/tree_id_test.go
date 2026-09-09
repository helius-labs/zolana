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

// testInputTreeID is slot 0's tree id; testOutputTreeID is distinct from every
// slot id so a swapped input/output id is caught.
const (
	testInputTreeID  = 7
	testOutputTreeID = 11
)

// testTreeSlots returns InputTrees slots with distinct tree ids, slot 0 =
// testInputTreeID, all publishing the same UTXO and nullifier roots.
func testTreeSlots(utxoRoot, nullifierRoot *big.Int) []TreeSlot {
	ids := []int64{testInputTreeID, 17, 19, 23, 29}
	out := make([]TreeSlot, InputTrees)
	for k := range out {
		out[k] = TreeSlot{ID: spptest.Fe(ids[k]), UtxoRoot: utxoRoot, NullifierRoot: nullifierRoot}
	}
	return out
}

// treeSlotsToProtocol converts assigned circuit slots to their host values.
func treeSlotsToProtocol(slots []TreeSlot) []protocol.TreeSlot {
	out := make([]protocol.TreeSlot, len(slots))
	for k, slot := range slots {
		out[k] = protocol.TreeSlot{
			ID:            spptest.AsBigInt(slot.ID),
			UtxoRoot:      spptest.AsBigInt(slot.UtxoRoot),
			NullifierRoot: spptest.AsBigInt(slot.NullifierRoot),
		}
	}
	return out
}

// testUtxoHash hashes u under the assigned tree id, matching utxoHashGadget.
func testUtxoHash(t testing.TB, u protocol.Utxo, treeID frontend.Variable) *big.Int {
	t.Helper()
	return spptest.MustUtxoHash(t, u, spptest.AsBigInt(treeID))
}

// testPublicInputHash fills in the tree slots and output tree id from the
// circuit assignment; every other preimage element comes from inputs.
func testPublicInputHash(
	t testing.TB,
	inputs protocol.PublicInputs,
	treeSlots []TreeSlot,
	outputTreeID frontend.Variable,
) *big.Int {
	t.Helper()
	inputs.TreeSlots = treeSlotsToProtocol(treeSlots)
	inputs.OutputTreeID = spptest.AsBigInt(outputTreeID)
	hash, err := protocol.PublicInputHash(inputs)
	return spptest.MustHash(t, hash, err)
}

type utxoHashPinCircuit struct {
	Utxo   UtxoCircuitFields
	TreeID frontend.Variable
	Hash   frontend.Variable `gnark:",public"`
}

func (c *utxoHashPinCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(UtxoHashCircuit(api, c.Utxo, c.TreeID), c.Hash)
	return nil
}

// The circuit's utxo hash equals the seven-field native preimage, and the tree
// id is part of it.
func TestUtxoHashCircuitBindsTreeID(t *testing.T) {
	assert := test.NewAssert(t)
	utxo := sampleUtxo(1)
	assignment := &utxoHashPinCircuit{
		Utxo:   fieldsFromUtxo(utxo),
		TreeID: spptest.Fe(testInputTreeID),
		Hash:   testUtxoHash(t, utxo, spptest.Fe(testInputTreeID)),
	}
	assert.SolvingSucceeded(&utxoHashPinCircuit{}, assignment, test.WithCurves(ecc.BN254))

	assignment.TreeID = spptest.Fe(testOutputTreeID)
	assert.SolvingFailed(&utxoHashPinCircuit{}, assignment, test.WithCurves(ecc.BN254))
}

// An input hashed under slot 0 cannot claim slot 1: the slot's tree id enters
// the utxo hash, so the leaf is no longer under the root.
func TestCircuitRejectsInputClaimingOtherSlot(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].TreeSlot = spptest.Fe(1)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// A slot index outside the published slots selects no tree and is rejected.
func TestCircuitRejectsOutOfRangeTreeSlot(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].TreeSlot = spptest.Fe(InputTrees)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// Publishing another output tree id changes the output hash preimage, so the
// published output hashes no longer match.
func TestCircuitRejectsOutputTreeIDMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.OutputTreeID = spptest.Fe(testInputTreeID)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}
