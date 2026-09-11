package shared_test

import (
	"math/big"
	"testing"

	. "zolana/prover/circuits/spp_transaction/shared"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

// singleTreeSlots is the shared fixture's routing: every input spends from slot
// 0, the slot testInputTreeID is published in.
func singleTreeSlots(nInputs int) []*big.Int {
	return zeroFields(nInputs)
}

// testInputFlags packs the assignment's InputFlags element the way the host
// does, so the circuit's decode is checked against the production packer.
func testInputFlags(t testing.TB, allowDummyInputs bool, treeIndexes []*big.Int) *big.Int {
	t.Helper()
	flags, err := common.PackInputFlags(allowDummyInputs, treeIndexes)
	if err != nil {
		t.Fatalf("pack input flags: %v", err)
	}
	return flags
}

// inputTreeSlots reads back the slot every input selected.
func (a *testAssignment) inputTreeSlots() []*big.Int {
	out := make([]*big.Int, len(a.Inputs))
	for i := range a.Inputs {
		out[i] = spptest.AsBigInt(a.Inputs[i].TreeSlot)
	}
	return out
}

func (a *testAssignment) allowDummyInputs() bool {
	return spptest.AsBigInt(a.InputFlags).Bit(0) == 1
}

// setAllowDummyInputs rewrites InputFlags with a new policy bit, keeping every
// input's published tree index.
func setAllowDummyInputs(t testing.TB, a *testAssignment, allowDummyInputs bool) {
	t.Helper()
	a.InputFlags = testInputFlags(t, allowDummyInputs, a.inputTreeSlots())
}

// An input spent from a slot other than 0 proves against that slot's tree id
// and roots and publishes its index, so one transaction may consolidate across
// trees.
func TestCircuitAcceptsInputsFromSeveralTreeSlots(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	moveInputToSlot(t, assignment, 1, 1)

	if got, want := spptest.AsBigInt(assignment.InputFlags).Int64(), int64(17); got != want {
		t.Fatalf("input flags for slots [0 1] with the policy on: got %d want %d", got, want)
	}
	assert.SolvingSucceeded(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// The published index must equal the private selection, so a proof checked
// against one tree cannot be routed into another.
func TestCircuitRejectsInputFlagsTreeIndexMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	moveInputToSlot(t, assignment, 1, 1)

	// Publish slot 0 for input 1 while it still spends from slot 1, with a
	// public input hash consistent with the published flags.
	assignment.InputFlags = testInputFlags(t, true, singleTreeSlots(shape.NInputs))
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// A tree index above the published width is unreachable: ToBinary range-checks
// InputFlags to 1+TreeIndexBits*NInputs bits.
func TestCircuitRejectsInputFlagsWiderThanTheShape(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	width := uint(1 + TreeIndexBits*shape.NInputs)
	assignment.InputFlags = new(big.Int).SetBit(spptest.AsBigInt(assignment.InputFlags), int(width), 1)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// An index that names no published slot is rejected by SelectTreeSlot, so the
// packed form needs no separate range assertion.
func TestCircuitRejectsInputFlagsIndexOutsidePublishedSlots(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].TreeSlot = spptest.Fe(InputTrees)
	setAllowDummyInputs(t, assignment, true)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}
