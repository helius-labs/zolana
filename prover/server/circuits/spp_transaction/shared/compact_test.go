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

// Compact padding: a padding slot publishes 0 as its nullifier or output hash,
// SPP leaves it out of the instruction and creates nothing for it (spec:
// Compact padding). The circuit accepts a zero only on a dummy slot, never in
// input slot 0, and pins a compact output's published owner tag to 0.

// padWithCompactInputs keeps the spend in slot 0, turns every later input slot
// into compact padding, and splits slot 0's amount over the outputs.
func padWithCompactInputs(t testing.TB, assignment *testAssignment) {
	t.Helper()
	for i := 1; i < len(assignment.Inputs); i++ {
		in := &assignment.Inputs[i]
		in.Utxo.Domain = spptest.Fe(DummyDomain)
		in.Utxo.Owner = spptest.Fe(0)
		in.Utxo.Asset = spptest.Fe(0)
		in.Utxo.Amount = spptest.Fe(0)
		in.OwnerPkHash = spptest.Fe(0)
		in.NullifierSecret = spptest.Fe(0)
		in.Nullifier = spptest.Fe(0)
	}
	remaining := spptest.AsBigInt(assignment.Inputs[0].Utxo.Amount).Int64()
	for i := range assignment.Outputs {
		amount := remaining / int64(len(assignment.Outputs)-i)
		remaining -= amount
		assignment.Outputs[i].Utxo.Amount = spptest.Fe(amount)
	}
	inputHashes := make([]*big.Int, len(assignment.Inputs))
	for i := range inputHashes {
		inputHashes[i] = big.NewInt(0)
	}
	inputHashes[0] = testUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[0].Utxo), assignment.inputTreeID(0))
	refreshNullifierAttackHashes(t, assignment, inputHashes)
}

// The {3,3} shape carries two compact slots, so it also covers the
// distinctness exemption for a pair of zeros.
func TestCompactInputPaddingSolves(t *testing.T) {
	assert := test.NewAssert(t)
	for _, shape := range []protocol.Shape{{NInputs: 2, NOutputs: 2}, {NInputs: 3, NOutputs: 3}} {
		circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
		assignment := buildCircuitAssignment(t, shape)
		padWithCompactInputs(t, assignment)
		assert.SolvingSucceeded(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
	}
}

func TestCompactInputPaddingSolvesOnDefaultRing(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	assignment := buildDefaultRingEddsaOnlyAssignment(t, shape)
	padWithCompactInputs(t, assignment)
	refreshDefaultRingPublicInputHash(t, assignment)
	assert.SolvingSucceeded(
		MustNewDefaultRingEddsaOnlyCircuit(Shape(shape)),
		asDefaultRingEddsaOnly(assignment),
		test.WithCurves(ecc.BN254),
	)
}

func TestCompactInputPaddingSolvesOnP256(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	padWithCompactInputs(t, assignment)
	authorization := authorizeP256(t, assignment, owner, owner)
	assert.SolvingSucceeded(
		MustNewCustomRingP256Circuit(Shape(shape)),
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// Compact padding inserts no nullifier, so the tree-capacity gate that forbids
// random dummies does not apply to it.
func TestCompactInputPaddingSolvesWhenDummyInputsDisallowed(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	padWithCompactInputs(t, assignment)
	setAllowDummyInputs(t, assignment, false)
	refreshPublicInputHash(t, assignment)
	assert.SolvingSucceeded(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// A spent UTXO that publishes nullifier 0 would skip its nullifier insertion,
// so the zero must force the slot to be a dummy.
func TestCompactNullifierRejectedOnSpentInput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assert.SolvingSucceeded(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))

	assignment.Inputs[1].Nullifier = spptest.Fe(0)
	refreshPublicInputHash(t, assignment)
	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// An address slot's nullifier is the address SPP inserts, so it cannot be 0.
// The address sits in slot 1, so the slot-0 rule cannot be what rejects it.
func TestCompactNullifierRejectedOnAddressSlot(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	makeAddressSlot(t, assignment, 1, addressOwnerPkHash(t), spptest.Fe(0xABCDEF))
	for i := range assignment.Outputs {
		assignment.Outputs[i].Utxo.Amount = spptest.Fe(50)
	}
	finalizeAddressAssignment(t, assignment, true, false)
	assert.SolvingSucceeded(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))

	assignment.Inputs[1].Nullifier = spptest.Fe(0)
	finalizeAddressAssignment(t, assignment, true, false)
	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// compactOutputAssignment pads a {1,2} transfer with a compact output: its
// published hash and owner tag are 0.
func compactOutputAssignment(t testing.TB) *testAssignment {
	t.Helper()
	assignment := dummyOutputAssignment(t, protocol.Shape{NInputs: 1, NOutputs: 2})
	tagDummyOutput(t, assignment, 0)
	assignment.Outputs[1].Hash = spptest.Fe(0)
	return assignment
}

func TestCompactOutputSolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}

	assignment := compactOutputAssignment(t)
	refreshDefaultRingPublicInputHash(t, assignment)
	assert.SolvingSucceeded(
		MustNewDefaultRingEddsaOnlyCircuit(Shape(shape)),
		asDefaultRingEddsaOnly(assignment),
		test.WithCurves(ecc.BN254),
	)

	assignment = compactOutputAssignment(t)
	refreshPublicInputHash(t, assignment)
	assert.SolvingSucceeded(
		MustNewCustomRingEddsaOnlyCircuit(Shape(shape)),
		asCustomRingEddsaOnly(assignment),
		test.WithCurves(ecc.BN254),
	)

	owner := spptest.FixedP256Key(t, 11)
	assignment, _ = p256DummyOutputAssignment(t, shape, owner, false, 0)
	assignment.Outputs[1].Hash = spptest.Fe(0)
	authorization := authorizeP256(t, assignment, owner, owner)
	assert.SolvingSucceeded(
		MustNewCustomRingP256Circuit(Shape(shape)),
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// Each tag below is accepted on a dummy output that publishes its hash; on a
// compact output SPP pads the owner tag chain with 0, so any other tag fails.
func TestCompactOutputRejectsNonzeroTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	withSignerTag := func() *testAssignment {
		assignment := compactOutputAssignment(t)
		tagDummyOutput(t, assignment, assignment.Inputs[0].OwnerPkHash)
		return assignment
	}

	assignment := withSignerTag()
	refreshDefaultRingPublicInputHash(t, assignment)
	assert.SolvingFailed(
		MustNewDefaultRingEddsaOnlyCircuit(Shape(shape)),
		asDefaultRingEddsaOnly(assignment),
		test.WithCurves(ecc.BN254),
	)

	assignment = withSignerTag()
	refreshPublicInputHash(t, assignment)
	assert.SolvingFailed(
		MustNewCustomRingEddsaOnlyCircuit(Shape(shape)),
		asCustomRingEddsaOnly(assignment),
		test.WithCurves(ecc.BN254),
	)

	owner := spptest.FixedP256Key(t, 11)
	var tag frontend.Variable = p256OwnerPkHash(t, owner)
	assignment, _ = p256DummyOutputAssignment(t, shape, owner, false, tag)
	assignment.Outputs[1].Hash = spptest.Fe(0)
	authorization := authorizeP256(t, assignment, owner, owner)
	assert.SolvingFailed(
		MustNewCustomRingP256Circuit(Shape(shape)),
		asCustomRingP256(assignment, authorization),
		test.WithCurves(ecc.BN254),
	)
}

// A real output that publishes hash 0 would skip its tree append. The ring
// authority rail binds no output owner tags, and the private tx hash takes the
// computed output hash, so the compact-output dummy rule is the only rejecting
// constraint here.
func TestCompactHashRejectedOnRealOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingAuthorityCircuit(Shape(shape))
	assignment := buildRingAuthorityAssignment(t, shape)
	assert.SolvingSucceeded(circuit, asCustomRingAuthority(assignment), test.WithCurves(ecc.BN254))

	assignment.Outputs[1].Hash = spptest.Fe(0)
	refreshRingAuthorityPublicInputHash(t, assignment)
	assert.SolvingFailed(circuit, asCustomRingAuthority(assignment), test.WithCurves(ecc.BN254))
}
