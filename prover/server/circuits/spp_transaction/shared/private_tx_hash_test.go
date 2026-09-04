package shared_test

import (
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

// TestCircuitRejectsZeroPrivateTxBlinding pins the non-zero guard. Zero is the
// value a witness lands on when a client forgets the field, and a blinding the
// attacker knows leaves the hash computable from public data, so it must fail
// to prove rather than silently produce a linkable transaction.
func TestCircuitRejectsZeroPrivateTxBlinding(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.PrivateTxBlinding = spptest.Fe(0)
	rebuildAfterOwnerChange(t, assignment)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// TestCircuitRejectsWrongPrivateTxBlinding covers the other half: a non-zero
// blinding that does not match the published private_tx_hash.
func TestCircuitRejectsWrongPrivateTxBlinding(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.PrivateTxBlinding = spptest.Fe(0xB11E)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}
