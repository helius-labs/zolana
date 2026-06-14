package transaction_test

import (
	"testing"
	. "zolana/prover/circuits/spp_transaction"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

// The owner hash binds OwnerKeyHash and NullifierPk (OwnerHashGadget in
// utxo.go); a UTXO whose committed owner does not match that preimage fails the
// owner binding in constrainInput.
func TestCircuitRejectsOwnerHashPreimageMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].Utxo.Owner = spptest.Fe(12345)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}
