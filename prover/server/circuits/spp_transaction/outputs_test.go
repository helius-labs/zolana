package transaction_test

import (
	"testing"
	. "rings/prover/circuits/spp_transaction"

	"rings/prover/prover-test/spp/protocol"
	"rings/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func TestCircuitRejectsBadOutputHash(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Outputs[0].Hash = spptest.Fe(999)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}
