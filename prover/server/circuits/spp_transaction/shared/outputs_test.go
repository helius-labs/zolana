package shared_test

import (
	"testing"
	. "zolana/prover/circuits/spp_transaction/shared"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func TestCircuitRejectsBadOutputHash(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Outputs[0].Hash = spptest.Fe(999)

	assert.SolvingFailed(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}
