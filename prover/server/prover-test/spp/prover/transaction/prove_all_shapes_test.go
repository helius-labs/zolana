package transaction

import (
	"fmt"
	"os"
	"testing"

	"zolana/prover/prover-test/spp/protocol"
)

// sweepShapes are the narrowest and widest shape of every output column. Each
// shape runs an independent groth16 setup, and the 51-input shape alone is over
// a million constraints, so the full sweep is opt-in with SPP_PROVE_ALL_SHAPES=1.
var sweepShapes = []protocol.Shape{
	{NInputs: 1, NOutputs: 2},
	{NInputs: 51, NOutputs: 2},
	{NInputs: 1, NOutputs: 4},
	{NInputs: 24, NOutputs: 4},
	{NInputs: 1, NOutputs: 8},
	{NInputs: 16, NOutputs: 8},
	{NInputs: 1, NOutputs: 16},
	{NInputs: 8, NOutputs: 16},
}

// TestProveAndVerifyEveryShape exercises the full compile -> setup -> witness ->
// prove -> verify pipeline for the per-shape proving systems the committed
// verifying keys are exported from. It is skipped under -short.
func TestProveAndVerifyEveryShape(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: per-shape groth16 setup + prove")
	}
	shapes := sweepShapes
	if os.Getenv("SPP_PROVE_ALL_SHAPES") == "1" {
		shapes = protocol.SupportedShapes
	}
	for _, shape := range shapes {
		name := fmt.Sprintf("inputs_%d_outputs_%d", shape.NInputs, shape.NOutputs)
		t.Run(name, func(t *testing.T) {
			if err := shape.Validate(); err != nil {
				t.Fatal(err)
			}
			tx, payerHash, err := benchmarkTransaction(shape)
			if err != nil {
				t.Fatalf("build transaction: %v", err)
			}
			ps, err := Setup(shape)
			if err != nil {
				t.Fatalf("setup: %v", err)
			}
			built, err := buildProofAssignment(shape, tx, payerHash, proofBuildOptions{})
			if err != nil {
				t.Fatalf("build assignment: %v", err)
			}
			proof, err := Prove(ps, built.witness)
			if err != nil {
				t.Fatalf("prove: %v", err)
			}
			if err := Verify(ps, built.witness, proof); err != nil {
				t.Fatalf("verify: %v", err)
			}
		})
	}
}
