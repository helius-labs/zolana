package transaction

import (
	"fmt"
	"testing"

	"zolana/prover/prover-test/spp/protocol"
)

// TestProveAndVerifyEveryShape exercises the full compile -> setup -> witness ->
// prove -> verify pipeline for every supported shape.
// Before this, proof generation was only tested at the (2,3) shape the
// high-level transaction builder emits; the other shapes' per-shape proving
// systems (the ones the committed verifying keys are exported from) had no
// end-to-end coverage. Each shape runs an independent groth16 setup, so the
// sweep is slow and is skipped under -short.
func TestProveAndVerifyEveryShape(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: per-shape groth16 setup + prove for every shape")
	}
	for _, shape := range protocol.SupportedShapes {
		name := fmt.Sprintf("inputs_%d_outputs_%d", shape.NInputs, shape.NOutputs)
		t.Run(name, func(t *testing.T) {
			tx, payerHash, err := sampleTransactionRequest(shape)
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
