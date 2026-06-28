package transaction

import (
	"fmt"
	"testing"

	"zolana/prover/prover-test/spp/protocol"
)

// TestProveAndVerifyEveryShape exercises the full compile -> setup -> witness ->
// prove -> verify pipeline for every supported shape on both ownership rails.
// Before this, proof generation was only tested at the (2,3) shape the
// high-level transaction builder emits; the other shapes' per-shape proving
// systems (the ones the committed verifying keys are exported from) had no
// end-to-end coverage. Each shape runs an independent groth16 setup, so the
// sweep is slow (the P256 rail dominates) and is skipped under -short.
func TestProveAndVerifyEveryShape(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: per-shape groth16 setup + prove for every shape and rail")
	}
	rails := []struct {
		name string
		p256 bool
	}{
		{name: "solana", p256: false},
		{name: "p256", p256: true},
	}
	for _, rail := range rails {
		for _, shape := range protocol.SupportedShapes {
			name := fmt.Sprintf("%s/inputs_%d_outputs_%d", rail.name, shape.NInputs, shape.NOutputs)
			t.Run(name, func(t *testing.T) {
				tx, payerHash, err := benchmarkTransaction(shape, rail.p256)
				if err != nil {
					t.Fatalf("build transaction: %v", err)
				}
				if TransactionRequiresP256(tx) != rail.p256 {
					t.Fatalf("rail mismatch: requiresP256=%v want %v", TransactionRequiresP256(tx), rail.p256)
				}
				ps, err := Setup(shape, rail.p256)
				if err != nil {
					t.Fatalf("setup: %v", err)
				}
				built, err := buildProofAssignment(shape, tx, payerHash, proofBuildOptions{})
				if err != nil {
					t.Fatalf("build assignment: %v", err)
				}
				proof, err := Prove(ps, built.circuit)
				if err != nil {
					t.Fatalf("prove: %v", err)
				}
				if err := Verify(ps, built.circuit, proof); err != nil {
					t.Fatalf("verify: %v", err)
				}
			})
		}
	}
}
