package merge_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	merge "zolana/prover/circuits/spp_merge"
)

// TestMergeCircuitCompiles is a smoke test: it confirms the 8-in / 1-out merge
// circuit compiles to R1CS. It runs emulated-P256 scalar multiplication
// (tx_viewing_pk derivation and the owner ECDH), so it is large.
func TestMergeCircuitCompiles(t *testing.T) {
	circuit := merge.NewMergeCircuit()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatalf("compile merge circuit: %v", err)
	}
	t.Logf("merge 8x1 R1CS constraints: %d", cs.GetNbConstraints())
}
