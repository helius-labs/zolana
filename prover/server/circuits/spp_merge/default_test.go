package merge_test

import (
	"strings"
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

func TestMergeCircuitRejectsMalformedLayout(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*merge.Circuit)
		want   string
	}{
		{
			name: "configured input count",
			mutate: func(c *merge.Circuit) {
				c.NumInputs--
			},
			want: "NumInputs must be",
		},
		{
			name: "input count",
			mutate: func(c *merge.Circuit) {
				c.Inputs = c.Inputs[:len(c.Inputs)-1]
			},
			want: "input count mismatch",
		},
		{
			name: "nullifier count",
			mutate: func(c *merge.Circuit) {
				c.Nullifiers = c.Nullifiers[:len(c.Nullifiers)-1]
			},
			want: "nullifier count mismatch",
		},
		{
			name: "utxo root count",
			mutate: func(c *merge.Circuit) {
				c.UtxoTreeRoots = c.UtxoTreeRoots[:len(c.UtxoTreeRoots)-1]
			},
			want: "utxo tree root count mismatch",
		},
		{
			name: "nullifier root count",
			mutate: func(c *merge.Circuit) {
				c.NullifierTreeRoots = c.NullifierTreeRoots[:len(c.NullifierTreeRoots)-1]
			},
			want: "nullifier tree root count mismatch",
		},
		{
			name: "state path height",
			mutate: func(c *merge.Circuit) {
				path := c.Inputs[0].StatePathElements
				c.Inputs[0].StatePathElements = path[:len(path)-1]
			},
			want: "state path height",
		},
		{
			name: "nullifier path height",
			mutate: func(c *merge.Circuit) {
				path := c.Inputs[0].NullifierLowPathElements
				c.Inputs[0].NullifierLowPathElements = path[:len(path)-1]
			},
			want: "nullifier path height",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			circuit := merge.NewMergeCircuit()
			tc.mutate(circuit)
			_, err := frontend.Compile(
				ecc.BN254.ScalarField(),
				r1cs.NewBuilder,
				circuit,
				frontend.WithCompressThreshold(300),
			)
			if err == nil {
				t.Fatal("expected malformed layout to fail compilation")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unexpected error: got %q want substring %q", err, tc.want)
			}
		})
	}
}
