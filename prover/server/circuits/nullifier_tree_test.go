package circuits

import (
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func newAddressAppendTemplate(treeHeight, batchSize uint32) BatchAddressTreeAppendCircuit {
	circuit := BatchAddressTreeAppendCircuit{
		BatchSize:            batchSize,
		TreeHeight:           treeHeight,
		LowElementValues:     make([]frontend.Variable, batchSize),
		LowElementNextValues: make([]frontend.Variable, batchSize),
		LowElementIndices:    make([]frontend.Variable, batchSize),
		LowElementProofs:     make([][]frontend.Variable, batchSize),
		NewElementValues:     make([]frontend.Variable, batchSize),
		NewElementProofs:     make([][]frontend.Variable, batchSize),
	}
	for i := range circuit.LowElementProofs {
		circuit.LowElementProofs[i] = make([]frontend.Variable, treeHeight)
		circuit.NewElementProofs[i] = make([]frontend.Variable, treeHeight)
	}
	return circuit
}

func TestBatchAddressTreeAppendValidateLayout(t *testing.T) {
	const treeHeight, batchSize = 4, 2

	wellFormed := newAddressAppendTemplate(treeHeight, batchSize)
	if err := wellFormed.ValidateLayout(); err != nil {
		t.Fatalf("well-formed template rejected: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(c *BatchAddressTreeAppendCircuit)
		wantErr string
	}{
		{
			name:    "zero batch size",
			mutate:  func(c *BatchAddressTreeAppendCircuit) { c.BatchSize = 0 },
			wantErr: "BatchSize must be >= 1",
		},
		{
			name:    "zero tree height",
			mutate:  func(c *BatchAddressTreeAppendCircuit) { c.TreeHeight = 0 },
			wantErr: "TreeHeight must be >= 1",
		},
		{
			name: "new element values longer than batch",
			mutate: func(c *BatchAddressTreeAppendCircuit) {
				c.NewElementValues = append(c.NewElementValues, frontend.Variable(0))
			},
			wantErr: "new element value count mismatch: got 3 want 2",
		},
		{
			name: "new element values shorter than batch",
			mutate: func(c *BatchAddressTreeAppendCircuit) {
				c.NewElementValues = c.NewElementValues[:1]
			},
			wantErr: "new element value count mismatch: got 1 want 2",
		},
		{
			name: "low element values shorter than batch",
			mutate: func(c *BatchAddressTreeAppendCircuit) {
				c.LowElementValues = c.LowElementValues[:1]
			},
			wantErr: "low element value count mismatch: got 1 want 2",
		},
		{
			name: "low element next values shorter than batch",
			mutate: func(c *BatchAddressTreeAppendCircuit) {
				c.LowElementNextValues = c.LowElementNextValues[:1]
			},
			wantErr: "low element next value count mismatch: got 1 want 2",
		},
		{
			name: "low element indices shorter than batch",
			mutate: func(c *BatchAddressTreeAppendCircuit) {
				c.LowElementIndices = c.LowElementIndices[:1]
			},
			wantErr: "low element index count mismatch: got 1 want 2",
		},
		{
			name: "low element proofs shorter than batch",
			mutate: func(c *BatchAddressTreeAppendCircuit) {
				c.LowElementProofs = c.LowElementProofs[:1]
			},
			wantErr: "low element proof count mismatch: got 1 want 2",
		},
		{
			name: "new element proofs shorter than batch",
			mutate: func(c *BatchAddressTreeAppendCircuit) {
				c.NewElementProofs = c.NewElementProofs[:1]
			},
			wantErr: "new element proof count mismatch: got 1 want 2",
		},
		{
			name: "low element proof row wrong height",
			mutate: func(c *BatchAddressTreeAppendCircuit) {
				c.LowElementProofs[1] = c.LowElementProofs[1][:treeHeight-1]
			},
			wantErr: "low element proof 1 height: got 3 want 4",
		},
		{
			name: "new element proof row wrong height",
			mutate: func(c *BatchAddressTreeAppendCircuit) {
				c.NewElementProofs[0] = append(c.NewElementProofs[0], frontend.Variable(0))
			},
			wantErr: "new element proof 0 height: got 5 want 4",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			circuit := newAddressAppendTemplate(treeHeight, batchSize)
			tc.mutate(&circuit)
			err := circuit.ValidateLayout()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// A template whose hashchain covers more elements than the update loop inserts
// must fail to compile, including one built directly rather than through the
// prover constructors.
func TestBatchAddressTreeAppendCompileRejectsOversizedNewElements(t *testing.T) {
	circuit := newAddressAppendTemplate(4, 2)
	circuit.NewElementValues = append(circuit.NewElementValues, frontend.Variable(0))

	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err == nil {
		t.Fatal("expected compile to fail for oversized NewElementValues")
	}
	if !strings.Contains(err.Error(), "new element value count mismatch: got 3 want 2") {
		t.Fatalf("unexpected compile error: %v", err)
	}
}

func TestBatchAddressTreeAppendCompilesWellFormedTemplate(t *testing.T) {
	circuit := newAddressAppendTemplate(4, 2)
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit); err != nil {
		t.Fatalf("well-formed template failed to compile: %v", err)
	}
}
