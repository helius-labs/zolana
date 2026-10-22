package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type tinyCircuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable
}

func (c *tinyCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, api.Mul(c.Y, c.Y))
	return nil
}

// The transfer variant is read from the canonical file name while the
// HasCommitment header flag round-trips.
func TestReadSystemFromFileResolvesTransferVariant(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &tinyCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	cases := []struct {
		filename         string
		hasCommitment    bool
		wantConfidential bool
		want             CircuitType
	}{
		{"transfer_ring_2_4.key", false, true, TransferRingCircuitType},
		{"transfer_confidential_2_4.key", false, true, TransferConfidentialCircuitType},
		{"transfer_eddsa_ring_2_4.key", true, true, TransferAnonymousRingEddsaCircuitType},
	}

	// A parent directory named like another rail must not change the result.
	dir := filepath.Join(t.TempDir(), "ring-merge-transfer")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, tc := range cases {
		ps := &TransferProofSystem{
			NInputs:          2,
			NOutputs:         4,
			HasCommitment:    tc.hasCommitment,
			ProvingKey:       pk,
			VerifyingKey:     vk,
			ConstraintSystem: ccs,
		}
		path := filepath.Join(dir, tc.filename)
		file, err := os.Create(path)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := ps.WriteTo(file); err != nil {
			file.Close()
			t.Fatalf("write: %v", err)
		}
		file.Close()

		loaded, err := ReadSystemFromFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got, ok := loaded.(*TransferProofSystem)
		if !ok {
			t.Fatalf("loaded type = %T, want *TransferProofSystem", loaded)
		}
		if got.HasCommitment != tc.hasCommitment || got.Confidential != tc.wantConfidential {
			t.Fatalf("%s flags: got (commitment=%v conf=%v), want (commitment=%v conf=%v)",
				tc.filename, got.HasCommitment, got.Confidential, tc.hasCommitment, tc.wantConfidential)
		}
		if got.CircuitType != tc.want {
			t.Fatalf("%s circuit type: got %v, want %v", tc.filename, got.CircuitType, tc.want)
		}
	}
	// A canonical filename cannot reinterpret a key header for another shape.
	original, err := os.ReadFile(filepath.Join(dir, "transfer_ring_2_4.key"))
	if err != nil {
		t.Fatal(err)
	}
	wrongShape := filepath.Join(dir, "transfer_ring_4_2.key")
	if err := os.WriteFile(wrongShape, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSystemFromFile(wrongShape); err == nil || !strings.Contains(err.Error(), "header shape") {
		t.Fatalf("accepted a key under a different canonical shape: %v", err)
	}
}

// Unknown names and unsupported shapes fail before any file is loaded.
func TestReadSystemRejectsUnknownKeyNames(t *testing.T) {
	for _, file := range []string{"transfer_old_ring_2_4.key", "transfer_confidential_50_2.key"} {
		if _, err := ReadSystemFromFile(filepath.Join(t.TempDir(), file)); err == nil || !strings.Contains(err.Error(), "unsupported proving key") {
			t.Fatalf("%s: expected unsupported proving key, got %v", file, err)
		}
	}
}
