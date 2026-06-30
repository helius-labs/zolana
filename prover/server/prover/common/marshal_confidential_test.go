package common

import (
	"os"
	"path/filepath"
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

// RequiresP256 round-trips through the key header; the confidentiality mode is
// not in the header (kept stable for existing keys/VKs) and is read from the
// canonical file name. ReadSystemFromFile must combine both into the right
// CircuitType for all four variants. The keys are irrelevant here, so one trivial
// setup is reused across the matrix.
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
		requiresP256     bool
		wantConfidential bool
		want             CircuitType
	}{
		{"transfer_zone_2_3.key", false, false, TransferZoneCircuitType},
		{"transfer_p256_zone_2_3.key", true, false, TransferP256ZoneCircuitType},
		{"transfer_confidential_2_3.key", false, true, TransferConfidentialCircuitType},
		{"transfer_p256_confidential_2_3.key", true, true, TransferP256ConfidentialCircuitType},
	}

	dir := t.TempDir()
	for _, tc := range cases {
		ps := &TransferProofSystem{
			NInputs:          2,
			NOutputs:         3,
			RequiresP256:     tc.requiresP256,
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
		if got.RequiresP256 != tc.requiresP256 || got.Confidential != tc.wantConfidential {
			t.Fatalf("%s flags: got (p256=%v conf=%v), want (p256=%v conf=%v)",
				tc.filename, got.RequiresP256, got.Confidential, tc.requiresP256, tc.wantConfidential)
		}
		if got.CircuitType != tc.want {
			t.Fatalf("%s circuit type: got %v, want %v", tc.filename, got.CircuitType, tc.want)
		}
	}
}
