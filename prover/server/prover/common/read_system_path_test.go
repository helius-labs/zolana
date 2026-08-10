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

type singleConstraint struct {
	X frontend.Variable `gnark:",public"`
}

func (c *singleConstraint) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), api.Mul(c.X, c.X))
	return nil
}

// The header must come from the file name, not the path. A directory named
// after another circuit family must not pick that family's header.
func TestReadSystemFromFileIgnoresDirectoryNames(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &singleConstraint{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	ps := &TransferProofSystem{
		NInputs:          2,
		NOutputs:         3,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}

	dir := filepath.Join(t.TempDir(), "aggregate-checkout")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "transfer_ring_2_3.key")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ps.WriteTo(file); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	system, err := ReadSystemFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	read, ok := system.(*TransferProofSystem)
	if !ok {
		t.Fatalf("read as %T, want a transfer system", system)
	}
	if read.CircuitType != TransferRingCircuitType {
		t.Errorf("circuit type is %s, want %s", read.CircuitType, TransferRingCircuitType)
	}
	if read.NInputs != 2 || read.NOutputs != 3 {
		t.Errorf("shape is %dx%d, want 2x3", read.NInputs, read.NOutputs)
	}
}
