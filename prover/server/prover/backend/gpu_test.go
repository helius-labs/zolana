//go:build linux && amd64 && cgo && aeglos

package backend

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/std"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"zolana/prover/prover/common"
	"zolana/prover/prover/provingkeys"
)

func TestGPUBackendTransfer(t *testing.T) {
	directory := os.Getenv("AEGLOS_TEST_KEYS")
	if directory == "" {
		t.Skip("AEGLOS_TEST_KEYS is unset")
	}
	const name = "transfer_ring_1_2.key"
	manifest, err := provingkeys.Load()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, name)
	keyFile, err := os.Open(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer keyFile.Close()
	digest := sha256.New()
	size, readErr := io.Copy(digest, keyFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	expected := manifest.Keys[name]
	if fmt.Sprintf("%x", digest.Sum(nil)) != expected.Sha256 || size != expected.Size {
		t.Fatal("key digest mismatch")
	}
	if _, err := keyFile.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	var system common.TransferProofSystem
	if _, err := system.UnsafeReadFrom(keyFile); err != nil {
		t.Fatal(err)
	}
	full, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.Open(filepath.Join(os.Getenv("AEGLOS_TEST_FIXTURES"), name+".0.witness"))
	if err != nil {
		t.Fatal(err)
	}
	_, readErr = full.ReadFrom(fixture)
	closeErr := fixture.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	std.RegisterHints()
	resetBackend(t)
	t.Setenv("PROVER_BACKEND", "aeglos")
	if err = Initialize(); err != nil {
		t.Fatal(err)
	}
	before := testutil.ToFloat64(gpuCache.WithLabelValues("miss"))
	proof, err := Prove(system.ConstraintSystem, system.ProvingKey, full)
	if err != nil {
		t.Fatal(err)
	}
	public, err := full.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err = groth16.Verify(proof, system.VerifyingKey, public); err != nil {
		t.Fatal(err)
	}
	if testutil.ToFloat64(gpuCache.WithLabelValues("miss")) != before+1 {
		t.Fatal("cache metric did not observe proof")
	}
	if testutil.ToFloat64(gpuMemory) <= 0 || testutil.ToFloat64(gpuKeys) != 1 {
		t.Fatal("GPU resources not observed")
	}
}
