package common

import (
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"zolana/prover/prover/provingkeys"
)

func TestLazyKeyManagerBuildsTransferKeyPaths(t *testing.T) {
	keysDir := filepath.Join("tmp", "proving-keys")
	manager := NewLazyKeyManager(keysDir, &DownloadConfig{})

	tests := map[string]string{
		"transfer ring eddsa": manager.determineTransferKeyPath(TransferRingCircuitType, 2, 3),
		"transfer ring p256":  manager.determineTransferKeyPath(TransferP256RingCircuitType, 2, 3),
	}

	expected := map[string]string{
		// Key filenames mirror the verifying-key modules.
		"transfer ring eddsa": filepath.Join(keysDir, "transfer_ring_2_3.key"),
		"transfer ring p256":  filepath.Join(keysDir, "transfer_p256_ring_2_3.key"),
	}

	for name, got := range tests {
		if got != expected[name] {
			t.Fatalf("%s path mismatch: got %q, want %q", name, got, expected[name])
		}
	}
}

func TestLazyKeyManagerBuildsCustomRingKeyPaths(t *testing.T) {
	keysDir := filepath.Join("tmp", "proving-keys")
	manager := NewLazyKeyManager(keysDir, &DownloadConfig{})

	for circuitType, filename := range RingKeyFiles {
		got := manager.determineRingKeyPath(circuitType)
		want := filepath.Join(keysDir, filename)
		if got != want {
			t.Fatalf("%s path mismatch: got %q, want %q", circuitType, got, want)
		}
	}
	if got := manager.determineRingKeyPath(TransferRingCircuitType); got != "" {
		t.Fatalf("transfer ring resolved to the ring key %q", got)
	}
}

// A proof's path names its key file, so the prover must name every key the
// lockfile pins, and no other.
func TestKeyFilesAreTheLockfileKeys(t *testing.T) {
	manifest, err := provingkeys.Load()
	if err != nil {
		t.Fatal(err)
	}
	pinned := make([]string, 0, len(manifest.Keys))
	for name := range manifest.Keys {
		pinned = append(pinned, name)
	}
	sort.Strings(pinned)
	if got := KeyFiles(); !slices.Equal(got, pinned) {
		t.Fatalf("key files %v, lockfile %v", got, pinned)
	}
}

func TestKeyFileIsEmptyForAnUnsupportedShape(t *testing.T) {
	for name, file := range map[string]string{
		"transfer 6x6":          TransferKeyFile(TransferConfidentialCircuitType, 6, 6),
		"ring authority 2x3":    TransferKeyFile(TransferRingAuthorityCircuitType, 2, 3),
		"merge 8x2":             TransferKeyFile(MergeCircuitType, 8, 2),
		"address append 40x100": BatchKeyFile(BatchAddressAppendCircuitType, 40, 100),
		"transfer as a batch":   BatchKeyFile(TransferConfidentialCircuitType, 40, 10),
		"unknown custom ring":   RingKeyFile("custom-ring-unknown"),
		"transfer as ring":      RingKeyFile(TransferConfidentialCircuitType),
	} {
		if file != "" {
			t.Errorf("%s: got %q", name, file)
		}
	}
}
