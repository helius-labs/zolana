package common

import (
	"path/filepath"
	"testing"
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

// An unsupported shape must be rejected before the loader touches the disk.
// Otherwise a caller enumerates distinct tuples, each taking the loading lock,
// and each key that does load stays in a map nothing evicts.
func TestLazyKeyManagerGatesRecursiveShapes(t *testing.T) {
	keysDir := filepath.Join("tmp", "proving-keys")
	manager := NewLazyKeyManager(keysDir, &DownloadConfig{})

	if got := manager.determineMergeChainKeyPath([]uint32{2, 1}, "2_1"); got != filepath.Join(keysDir, "merge-chain_2_1.key") {
		t.Fatalf("supported merge chain path mismatch: got %q", got)
	}
	if got := manager.determineNullifierFoldKeyPath(40, 10, 2); got != filepath.Join(keysDir, "nullifier-fold_40_10_r2.key") {
		t.Fatalf("supported nullifier fold path mismatch: got %q", got)
	}

	if got := manager.determineMergeChainKeyPath([]uint32{7, 3, 1}, "7_3_1"); got != "" {
		t.Errorf("unsupported merge chain shape mapped to %q", got)
	}
	if got := manager.determineNullifierFoldKeyPath(40, 10, 7); got != "" {
		t.Errorf("unsupported fold run mapped to %q", got)
	}

	if _, err := manager.GetMergeChainSystem([]uint32{1, 2, 3, 4, 5, 6, 7, 8, 9}); err == nil {
		t.Error("expected an unsupported merge chain shape to be rejected")
	}
	if _, err := manager.GetNullifierFoldSystem(40, 250, 2); err == nil {
		t.Error("expected an unsupported fold shape to be rejected")
	}
}
