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

func TestLazyKeyManagerBuildsCustomRingKeyPaths(t *testing.T) {
	keysDir := filepath.Join("tmp", "proving-keys")
	manager := NewLazyKeyManager(keysDir, &DownloadConfig{})

	got := manager.determineRingKeyPath(CustomRingCircuitType, "transfer")
	want := filepath.Join(keysDir, "custom_ring_transfer.key")
	if got != want {
		t.Fatalf("path mismatch: got %q, want %q", got, want)
	}
}
