package common

import (
	"path/filepath"
	"testing"
)

func TestLazyKeyManagerBuildsTransferKeyPaths(t *testing.T) {
	keysDir := filepath.Join("tmp", "proving-keys")
	manager := NewLazyKeyManager(keysDir, &DownloadConfig{})

	tests := map[string]string{
		"transfer eddsa": manager.determineTransferKeyPath(TransferCircuitType, 2, 3),
		"transfer p256":  manager.determineTransferKeyPath(TransferP256CircuitType, 2, 3),
	}

	expected := map[string]string{
		// Key filenames mirror the verifying-key modules: transfer (eddsa) /
		// transfer_p256 (p256).
		"transfer eddsa": filepath.Join(keysDir, "transfer_2_3.key"),
		"transfer p256":  filepath.Join(keysDir, "transfer_p256_2_3.key"),
	}

	for name, got := range tests {
		if got != expected[name] {
			t.Fatalf("%s path mismatch: got %q, want %q", name, got, expected[name])
		}
	}
}
