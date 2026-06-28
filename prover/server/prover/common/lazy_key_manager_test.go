package common

import (
	"path/filepath"
	"testing"
)

func TestLazyKeyManagerBuildsTransferKeyPaths(t *testing.T) {
	keysDir := filepath.Join("tmp", "proving-keys")
	manager := NewLazyKeyManager(keysDir, &DownloadConfig{})

	tests := map[string]string{
		"transfer zone eddsa": manager.determineTransferKeyPath(TransferZoneCircuitType, 2, 3),
		"transfer zone p256":  manager.determineTransferKeyPath(TransferP256ZoneCircuitType, 2, 3),
	}

	expected := map[string]string{
		// Key filenames mirror the verifying-key modules: transfer_zone (eddsa) /
		// transfer_p256_zone (p256).
		"transfer zone eddsa": filepath.Join(keysDir, "transfer_zone_2_3.key"),
		"transfer zone p256":  filepath.Join(keysDir, "transfer_p256_zone_2_3.key"),
	}

	for name, got := range tests {
		if got != expected[name] {
			t.Fatalf("%s path mismatch: got %q, want %q", name, got, expected[name])
		}
	}
}
