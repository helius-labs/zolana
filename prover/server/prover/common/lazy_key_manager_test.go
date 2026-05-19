package common

import (
	"path/filepath"
	"testing"
)

func TestLazyKeyManagerBuildsKeyPathsWithoutTrailingSeparator(t *testing.T) {
	keysDir := filepath.Join("tmp", "proving-keys")
	manager := NewLazyKeyManager(keysDir, &DownloadConfig{})

	tests := map[string]string{
		"v1 inclusion": manager.determineMerkleKeyPath(26, 1, 0, 0, 1),
		"v2 combined":  manager.determineMerkleKeyPath(32, 2, 40, 1, 2),
		"batch append": manager.determineBatchKeyPath(BatchAppendCircuitType, 32, 10),
		"specific":     manager.tryParseSpecificConfig("v1_inclusion_26_1"),
	}

	expected := map[string]string{
		"v1 inclusion": filepath.Join(keysDir, "v1_inclusion_26_1.key"),
		"v2 combined":  filepath.Join(keysDir, "v2_combined_32_40_2_1.key"),
		"batch append": filepath.Join(keysDir, "batch_append_32_10.key"),
		"specific":     filepath.Join(keysDir, "v1_inclusion_26_1.key"),
	}

	for name, got := range tests {
		if got != expected[name] {
			t.Fatalf("%s path mismatch: got %q, want %q", name, got, expected[name])
		}
	}
}
