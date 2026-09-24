package common

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func strPtr(s string) *string { return &s }

func TestProvingKeysReportCoversPinnedLoadedAndLocalKeys(t *testing.T) {
	pinnedOnDisk := sha256.Sum256([]byte("transfer_ring_2_2"))
	pinnedMissing := sha256.Sum256([]byte("merge_36_1"))
	useTestManifest(t, &lockManifest{
		Prefix: "proving-keys/test",
		Keys: map[string]lockEntry{
			"transfer_ring_2_2.key": {Sha256: hex.EncodeToString(pinnedOnDisk[:]), Size: 1},
			"merge_36_1.key":        {Sha256: hex.EncodeToString(pinnedMissing[:]), Size: 1},
		},
	})
	keysDir := t.TempDir()
	for _, name := range []string{"transfer_ring_2_2.key", "local_only.key", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(keysDir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	manager := NewLazyKeyManager(keysDir, &DownloadConfig{AutoDownload: false})
	loaded := sha256.Sum256([]byte("bytes actually read"))
	manager.loadedDigests["transfer_ring_2_2.key"] = loaded

	report, err := manager.ProvingKeysReport()
	if err != nil {
		t.Fatalf("ProvingKeysReport: %v", err)
	}
	want := &ProvingKeysReport{
		Prefix: "proving-keys/test",
		Keys: []ProvingKeyStatus{
			{Name: "local_only.key", Available: true},
			{Name: "merge_36_1.key", ExpectedSha256: strPtr(hex.EncodeToString(pinnedMissing[:])), Available: false},
			{
				Name:           "transfer_ring_2_2.key",
				ExpectedSha256: strPtr(hex.EncodeToString(pinnedOnDisk[:])),
				LoadedSha256:   strPtr(hex.EncodeToString(loaded[:])),
				Available:      true,
			},
		},
	}
	if !reflect.DeepEqual(report, want) {
		t.Fatalf("report = %+v, want %+v", report, want)
	}
}

func TestProvingKeysReportPinnedKeyAvailableWithAutoDownload(t *testing.T) {
	pinned := sha256.Sum256([]byte("merge_8_1"))
	release := sha256.Sum256([]byte("custom_ring_policy"))
	useTestManifest(t, &lockManifest{
		Prefix: "proving-keys/test",
		Keys: map[string]lockEntry{
			"merge_8_1.key": {Sha256: hex.EncodeToString(pinned[:]), Size: 1},
			// Release assets are never auto-downloaded, so they stay unavailable.
			"custom_ring_policy.key": {Sha256: hex.EncodeToString(release[:]), Size: 1, Source: "release"},
		},
	})
	manager := NewLazyKeyManager(t.TempDir(), &DownloadConfig{AutoDownload: true})

	report, err := manager.ProvingKeysReport()
	if err != nil {
		t.Fatalf("ProvingKeysReport: %v", err)
	}
	want := []ProvingKeyStatus{
		{Name: "custom_ring_policy.key", ExpectedSha256: strPtr(hex.EncodeToString(release[:])), Available: false},
		{Name: "merge_8_1.key", ExpectedSha256: strPtr(hex.EncodeToString(pinned[:])), Available: true},
	}
	if !reflect.DeepEqual(report.Keys, want) {
		t.Fatalf("keys = %+v, want %+v", report.Keys, want)
	}
}
