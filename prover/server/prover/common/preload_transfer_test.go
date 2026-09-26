package common

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRingPreloadRequiresSelectedKey(t *testing.T) {
	for _, circuit := range []CircuitType{CustomRingBaseCircuitType, CustomRingPolicyCircuitType} {
		t.Run(string(circuit), func(t *testing.T) {
			manager := NewLazyKeyManager(t.TempDir(), &DownloadConfig{AutoDownload: false})
			err := manager.PreloadCircuits([]string{string(circuit)})
			if err == nil || !strings.Contains(err.Error(), manager.determineRingKeyPath(circuit)) {
				t.Fatalf("selected ring key was not required: %v", err)
			}
			if err := manager.PreloadCircuits([]string{string(circuit) + ":1:1"}); err == nil {
				t.Fatal("ring preload accepted a shape")
			}
		})
	}
}

func TestTransferPreloadSelection(t *testing.T) {
	manager := NewLazyKeyManager(t.TempDir(), &DownloadConfig{AutoDownload: false})
	paths, matched, err := manager.selectedTransferPaths("transfer-confidential:2:3")
	if err != nil || !matched || len(paths) != 1 || filepath.Base(paths[0]) != "transfer_confidential_2_3.key" {
		t.Fatalf("selection %v %v", paths, err)
	}
	paths, matched, err = manager.selectedTransferPaths("merge")
	if err != nil || !matched || len(paths) != 2 {
		t.Fatalf("merge selection %v %v", paths, err)
	}
	if err := manager.PreloadForRunMode(Rpc); err == nil {
		t.Fatal("missing RPC keys reported ready")
	}
	if err := manager.PreloadCircuits([]string{"transfer-confidential:2:3"}); err == nil {
		t.Fatal("missing selected key reported ready")
	}
	if err := manager.PreloadCircuits([]string{"unknown"}); err == nil {
		t.Fatal("unknown circuit accepted")
	}
}

func TestRPCPreloadsOnlyPublishedShapes(t *testing.T) {
	manifest, err := loadManifest()
	if err != nil {
		t.Fatal(err)
	}
	manager := NewLazyKeyManager(t.TempDir(), &DownloadConfig{AutoDownload: false})
	paths := manager.transferPreloadPaths(transferPreloadCircuits)
	if len(paths) == 0 {
		t.Fatal("no transfer keys selected")
	}
	for _, path := range paths {
		if _, ok := manifest.Keys[filepath.Base(path)]; !ok {
			t.Fatalf("unpublished key %s", path)
		}
	}
	if _, _, err := manager.selectedTransferPaths("transfer-ring-authority:2:3"); err == nil {
		t.Fatal("unsupported authority shape")
	}
}
