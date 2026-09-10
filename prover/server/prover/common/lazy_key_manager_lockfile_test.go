package common

import (
	"path/filepath"
	"testing"

	"zolana/prover/prover/provingkeys"
)

func TestLazyKeyManagerKeyPathsExistInLockfile(t *testing.T) {
	manifest, err := provingkeys.Load()
	if err != nil {
		t.Fatalf("load proving-keys lockfile: %v", err)
	}
	manager := NewLazyKeyManager(filepath.Join("tmp", "proving-keys"), &DownloadConfig{})

	var paths []string
	for _, shape := range transferSupportedShapes {
		for _, circuitType := range []CircuitType{
			TransferConfidentialCircuitType,
			TransferRingCircuitType,
			TransferP256RingCircuitType,
		} {
			paths = append(paths, manager.determineTransferKeyPath(circuitType, shape[0], shape[1]))
		}
	}
	for _, shape := range ringAuthoritySupportedShapes {
		paths = append(paths, manager.determineTransferKeyPath(TransferRingAuthorityCircuitType, shape[0], shape[1]))
	}
	for _, nInputs := range mergeSupportedInputCounts {
		paths = append(paths, manager.determineTransferKeyPath(MergeCircuitType, nInputs, 1))
		paths = append(paths, manager.determineTransferKeyPath(MergeRingCircuitType, nInputs, 1))
	}
	paths = append(paths, manager.determineRingKeyPath(CustomRingCircuitType, "transfer"))
	paths = append(paths, manager.determineBatchKeyPath(BatchAddressAppendCircuitType, 40, 10))
	paths = append(paths, manager.determineBatchKeyPath(BatchAddressAppendCircuitType, 40, 250))

	for _, path := range paths {
		if path == "" {
			t.Fatal("resolver returned an empty key path for a listed shape")
		}
		name := filepath.Base(path)
		if _, ok := manifest.Keys[name]; !ok {
			t.Errorf("resolver names %s, which is not pinned in proving-keys.lock", name)
		}
	}
	if len(paths) != len(manifest.Keys) {
		t.Errorf("resolver produces %d key names, lockfile pins %d", len(paths), len(manifest.Keys))
	}
}

func TestLazyKeyManagerRejectsRingAuthorityShapesOutsideTheSubset(t *testing.T) {
	manager := NewLazyKeyManager(filepath.Join("tmp", "proving-keys"), &DownloadConfig{})
	for _, shape := range transferSupportedShapes {
		if manager.determineTransferKeyPath(TransferRingCircuitType, shape[0], shape[1]) == "" {
			t.Fatalf("ring shape %dx%d has no key path", shape[0], shape[1])
		}
		inSubset := false
		for _, allowed := range ringAuthoritySupportedShapes {
			if allowed == shape {
				inSubset = true
			}
		}
		got := manager.determineTransferKeyPath(TransferRingAuthorityCircuitType, shape[0], shape[1])
		if inSubset && got == "" {
			t.Fatalf("ring-authority shape %dx%d has no key path", shape[0], shape[1])
		}
		if !inSubset && got != "" {
			t.Fatalf("ring-authority shape %dx%d resolves to %q; the program rejects it", shape[0], shape[1], got)
		}
	}
}
