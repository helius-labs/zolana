package common

import (
	"path/filepath"
	"slices"
	"sort"
	"testing"

	mergeshared "zolana/prover/circuits/spp_merge/shared"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover/provingkeys"
)

func TestLazyKeyManagerBuildsTransferKeyPaths(t *testing.T) {
	keysDir := filepath.Join("tmp", "proving-keys")
	manager := NewLazyKeyManager(keysDir, &DownloadConfig{})

	tests := map[string]string{
		"transfer ring eddsa": manager.determineTransferKeyPath(TransferRingCircuitType, 49, 2),
		"transfer ring p256":  manager.determineTransferKeyPath(TransferP256RingCircuitType, 8, 16),
	}

	expected := map[string]string{
		// Key filenames mirror the verifying-key modules.
		"transfer ring eddsa": filepath.Join(keysDir, "transfer_ring_49_2.key"),
		"transfer ring p256":  filepath.Join(keysDir, "transfer_p256_ring_8_16.key"),
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
		"removed transfer 1x1":  TransferKeyFile(TransferConfidentialCircuitType, 1, 1),
		"removed transfer 2x3":  TransferKeyFile(TransferRingCircuitType, 2, 3),
		"removed transfer 36x2": TransferKeyFile(TransferP256RingCircuitType, 36, 2),
		"ring authority 2x4":    TransferKeyFile(TransferRingAuthorityCircuitType, 2, 4),
		"ring authority 1x1":    TransferKeyFile(TransferRingAuthorityCircuitType, 1, 1),
		"ring authority 3x3":    TransferKeyFile(TransferRingAuthorityCircuitType, 3, 3),
		"ring authority 8x8":    TransferKeyFile(TransferRingAuthorityCircuitType, 8, 8),
		"merge 24x2":            TransferKeyFile(MergeCircuitType, 24, 2),
		"removed merge 8x1":     TransferKeyFile(MergeCircuitType, 8, 1),
		"removed merge 36x1":    TransferKeyFile(MergeRingCircuitType, 36, 1),
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

func TestShapeListsMirrorTheirSources(t *testing.T) {
	if len(transferSupportedShapes) != len(protocol.SupportedShapes) {
		t.Fatalf("transfer shapes %d, protocol shapes %d", len(transferSupportedShapes), len(protocol.SupportedShapes))
	}
	for i, shape := range protocol.SupportedShapes {
		if transferSupportedShapes[i] != [2]uint32{uint32(shape.NInputs), uint32(shape.NOutputs)} {
			t.Fatalf("transfer shape %d is %v, protocol has %s", i, transferSupportedShapes[i], shape)
		}
	}
	if len(mergeSupportedInputCounts) != len(mergeshared.SupportedInputCounts) {
		t.Fatalf("merge counts %v, circuit counts %v", mergeSupportedInputCounts, mergeshared.SupportedInputCounts)
	}
	for i, count := range mergeshared.SupportedInputCounts {
		if mergeSupportedInputCounts[i] != uint32(count) {
			t.Fatalf("merge counts %v, circuit counts %v", mergeSupportedInputCounts, mergeshared.SupportedInputCounts)
		}
	}
}

func TestRingAuthorityKeysAreTheSmallSquareShapes(t *testing.T) {
	var files []string
	for _, shape := range transferSupportedShapes {
		if file := TransferKeyFile(TransferRingAuthorityCircuitType, shape[0], shape[1]); file != "" {
			files = append(files, file)
		}
	}
	want := []string{"transfer_ring_authority_2_2.key", "transfer_ring_authority_4_4.key"}
	if !slices.Equal(files, want) {
		t.Fatalf("ring authority keys %v, want %v", files, want)
	}
}
