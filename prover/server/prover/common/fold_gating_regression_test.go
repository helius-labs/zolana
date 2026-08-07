//go:build unix

package common

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The key file for each unsupported shape is a FIFO, so a loader that opens it
// blocks instead of failing. A rejection must come before any file access.
func TestUnsupportedFoldShapeDoesNotOpenTheKeyFile(t *testing.T) {
	keysDir := t.TempDir()
	for _, name := range []string{"merge-chain_9_9_9.key", "nullifier-fold_40_10_r9.key"} {
		path := filepath.Join(keysDir, name)
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatalf("mkfifo %s: %v", name, err)
		}
		t.Cleanup(func() { unblockFifoReader(path) })
	}

	manager := NewLazyKeyManager(keysDir, &DownloadConfig{})

	calls := map[string]func() error{
		"merge chain 9_9_9": func() error {
			_, err := manager.GetMergeChainSystem([]uint32{9, 9, 9})
			return err
		},
		"nullifier fold 40_10_r9": func() error {
			_, err := manager.GetNullifierFoldSystem(40, 10, 9)
			return err
		},
	}
	for label, call := range calls {
		result := make(chan error, 1)
		go func() { result <- call() }()
		select {
		case err := <-result:
			if err == nil {
				t.Errorf("%s was accepted, want a rejection", label)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("%s reached the key file before the shape was rejected", label)
		}
	}
}

// A nonblocking write open succeeds only when a reader is stuck on the FIFO
// and releases it. Without a reader it fails and there is nothing to release.
func unblockFifoReader(path string) {
	if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
		f.Close()
	}
}
