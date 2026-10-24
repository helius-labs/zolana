package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsCorruptPinnedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "batch_address-append_40_10.key")
	if err := os.WriteFile(path, []byte("corrupt proving key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := load(path, "589c90ea00bc771e7b61c28c20290c4dfaa9a33790d7231261d7bbe621459843"); err == nil {
		t.Fatal("corrupt key reached deserialization")
	}
}
