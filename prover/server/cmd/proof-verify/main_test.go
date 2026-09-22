package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
)

func TestRejectPublicInputOutsideScalarField(t *testing.T) {
	for _, input := range []string{"", "-1", ecc.BN254.ScalarField().String()} {
		if err := verify("missing.key", input, strings.NewReader(`{}`)); err == nil || err.Error() != "invalid public input field" {
			t.Fatalf("input %q returned %v", input, err)
		}
	}
}

func TestRejectUnpinnedKey(t *testing.T) {
	if err := verify("unknown.key", "1", strings.NewReader(`{}`)); err == nil || err.Error() != "key is absent from pinned manifest" {
		t.Fatalf("unexpected result %v", err)
	}
}

func TestRejectModifiedPinnedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transfer_confidential_2_3.key")
	if err := os.WriteFile(path, []byte("invalid key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verify(path, "1", strings.NewReader(`{}`)); err == nil || err.Error() != "key does not match pinned manifest" {
		t.Fatalf("unexpected result %v", err)
	}
}
