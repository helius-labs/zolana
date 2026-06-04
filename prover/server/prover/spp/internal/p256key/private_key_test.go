package p256key

import (
	"math/big"
	"testing"
)

func TestPrivateKeyFromScalarRejectsInvalidScalars(t *testing.T) {
	if _, err := PrivateKeyFromScalar(nil); err == nil {
		t.Fatal("expected nil scalar to fail")
	}
	if _, err := PrivateKeyFromScalar(big.NewInt(0)); err == nil {
		t.Fatal("expected zero scalar to fail")
	}
}
