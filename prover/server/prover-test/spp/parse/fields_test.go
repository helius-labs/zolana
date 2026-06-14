package parse

import (
	"bytes"
	"math/big"
	"testing"
)

func TestHexStringTrimsWhitespaceAndPrefix(t *testing.T) {
	for _, value := range []string{" 0x0a ", " 0X0a "} {
		if got := HexString(value); got != "0a" {
			t.Fatalf("HexString(%q) = %q, want 0a", value, got)
		}
	}
}

func TestHexBytesUsesHexString(t *testing.T) {
	got, err := HexBytes(" 0X0a ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{10}) {
		t.Fatalf("HexBytes = %x, want 0a", got)
	}
}

func TestBigIntParsesPrefixedHex(t *testing.T) {
	got, err := BigInt(" 0X0a ")
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("BigInt = %s, want 10", got)
	}
}

func TestBigIntDoesNotInferHex(t *testing.T) {
	got, err := BigInt("123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "123456789012345678901" {
		t.Fatalf("BigInt = %s, want decimal input", got)
	}

	if _, err := BigInt("00000000000000000000000a"); err == nil {
		t.Fatal("expected bare hex digits to fail")
	}
}

func TestFieldFormat(t *testing.T) {
	if got := FieldHex(big.NewInt(10)); got != "000000000000000000000000000000000000000000000000000000000000000a" {
		t.Fatalf("FieldHex = %q", got)
	}
	got, err := FieldBytes(big.NewInt(10))
	if err != nil {
		t.Fatal(err)
	}
	if got[31] != 10 {
		t.Fatalf("FieldBytes last byte = %d, want 10", got[31])
	}
}

func TestFieldBytesRejectsInvalidFields(t *testing.T) {
	if _, err := FieldBytes(nil); err == nil {
		t.Fatal("expected nil field to fail")
	}
	if _, err := FieldBytes(big.NewInt(-1)); err == nil {
		t.Fatal("expected negative field to fail")
	}
}
