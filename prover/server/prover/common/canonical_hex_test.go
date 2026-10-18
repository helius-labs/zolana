package common

import (
	"bytes"
	"testing"
)

func TestCanonicalHexBytes(t *testing.T) {
	for _, encoded := range []string{"ab", "0Xab", "0xAB", "0xa", "0xgg"} {
		if _, err := DecodeCanonicalHex(encoded); err == nil {
			t.Errorf("accepted %q", encoded)
		}
	}
	got, err := DecodeCanonicalHex("0x00ab")
	if err != nil || !bytes.Equal(got, []byte{0, 0xab}) {
		t.Fatalf("decoded %x: %v", got, err)
	}
	var fixed [2]byte
	if err := DecodeCanonicalHexInto(fixed[:], "0x00ab"); err != nil || !bytes.Equal(fixed[:], got) {
		t.Fatalf("fixed-width decode %x: %v", fixed, err)
	}
	if err := DecodeCanonicalHexInto(fixed[:], "0xab"); err == nil {
		t.Fatal("accepted wrong fixed width")
	}
}
