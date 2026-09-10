package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestKernelFieldEncoding(t *testing.T) {
	for _, values := range [][]fr.Element{
		nil,
		{{0, 0, 0, 0}},
		{{1, 2, 3, 4}, {0x0123456789abcdef, 0xfedcba9876543210, 1 << 63, ^uint64(0)}},
	} {
		var reference bytes.Buffer
		if err := binary.Write(&reference, binary.LittleEndian, values); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encodeKernelFields(values), reference.Bytes()) {
			t.Fatal("field encoding differs from the existing kernel ABI")
		}
	}
}
