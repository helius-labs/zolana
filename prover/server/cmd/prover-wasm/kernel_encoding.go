package main

import (
	"encoding/binary"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// The arithmetic bridge uses four little-endian Montgomery limbs per element.
// Avoid reflection on the six large field vectors transferred for every proof.
func encodeKernelFields(values []fr.Element) []byte {
	out := make([]byte, len(values)*32)
	for i, value := range values {
		encoded := out[i*32 : (i+1)*32]
		binary.LittleEndian.PutUint64(encoded[0:8], value[0])
		binary.LittleEndian.PutUint64(encoded[8:16], value[1])
		binary.LittleEndian.PutUint64(encoded[16:24], value[2])
		binary.LittleEndian.PutUint64(encoded[24:32], value[3])
	}
	return out
}
