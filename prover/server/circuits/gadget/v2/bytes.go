package checked

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

const byteBits = 8

// BytesToField packs bounded big-endian bytes as one field value. At most 31
// bytes fit below BN254's scalar modulus. A 32-byte value must start with zero.
func BytesToField(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	if len(bytes) > gadget.HashBytesChunkSize+1 {
		panic("bytes to field: more than 32 bytes")
	}
	if len(bytes) == gadget.HashBytesChunkSize+1 {
		api.AssertIsEqual(bytes[0], 0)
	}
	if api.Compiler().Field().BitLen() <= byteBits*min(len(bytes), gadget.HashBytesChunkSize) {
		panic("bytes to field: packed integer can wrap the native field")
	}
	rc := rangecheck.New(api)
	acc := frontend.Variable(0)
	for _, b := range bytes {
		rc.Check(b, byteBits)
		acc = api.Add(api.Mul(acc, 256), b)
	}
	return acc
}

// BitsToBytesBE groups little-endian bits into big-endian bytes. The bit count
// must be a multiple of eight.
func BitsToBytesBE(api frontend.API, bits []frontend.Variable) []frontend.Variable {
	if len(bits)%byteBits != 0 {
		panic("bits to bytes: bit count is not a multiple of eight")
	}
	n := len(bits) / byteBits
	out := make([]frontend.Variable, n)
	for i := range out {
		start := (n - 1 - i) * byteBits
		out[i] = api.FromBinary(bits[start : start+byteBits]...)
	}
	return out
}

// FieldToBytesBE returns the unique 32-byte encoding of a native field value.
// Full-width ToBinary enforces canonicality before any caller takes a suffix.
// Reducing a 256-bit representative modulo the field would admit byte aliases.
func FieldToBytesBE(api frontend.API, value frontend.Variable) [32]frontend.Variable {
	if api.Compiler().Field().BitLen() > 256 {
		panic("field to bytes: field exceeds 32 bytes")
	}
	bits := api.ToBinary(value)
	for len(bits) < 256 {
		bits = append(bits, 0)
	}
	var out [32]frontend.Variable
	copy(out[:], BitsToBytesBE(api, bits))
	return out
}
