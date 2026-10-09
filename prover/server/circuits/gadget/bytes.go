package gadget

import "github.com/consensys/gnark/frontend"

const byteBits = 8

// BytesToField packs bytes as one big-endian value. It does not reduce or
// range-check: the caller bounds the bytes and keeps the value below the field
// modulus.
func BytesToField(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	acc := frontend.Variable(0)
	for _, b := range bytes {
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
