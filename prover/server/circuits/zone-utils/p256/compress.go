package p256

import "github.com/consensys/gnark/frontend"

// CompressPubkey converts a 65-byte uncompressed P-256 point (0x04 || x || y)
// into the 33-byte SEC1 compressed form ((0x02 + parity(y)) || x).
//
// The parity bit is the LSB of y, which is the LSB of y[31] (the last byte
// of the y coordinate, since gnark stores y as 32 big-endian bytes).
//
// The 0x04 prefix at uncompressed[0] is not asserted here -- callers that
// receive an arbitrary witness should constrain it separately.
func CompressPubkey(api frontend.API, uncompressed [65]frontend.Variable) [33]frontend.Variable {
	// gnark ToBinary returns LSB first, so bits[0] is the parity bit.
	bits := api.ToBinary(uncompressed[64], 8)
	parity := bits[0]

	var compressed [33]frontend.Variable
	compressed[0] = api.Add(2, parity) // 0x02 if y even, 0x03 if y odd
	for i := 0; i < 32; i++ {
		compressed[1+i] = uncompressed[1+i]
	}
	return compressed
}
