package p256

import "github.com/consensys/gnark/frontend"

// CompressPubkey converts a validated canonical P-256 point into SEC1 form
// (0x02+parity(y)) || x. It bounds only the last Y byte used for parity.
// The caller must establish the other byte bounds, prefix, canonicality,
// curve membership and nonidentity. Generator output satisfies this contract.
func CompressPubkey(api frontend.API, uncompressed [65]frontend.Variable) [33]frontend.Variable {
	// gnark ToBinary returns LSB first, so bits[0] is the parity bit.
	bits := api.ToBinary(uncompressed[64], 8)
	parity := bits[0]

	// Assemble the parity prefix and retain the validated X coordinate.
	var compressed [33]frontend.Variable
	compressed[0] = api.Add(2, parity) // 0x02 if y even, 0x03 if y odd
	for i := 0; i < 32; i++ {
		compressed[1+i] = uncompressed[1+i]
	}
	return compressed
}
