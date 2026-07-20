package gadget

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// PackBEChunkBytes is the byte width of a hash_bytes chunk. 31 bytes < 2^248 <
// the BN254 modulus, so every chunk is a valid field element (lossless).
const PackBEChunkBytes = 31

// PackBE packs a byte slice into big-endian field-element chunks of chunkBytes
// bytes each (the final chunk holds the remaining bytes). Mirrors
// program-libs/hasher/src/primitives/pack_be.rs when chunkBytes == 31; the KDF
// uses it directly for its fixed-length operands.
func PackBE(api frontend.API, bytes []frontend.Variable, chunkBytes int) []frontend.Variable {
	var fes []frontend.Variable
	for offset := 0; offset < len(bytes); offset += chunkBytes {
		end := offset + chunkBytes
		if end > len(bytes) {
			end = len(bytes)
		}
		chunk := bytes[offset:end]
		v := frontend.Variable(0)
		n := len(chunk)
		for i, b := range chunk {
			coeff := new(big.Int).Lsh(big.NewInt(1), uint(8*(n-1-i)))
			v = api.Add(v, api.Mul(b, coeff))
		}
		fes = append(fes, v)
	}
	return fes
}

// HashBytes is the canonical byte commitment: Poseidon(len_fe, chunk_0, ..,
// chunk_{k-1}) over 31-byte big-endian chunks (spec: Byte Field Encoding).
// Mirrors program-libs/hasher/src/primitives/hash_bytes.rs. Carries no domain
// tag; distinct uses are separated by length and by position in the enclosing
// hash.
func HashBytes(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	chunks := PackBE(api, bytes, PackBEChunkBytes)
	inputs := make([]frontend.Variable, 0, 1+len(chunks))
	inputs = append(inputs, frontend.Variable(uint64(len(bytes))))
	inputs = append(inputs, chunks...)
	return PoseidonHash(api, inputs)
}
