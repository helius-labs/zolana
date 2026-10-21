package base

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// DisclosurePad is Poseidon(seed, j) per field j over seed = Poseidon(domain, key0, key1, salt), a known pad reveals no other.
func DisclosurePad(api frontend.API, domain uint64, key []frontend.Variable, salt frontend.Variable, n int) []frontend.Variable {
	seed := gadget.PoseidonHash(api, []frontend.Variable{domain, key[0], key[1], salt})
	pad := make([]frontend.Variable, n)
	for i := range pad {
		pad[i] = gadget.PoseidonHash(api, []frontend.Variable{seed, i})
	}
	return pad
}

// PackDisclosure zero pads bytes at the end to whole 31-byte chunks and packs each chunk, the caller bounds every byte.
func PackDisclosure(api frontend.API, bytes []frontend.Variable) []frontend.Variable {
	chunks := (len(bytes) + gadget.HashBytesChunkSize - 1) / gadget.HashBytesChunkSize
	return packBounded(api, append(append([]frontend.Variable{}, bytes...), zeros(chunks*gadget.HashBytesChunkSize-len(bytes))...))
}

// packBounded is gadget.PackBytesBE over bytes the caller bounds where they are produced.
func packBounded(api frontend.API, bytes []frontend.Variable) []frontend.Variable {
	return gadget.PackBytesBEWith(api, gadget.BoundedBytes{}, bytes)
}

// uintBytes is the big-endian encoding of an unsigned value below 2^(8n), a larger value fails the decomposition.
func uintBytes(api frontend.API, value frontend.Variable, n int) []frontend.Variable {
	return gadget.BitsToBytesBE(api, api.ToBinary(value, 8*n))
}

// masked multiplies every byte by the bit flag, zeroing a slot the disclosure does not open.
func masked(api frontend.API, flag frontend.Variable, bytes []frontend.Variable) []frontend.Variable {
	out := make([]frontend.Variable, len(bytes))
	for i, b := range bytes {
		out[i] = api.Mul(flag, b)
	}
	return out
}

func zeros(n int) []frontend.Variable {
	out := make([]frontend.Variable, n)
	for i := range out {
		out[i] = 0
	}
	return out
}
