package base

import (
	"math/big"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

const (
	// InputPrefixLen is the byte width of a spent hash's prefix on a commitment key.
	InputPrefixLen = 16
	// InputPrefixBits bounds a prefix of a canonical hash, two of them pack below q.
	InputPrefixBits = 126
)

// PackDisclosure zero pads bytes at the end to whole 31-byte chunks and packs each chunk, the caller bounds every byte.
func PackDisclosure(api frontend.API, bytes []frontend.Variable) []frontend.Variable {
	chunks := (len(bytes) + gadget.HashBytesChunkSize - 1) / gadget.HashBytesChunkSize
	return packBounded(api, append(append([]frontend.Variable{}, bytes...), zeros(chunks*gadget.HashBytesChunkSize-len(bytes))...))
}

// commitmentTail is hashes[0] in full, then the prefixes of the other hashes two per field, the last half zero for an odd prefix count.
func commitmentTail(api frontend.API, rc frontend.Rangechecker, hashes []frontend.Variable) []frontend.Variable {
	prefixes := make([]frontend.Variable, 0, len(hashes))
	for _, hash := range hashes[1:] {
		// The canonical split leaves one prefix per hash, the prefix of hash + q would name another note.
		prefix, _ := gadget.SplitField(api, rc, hash, 8*(32-InputPrefixLen))
		prefixes = append(prefixes, prefix)
	}
	shift := new(big.Int).Lsh(big.NewInt(1), InputPrefixBits)
	tail := []frontend.Variable{hashes[0]}
	for k := 0; k < len(prefixes); k += 2 {
		second := frontend.Variable(0)
		if k+1 < len(prefixes) {
			second = prefixes[k+1]
		}
		// Both prefixes lie below 2^InputPrefixBits, the pair packs without a wrap and decodes to one pair.
		tail = append(tail, api.Add(api.Mul(prefixes[k], shift), second))
	}
	return tail
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
