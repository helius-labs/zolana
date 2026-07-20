package protocol

import (
	"fmt"
	"math/big"

	"zolana/prover/prover-test/poseidon"
)

const packBEChunkBytes = 31

// packBE packs a byte slice into 31-byte big-endian field-element chunks (the
// final chunk holds the remainder), mirroring
// program-libs/hasher/src/primitives/pack_be.rs.
func packBE(data []byte) []*big.Int {
	var chunks []*big.Int
	for off := 0; off < len(data); off += packBEChunkBytes {
		end := off + packBEChunkBytes
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, new(big.Int).SetBytes(data[off:end]))
	}
	return chunks
}

// HashBytes is the canonical byte commitment Poseidon(len_fe, chunk_0, ..,
// chunk_{k-1}) over 31-byte big-endian chunks, mirroring
// program-libs/hasher/src/primitives/hash_bytes.rs and the in-circuit
// gadget.HashBytes.
func HashBytes(data []byte) (*big.Int, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("spp: hash_bytes: empty input")
	}
	chunks := packBE(data)
	inputs := make([]*big.Int, 0, 1+len(chunks))
	inputs = append(inputs, new(big.Int).SetUint64(uint64(len(data))))
	inputs = append(inputs, chunks...)
	h, err := poseidon.Hash(inputs)
	if err != nil {
		return nil, fmt.Errorf("spp: hash_bytes: %w", err)
	}
	return h, nil
}
