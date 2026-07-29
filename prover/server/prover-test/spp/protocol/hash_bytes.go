package protocol

import (
	"fmt"
	"math/big"

	"zolana/prover/prover-test/poseidon"
)

const hashBytesChunkSize = 31

// HashBytes implements the protocol byte hash for host-side assignments.
func HashBytes(bytes []byte) (*big.Int, error) {
	if len(bytes) == 0 {
		return new(big.Int), nil
	}

	chunks := make([]*big.Int, 0, (len(bytes)+hashBytesChunkSize-1)/hashBytesChunkSize)
	for offset := 0; offset < len(bytes); offset += hashBytesChunkSize {
		end := offset + hashBytesChunkSize
		if end > len(bytes) {
			end = len(bytes)
		}
		chunks = append(chunks, new(big.Int).SetBytes(bytes[offset:end]))
	}

	accumulator := chunks[0]
	for _, chunk := range chunks[1:] {
		next, err := poseidon.Hash([]*big.Int{accumulator, chunk})
		if err != nil {
			return nil, fmt.Errorf("hash bytes: %w", err)
		}
		accumulator = next
	}
	return accumulator, nil
}
