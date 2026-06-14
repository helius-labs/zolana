package nullifiertree

import (
	"math/big"

	merkletree "zolana/prover/merkle-tree"
)

type BatchAddressAppendParameters struct {
	PublicInputHash *big.Int
	OldRoot         *big.Int
	NewRoot         *big.Int
	HashchainHash   *big.Int
	StartIndex      uint64

	LowElementValues     []big.Int
	LowElementIndices    []big.Int
	LowElementNextValues []big.Int

	NewElementValues []big.Int

	LowElementProofs [][]big.Int
	NewElementProofs [][]big.Int

	TreeHeight uint32
	BatchSize  uint32
	Tree       *merkletree.IndexedMerkleTree
}
