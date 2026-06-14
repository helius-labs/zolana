package protocol

import (
	"fmt"
	"math/big"

	"zolana/prover/prover-test/poseidon"
)

func stateNodeHash(left, right *big.Int) (*big.Int, error) {
	if err := validateFieldElement("left", left); err != nil {
		return nil, err
	}
	if err := validateFieldElement("right", right); err != nil {
		return nil, err
	}
	return poseidon.Hash([]*big.Int{left, right})
}

func MerkleRoot(leaf *big.Int, pathElements []*big.Int, pathIndex uint64) (*big.Int, error) {
	if len(pathElements) > 64 {
		return nil, fmt.Errorf("spp: Merkle path height %d exceeds uint64 path index", len(pathElements))
	}
	if !pathIndexFitsHeight(pathIndex, len(pathElements)) {
		return nil, fmt.Errorf("spp: Merkle path index %d does not fit height %d", pathIndex, len(pathElements))
	}
	if err := validateFieldElement("leaf", leaf); err != nil {
		return nil, err
	}
	h := new(big.Int).Set(leaf)
	for j := 0; j < len(pathElements); j++ {
		if err := validateFieldElement(fmt.Sprintf("path element[%d]", j), pathElements[j]); err != nil {
			return nil, err
		}
		bit := (pathIndex >> uint(j)) & 1
		var err error
		if bit == 0 {
			h, err = stateNodeHash(h, pathElements[j])
		} else {
			h, err = stateNodeHash(pathElements[j], h)
		}
		if err != nil {
			return nil, err
		}
	}
	return h, nil
}

func pathIndexFitsHeight(pathIndex uint64, height int) bool {
	if height >= 64 {
		return true
	}
	return pathIndex < uint64(1)<<uint(height)
}

func emptyStateNodes(height int) ([]*big.Int, error) {
	out := make([]*big.Int, height+1)
	out[0] = new(big.Int)
	for k := 1; k <= height; k++ {
		var err error
		out[k], err = stateNodeHash(out[k-1], out[k-1])
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

type StateTreeWitness struct {
	Leaf         *big.Int
	PathIndex    uint64
	PathElements []*big.Int
	Root         *big.Int
}

func BuildSparseStateTree(entries map[uint64]*big.Int) (*big.Int, map[uint64]StateTreeWitness, error) {
	return buildSparseBinaryStateTree(entries, StateTreeHeight)
}

func buildSparseBinaryStateTree(entries map[uint64]*big.Int, height int) (*big.Int, map[uint64]StateTreeWitness, error) {
	if height < 0 {
		return nil, nil, fmt.Errorf("spp: state tree height is negative")
	}
	empty, err := emptyStateNodes(height)
	if err != nil {
		return nil, nil, err
	}
	nodes := make([]map[uint64]*big.Int, height+1)
	for i := range nodes {
		nodes[i] = make(map[uint64]*big.Int)
	}
	for idx, leaf := range entries {
		if !pathIndexFitsHeight(idx, height) {
			return nil, nil, fmt.Errorf("spp: leaf index %d does not fit tree height %d", idx, height)
		}
		if err := validateFieldElement(fmt.Sprintf("leaf[%d]", idx), leaf); err != nil {
			return nil, nil, err
		}
		nodes[0][idx] = new(big.Int).Set(leaf)
	}

	for level := 0; level < height; level++ {
		for idx := range nodes[level] {
			parentIdx := idx / 2
			if _, done := nodes[level+1][parentIdx]; done {
				continue
			}
			leftIdx := parentIdx * 2
			rightIdx := leftIdx + 1
			left, ok := nodes[level][leftIdx]
			if !ok {
				left = empty[level]
			}
			right, ok := nodes[level][rightIdx]
			if !ok {
				right = empty[level]
			}
			nodes[level+1][parentIdx], err = stateNodeHash(left, right)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	root := nodes[height][0]
	if root == nil {
		root = empty[height]
	}

	proofs := make(map[uint64]StateTreeWitness, len(entries))
	for idx, leaf := range entries {
		pathElements := make([]*big.Int, height)
		cur := idx
		for level := 0; level < height; level++ {
			sibIdx := cur ^ 1
			sib, ok := nodes[level][sibIdx]
			if !ok {
				sib = empty[level]
			}
			pathElements[level] = new(big.Int).Set(sib)
			cur >>= 1
		}
		proofs[idx] = StateTreeWitness{
			Leaf:         new(big.Int).Set(leaf),
			PathIndex:    idx,
			PathElements: pathElements,
			Root:         new(big.Int).Set(root),
		}
	}
	return new(big.Int).Set(root), proofs, nil
}
