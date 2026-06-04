package model

import (
	"fmt"
	"math/big"

	"light/light-prover/prover/poseidon"
)

func stateNodeHash(left, right *big.Int) (*big.Int, error) {
	if err := validateFieldElement("left", left); err != nil {
		return nil, err
	}
	if err := validateFieldElement("right", right); err != nil {
		return nil, err
	}
	return poseidon.HashWithT(3, []*big.Int{left, right})
}

// StatePathFold folds an LSB-first Merkle path. 0 means left, 1 means right.
func StatePathFold(leaf *big.Int, siblings []*big.Int, directions []int) (*big.Int, error) {
	if len(siblings) != len(directions) {
		return nil, fmt.Errorf("spp.StatePathFold: siblings=%d directions=%d", len(siblings), len(directions))
	}
	if err := validateFieldElement("leaf", leaf); err != nil {
		return nil, err
	}
	h := new(big.Int).Set(leaf)
	for j := 0; j < len(siblings); j++ {
		if err := validateFieldElement(fmt.Sprintf("sibling[%d]", j), siblings[j]); err != nil {
			return nil, err
		}
		switch directions[j] {
		case 0:
			var err error
			h, err = stateNodeHash(h, siblings[j])
			if err != nil {
				return nil, err
			}
		case 1:
			var err error
			h, err = stateNodeHash(siblings[j], h)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("spp: state tree direction bit must be 0 or 1")
		}
	}
	return h, nil
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
	Leaf       *big.Int
	Siblings   []*big.Int
	Directions []int
	Root       *big.Int
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
		siblings := make([]*big.Int, height)
		directions := make([]int, height)
		cur := idx
		for level := 0; level < height; level++ {
			directions[level] = int(cur & 1)
			sibIdx := cur ^ 1
			sib, ok := nodes[level][sibIdx]
			if !ok {
				sib = empty[level]
			}
			siblings[level] = new(big.Int).Set(sib)
			cur >>= 1
		}
		proofs[idx] = StateTreeWitness{
			Leaf:       new(big.Int).Set(leaf),
			Siblings:   siblings,
			Directions: directions,
			Root:       new(big.Int).Set(root),
		}
	}
	return new(big.Int).Set(root), proofs, nil
}
