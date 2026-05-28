package spp

import (
	"fmt"
	"math/big"

	"light/light-prover/prover/poseidon"
)

// StateNodeHash computes a binary state-tree node hash.
func StateNodeHash(left, right *big.Int) *big.Int {
	h, err := poseidon.HashWithT(3, []*big.Int{left, right})
	if err != nil {
		panic(err)
	}
	return h
}

// StatePathFold folds a leaf up a binary Merkle path. directions[j] is
// LSB-first: 0 means the current hash is the left child, 1 means right.
func StatePathFold(leaf *big.Int, siblings []*big.Int, directions []int) *big.Int {
	if len(siblings) != len(directions) {
		panic(fmt.Sprintf("spp.StatePathFold: siblings=%d directions=%d", len(siblings), len(directions)))
	}
	h := new(big.Int).Set(leaf)
	for j := 0; j < len(siblings); j++ {
		switch directions[j] {
		case 0:
			h = StateNodeHash(h, siblings[j])
		case 1:
			h = StateNodeHash(siblings[j], h)
		default:
			panic("spp: state tree direction bit must be 0 or 1")
		}
	}
	return h
}

func emptyStateNodes(height int) []*big.Int {
	out := make([]*big.Int, height+1)
	out[0] = new(big.Int)
	for k := 1; k <= height; k++ {
		out[k] = StateNodeHash(out[k-1], out[k-1])
	}
	return out
}

type StateTreeWitness struct {
	Leaf       *big.Int
	Siblings   []*big.Int
	Directions []int
	Root       *big.Int
}

// BuildSparseStateTree builds a test/witness sparse binary state tree.
func BuildSparseStateTree(entries map[uint64]*big.Int) (*big.Int, map[uint64]StateTreeWitness) {
	return buildSparseBinaryStateTree(entries, StateTreeHeight)
}

func buildSparseBinaryStateTree(entries map[uint64]*big.Int, height int) (*big.Int, map[uint64]StateTreeWitness) {
	empty := emptyStateNodes(height)
	nodes := make([]map[uint64]*big.Int, height+1)
	for i := range nodes {
		nodes[i] = make(map[uint64]*big.Int)
	}
	for idx, leaf := range entries {
		if _, exists := nodes[0][idx]; exists {
			panic(fmt.Sprintf("spp: duplicate state tree leaf index %d", idx))
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
			nodes[level+1][parentIdx] = StateNodeHash(left, right)
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
	return new(big.Int).Set(root), proofs
}
