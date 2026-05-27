package spp

import (
	"math/big"
	"testing"
)

func TestBuildSparseStateTreeProofsFoldToRoot(t *testing.T) {
	entries := map[uint64]*big.Int{
		3:  fe(11),
		17: fe(22),
	}
	root, proofs := BuildSparseStateTree(entries)

	for index, proof := range proofs {
		got := StatePathFold(proof.Leaf, proof.Siblings, proof.Directions)
		if got.Cmp(root) != 0 {
			t.Fatalf("proof %d folded to %s, want root %s", index, got, root)
		}
		if proof.Root.Cmp(root) != 0 {
			t.Fatalf("proof %d stored root %s, want %s", index, proof.Root, root)
		}
	}
}
