package model

import (
	"math/big"
	"testing"
)

func TestBuildSparseStateTreeProofsFoldToRoot(t *testing.T) {
	entries := map[uint64]*big.Int{
		3:  fe(11),
		17: fe(22),
	}
	root, proofs, err := BuildSparseStateTree(entries)
	if err != nil {
		t.Fatalf("build sparse state tree: %v", err)
	}

	for index, proof := range proofs {
		got, err := StatePathFold(proof.Leaf, proof.Siblings, proof.Directions)
		if err != nil {
			t.Fatalf("fold proof %d: %v", index, err)
		}
		if got.Cmp(root) != 0 {
			t.Fatalf("proof %d folded to %s, want root %s", index, got, root)
		}
		if proof.Root.Cmp(root) != 0 {
			t.Fatalf("proof %d stored root %s, want %s", index, proof.Root, root)
		}
	}
}
