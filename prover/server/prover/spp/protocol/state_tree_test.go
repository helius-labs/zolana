package protocol

import (
	"math/big"
	"testing"
)

func TestBuildSparseStateTreeProofsComputeRoot(t *testing.T) {
	entries := map[uint64]*big.Int{
		3:  fe(11),
		17: fe(22),
	}
	root, proofs, err := BuildSparseStateTree(entries)
	if err != nil {
		t.Fatalf("build sparse state tree: %v", err)
	}

	for index, proof := range proofs {
		got, err := MerkleRoot(proof.Leaf, proof.PathElements, proof.PathIndex)
		if err != nil {
			t.Fatalf("compute Merkle root for proof %d: %v", index, err)
		}
		if got.Cmp(root) != 0 {
			t.Fatalf("proof %d computed root %s, want %s", index, got, root)
		}
		if proof.Root.Cmp(root) != 0 {
			t.Fatalf("proof %d stored root %s, want %s", index, proof.Root, root)
		}
	}
}
