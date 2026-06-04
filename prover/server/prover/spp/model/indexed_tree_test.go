package model

import (
	"math/big"
	"testing"
)

func TestIndexedTreeNonInclusionWitness(t *testing.T) {
	tree := mustNewIndexedTree(t)
	mustInsert(t, tree, fe(10))
	mustInsert(t, tree, fe(30))

	witness := mustNonInclusion(t, tree, fe(20))
	if err := VerifyNonInclusion(witness); err != nil {
		t.Fatalf("verify non-inclusion witness: %v", err)
	}
	if witness.LowValue.Cmp(fe(10)) != 0 {
		t.Fatalf("low value mismatch: got %s want 10", witness.LowValue)
	}
	if witness.NextValue.Cmp(fe(30)) != 0 {
		t.Fatalf("next value mismatch: got %s want 30", witness.NextValue)
	}
}

func TestIndexedTreeSupportsUnsortedInserts(t *testing.T) {
	tree := mustNewIndexedTree(t)
	mustInsert(t, tree, fe(30))
	mustInsert(t, tree, fe(10))

	witness := mustNonInclusion(t, tree, fe(20))
	if err := VerifyNonInclusion(witness); err != nil {
		t.Fatalf("verify non-inclusion witness: %v", err)
	}
	if witness.LowValue.Cmp(fe(10)) != 0 {
		t.Fatalf("low value mismatch: got %s want 10", witness.LowValue)
	}
	if witness.NextValue.Cmp(fe(30)) != 0 {
		t.Fatalf("next value mismatch: got %s want 30", witness.NextValue)
	}
}

func TestIndexedTreeRejectsDuplicateInsert(t *testing.T) {
	tree := mustNewIndexedTree(t)
	mustInsert(t, tree, fe(10))
	if err := tree.InsertChecked(fe(10)); err == nil {
		t.Fatal("expected duplicate insert to fail")
	}
}

func TestIndexedTreeAccessors(t *testing.T) {
	tree := mustNewIndexedTree(t)
	if tree.NextIndex() != 1 {
		t.Fatalf("next index = %d, want 1", tree.NextIndex())
	}
	root := tree.Root()
	root.Set(big.NewInt(123))
	if tree.Root().Cmp(root) == 0 {
		t.Fatal("root accessor returned mutable tree state")
	}
}

func mustNewIndexedTree(t *testing.T) *IndexedTree {
	t.Helper()
	tree, err := NewIndexedTree()
	if err != nil {
		t.Fatalf("new indexed tree: %v", err)
	}
	return tree
}

func mustInsert(t *testing.T, tree *IndexedTree, value *big.Int) {
	t.Helper()
	if err := tree.InsertChecked(value); err != nil {
		t.Fatalf("insert indexed tree value: %v", err)
	}
}

func mustNonInclusion(t *testing.T, tree *IndexedTree, target *big.Int) NonInclusionWitness {
	t.Helper()
	witness, err := tree.NonInclusionChecked(target)
	if err != nil {
		t.Fatalf("non-inclusion witness: %v", err)
	}
	return witness
}
