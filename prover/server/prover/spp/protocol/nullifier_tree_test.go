package protocol

import (
	"math/big"
	"testing"
)

func TestNullifierTreeNonInclusionWitness(t *testing.T) {
	tree := mustNewNullifierTree(t)
	mustInsert(t, tree, fe(10))
	mustInsert(t, tree, fe(30))

	witness := mustNonInclusion(t, tree, fe(20))
	if err := VerifyNullifierNonInclusion(witness); err != nil {
		t.Fatalf("verify non-inclusion witness: %v", err)
	}
	if witness.LowValue.Cmp(fe(10)) != 0 {
		t.Fatalf("low value mismatch: got %s want 10", witness.LowValue)
	}
	if witness.NextValue.Cmp(fe(30)) != 0 {
		t.Fatalf("next value mismatch: got %s want 30", witness.NextValue)
	}
}

func TestNullifierTreeSupportsUnsortedInserts(t *testing.T) {
	tree := mustNewNullifierTree(t)
	mustInsert(t, tree, fe(30))
	mustInsert(t, tree, fe(10))

	witness := mustNonInclusion(t, tree, fe(20))
	if err := VerifyNullifierNonInclusion(witness); err != nil {
		t.Fatalf("verify non-inclusion witness: %v", err)
	}
	if witness.LowValue.Cmp(fe(10)) != 0 {
		t.Fatalf("low value mismatch: got %s want 10", witness.LowValue)
	}
	if witness.NextValue.Cmp(fe(30)) != 0 {
		t.Fatalf("next value mismatch: got %s want 30", witness.NextValue)
	}
}

func TestNullifierTreeRejectsDuplicateInsert(t *testing.T) {
	tree := mustNewNullifierTree(t)
	mustInsert(t, tree, fe(10))
	if err := tree.Insert(fe(10)); err == nil {
		t.Fatal("expected duplicate insert to fail")
	}
}

func TestNullifierTreeAccessors(t *testing.T) {
	tree := mustNewNullifierTree(t)
	if tree.NextIndex() != 1 {
		t.Fatalf("next index = %d, want 1", tree.NextIndex())
	}
	root := tree.Root()
	root.Set(big.NewInt(123))
	if tree.Root().Cmp(root) == 0 {
		t.Fatal("root accessor returned mutable tree state")
	}
}

func mustNewNullifierTree(t *testing.T) *NullifierTree {
	t.Helper()
	tree, err := NewNullifierTree()
	if err != nil {
		t.Fatalf("new nullifier tree: %v", err)
	}
	return tree
}

func mustInsert(t *testing.T, tree *NullifierTree, value *big.Int) {
	t.Helper()
	if err := tree.Insert(value); err != nil {
		t.Fatalf("insert nullifier tree value: %v", err)
	}
}

func mustNonInclusion(t *testing.T, tree *NullifierTree, target *big.Int) NonInclusionWitness {
	t.Helper()
	witness, err := tree.NonInclusionWitness(target)
	if err != nil {
		t.Fatalf("non-inclusion witness: %v", err)
	}
	return witness
}
