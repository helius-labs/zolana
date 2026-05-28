package spp

import "testing"

func TestIndexedTreeNonInclusionWitness(t *testing.T) {
	tree := NewIndexedTree()
	tree.Insert(fe(10))
	tree.Insert(fe(30))

	witness := tree.NonInclusion(fe(20))
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
	tree := NewIndexedTree()
	tree.Insert(fe(30))
	tree.Insert(fe(10))

	witness := tree.NonInclusion(fe(20))
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
	tree := NewIndexedTree()
	tree.Insert(fe(10))
	if err := tree.InsertChecked(fe(10)); err == nil {
		t.Fatal("expected duplicate insert to fail")
	}
}
