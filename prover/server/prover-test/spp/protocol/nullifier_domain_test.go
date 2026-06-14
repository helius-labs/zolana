package protocol

import (
	"math/big"
	"testing"

	"zolana/prover/prover-test/poseidon"
)

// nullifierTreeInitRootDecimal pins the init root of the general nullifier
// tree (H=40): one leaf Poseidon(0, p-1) at index 0, next_index = 1. The
// on-chain batched tree must initialize with the same sentinel and root, or
// every non-inclusion witness the prover builds opens against a root the
// on-chain tree never had.
const nullifierTreeInitRootDecimal = "13368749264980912746696049467680321808043390952490062751616344095712404128375"

func TestNullifierTreeInitRoot(t *testing.T) {
	tree, err := NewNullifierTree()
	if err != nil {
		t.Fatal(err)
	}
	want, ok := new(big.Int).SetString(nullifierTreeInitRootDecimal, 10)
	if !ok {
		t.Fatal("bad init root constant")
	}
	if tree.Root().Cmp(want) != 0 {
		t.Fatalf("init root mismatch:\n got %s\nwant %s", tree.Root(), want)
	}
	if tree.NextIndex() != 1 {
		t.Fatalf("init next_index: got %d, want 1", tree.NextIndex())
	}
}

// The sentinel is the largest field element p - 1; the insertable domain is
// strictly between 0 and the sentinel.
func TestNullifierDomainSentinel(t *testing.T) {
	want := new(big.Int).Sub(poseidon.Modulus, big.NewInt(1))
	if nullifierUpperBound.Cmp(want) != 0 {
		t.Fatalf("sentinel: got %s, want p-1 %s", nullifierUpperBound, want)
	}
	if InNullifierDomain(big.NewInt(0)) {
		t.Fatal("0 must not be insertable")
	}
	if InNullifierDomain(want) {
		t.Fatal("the sentinel itself must not be insertable")
	}
	if !InNullifierDomain(new(big.Int).Sub(poseidon.Modulus, big.NewInt(2))) {
		t.Fatal("p-2 must be insertable")
	}
	if !InNullifierDomain(big.NewInt(1)) {
		t.Fatal("1 must be insertable")
	}
}
