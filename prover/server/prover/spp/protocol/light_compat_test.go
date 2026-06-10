package protocol

import (
	"math/big"
	"testing"
)

// addressTreeInitRoot40 pins ADDRESS_TREE_INIT_ROOT_40 from
// privacy-program-libs (crates/batched-merkle-tree/src/constants.rs): the
// root the on-chain light-batched-merkle-tree (AddressV2, H=40) starts with.
var addressTreeInitRoot40 = []byte{
	28, 65, 107, 255, 208, 234, 51, 3, 131, 95, 62, 130, 202, 177, 176, 26, 216, 81, 64, 184, 200,
	25, 95, 124, 248, 129, 44, 109, 229, 146, 106, 76,
}

// The SPP nullifier tree IS the on-chain Light batched address tree, so the
// Go witness tree must reproduce Light's exact init state: one leaf
// Poseidon2(0, 2^248-1) at index 0, next_index = 1. If this breaks, every
// non-inclusion witness the prover builds opens against a root the on-chain
// tree never had.
func TestNullifierTreeInitRootMatchesLightAddressTree(t *testing.T) {
	tree, err := NewNullifierTree()
	if err != nil {
		t.Fatal(err)
	}
	want := new(big.Int).SetBytes(addressTreeInitRoot40)
	if tree.Root().Cmp(want) != 0 {
		t.Fatalf("init root mismatch:\n got %s\nwant %s (ADDRESS_TREE_INIT_ROOT_40)", tree.Root(), want)
	}
	if tree.NextIndex() != 1 {
		t.Fatalf("init next_index: got %d, want 1", tree.NextIndex())
	}
}

// The sentinel must be Light's HIGHEST_ADDRESS_PLUS_ONE = 2^248 - 1; the
// domain bound and Truncate248 must agree with it.
func TestNullifierDomainMatchesLight(t *testing.T) {
	want, _ := new(big.Int).SetString(
		"452312848583266388373324160190187140051835877600158453279131187530910662655", 10)
	if nullifierUpperBound.Cmp(want) != 0 {
		t.Fatalf("sentinel: got %s, want HIGHEST_ADDRESS_PLUS_ONE %s", nullifierUpperBound, want)
	}
	// Truncate248 of the sentinel itself is the identity (it already fits).
	if Truncate248(want).Cmp(want) != 0 {
		t.Fatal("Truncate248 must be identity on 248-bit values")
	}
	// 2^248 truncates to 0; 2^248 + 5 truncates to 5.
	two248 := new(big.Int).Lsh(big.NewInt(1), 248)
	if Truncate248(two248).Sign() != 0 {
		t.Fatal("Truncate248(2^248) must be 0")
	}
	if Truncate248(new(big.Int).Add(two248, big.NewInt(5))).Cmp(big.NewInt(5)) != 0 {
		t.Fatal("Truncate248(2^248+5) must be 5")
	}
}
