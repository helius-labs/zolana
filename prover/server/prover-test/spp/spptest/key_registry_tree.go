package spptest

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"

	merkletree "zolana/prover/merkle-tree"
)

type KeyRegistryLeaf struct {
	Member *big.Int
	Next   *big.Int
	Key    *big.Int
}

func (l KeyRegistryLeaf) Hash(t testing.TB) *big.Int {
	t.Helper()
	return MustPoseidon(t, 4, []*big.Int{l.Member, l.Next, l.Key})
}

// The sentinel occupies slot zero.
type KeyRegistryTree struct {
	tree   merkletree.PoseidonTree
	leaves []KeyRegistryLeaf
}

type KeyRegistryInsertion struct {
	OldRoot  *big.Int
	NewRoot  *big.Int
	Low      KeyRegistryLeaf
	LowIndex uint64
	LowProof []big.Int
	NewIndex uint64
	NewProof []big.Int
}

// Above every member.
func KeyRegistrySentinelNext() *big.Int {
	return new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
}

func NewKeyRegistryTree(t testing.TB, height int) *KeyRegistryTree {
	t.Helper()
	r := &KeyRegistryTree{tree: merkletree.NewTree(height)}
	r.set(t, 0, KeyRegistryLeaf{Member: big.NewInt(0), Next: KeyRegistrySentinelNext(), Key: big.NewInt(0)})
	return r
}

func (r *KeyRegistryTree) Root() *big.Int {
	root := r.tree.Root.Value()
	return &root
}

// Ordering is left to the circuit under test.
func (r *KeyRegistryTree) Register(t testing.TB, member, key *big.Int) KeyRegistryInsertion {
	t.Helper()
	lowIndex := r.lowIndex(member)
	low := r.leaves[lowIndex]
	newIndex := len(r.leaves)
	insertion := KeyRegistryInsertion{
		OldRoot:  r.Root(),
		Low:      low,
		LowIndex: uint64(lowIndex),
		LowProof: r.tree.GenerateProof(lowIndex),
		NewIndex: uint64(newIndex),
	}
	r.set(t, lowIndex, KeyRegistryLeaf{Member: low.Member, Next: member, Key: low.Key})
	insertion.NewProof = r.tree.GenerateProof(newIndex)
	r.set(t, newIndex, KeyRegistryLeaf{Member: member, Next: low.Next, Key: key})
	insertion.NewRoot = r.Root()
	return insertion
}

func (r *KeyRegistryTree) lowIndex(member *big.Int) int {
	low := 0
	for i, leaf := range r.leaves {
		if leaf.Member.Cmp(member) < 0 && leaf.Member.Cmp(r.leaves[low].Member) >= 0 {
			low = i
		}
	}
	return low
}

func (r *KeyRegistryTree) set(t testing.TB, index int, leaf KeyRegistryLeaf) {
	t.Helper()
	r.tree.Update(index, *leaf.Hash(t))
	if index == len(r.leaves) {
		r.leaves = append(r.leaves, leaf)
		return
	}
	r.leaves[index] = leaf
}
