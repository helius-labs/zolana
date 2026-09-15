package spptest

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"

	merkletree "zolana/prover/merkle-tree"
)

type HeadLeaf struct {
	Member    *big.Int
	Next      *big.Int
	Nullifier *big.Int
}

func (l HeadLeaf) Hash(t testing.TB) *big.Int {
	t.Helper()
	return MustPoseidon(t, 4, []*big.Int{l.Member, l.Next, l.Nullifier})
}

// The sentinel occupies slot zero.
type HeadMap struct {
	tree   merkletree.PoseidonTree
	leaves []HeadLeaf
}

type HeadMapInsertion struct {
	OldRoot  *big.Int
	NewRoot  *big.Int
	Low      HeadLeaf
	LowIndex uint64
	LowProof []big.Int
	NewIndex uint64
	NewProof []big.Int
}

type HeadMapTransition struct {
	OldRoot *big.Int
	NewRoot *big.Int
	Leaf    HeadLeaf
	Index   uint64
	Proof   []big.Int
}

// Above every member.
func HeadMapSentinelNext() *big.Int {
	return new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
}

func NewHeadMap(t testing.TB, height int) *HeadMap {
	t.Helper()
	m := &HeadMap{tree: merkletree.NewTree(height)}
	m.set(t, 0, HeadLeaf{Member: big.NewInt(0), Next: HeadMapSentinelNext(), Nullifier: big.NewInt(0)})
	return m
}

func (m *HeadMap) Root() *big.Int {
	root := m.tree.Root.Value()
	return &root
}

// Ordering is left to the circuit under test.
func (m *HeadMap) Register(t testing.TB, member, genesis *big.Int) HeadMapInsertion {
	t.Helper()
	lowIndex := m.lowIndex(member)
	low := m.leaves[lowIndex]
	newIndex := len(m.leaves)
	insertion := HeadMapInsertion{
		OldRoot:  m.Root(),
		Low:      low,
		LowIndex: uint64(lowIndex),
		LowProof: m.tree.GenerateProof(lowIndex),
		NewIndex: uint64(newIndex),
	}
	m.set(t, lowIndex, HeadLeaf{Member: low.Member, Next: member, Nullifier: low.Nullifier})
	insertion.NewProof = m.tree.GenerateProof(newIndex)
	m.set(t, newIndex, HeadLeaf{Member: member, Next: low.Next, Nullifier: genesis})
	insertion.NewRoot = m.Root()
	return insertion
}

func (m *HeadMap) Transfer(t testing.TB, index uint64, successor *big.Int) HeadMapTransition {
	t.Helper()
	leaf := m.leaves[index]
	transition := HeadMapTransition{
		OldRoot: m.Root(),
		Leaf:    leaf,
		Index:   index,
		Proof:   m.tree.GenerateProof(int(index)),
	}
	m.set(t, int(index), HeadLeaf{Member: leaf.Member, Next: leaf.Next, Nullifier: successor})
	transition.NewRoot = m.Root()
	return transition
}

func (m *HeadMap) lowIndex(member *big.Int) int {
	low := 0
	for i, leaf := range m.leaves {
		if leaf.Member.Cmp(member) < 0 && leaf.Member.Cmp(m.leaves[low].Member) >= 0 {
			low = i
		}
	}
	return low
}

func (m *HeadMap) set(t testing.TB, index int, leaf HeadLeaf) {
	t.Helper()
	m.tree.Update(index, *leaf.Hash(t))
	if index == len(m.leaves) {
		m.leaves = append(m.leaves, leaf)
		return
	}
	m.leaves[index] = leaf
}
