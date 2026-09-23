package spptest

import (
	"math/big"
	"testing"

	merkletree "zolana/prover/merkle-tree"
)

// KeyRegistry appends member keys after the sentinel, ordering is left to the program.
type KeyRegistry struct {
	tree merkletree.PoseidonTree
	size uint64
}

type RegisteredKey struct {
	Member *big.Int
	Next   *big.Int
	CtHash *big.Int
	Index  uint64
}

func NewKeyRegistry(t testing.TB, height int) *KeyRegistry {
	t.Helper()
	r := &KeyRegistry{tree: merkletree.NewTree(height)}
	r.tree.Update(0, *registryLeaf(t, big.NewInt(0), KeyRegistrySentinelNext(), big.NewInt(0)))
	return r
}

func (r *KeyRegistry) Root() *big.Int {
	root := r.tree.Root.Value()
	return &root
}

func (r *KeyRegistry) Register(t testing.TB, member, nullifierPk, ctHash *big.Int) RegisteredKey {
	t.Helper()
	key := RegisteredKey{Member: member, Next: KeyRegistrySentinelNext(), CtHash: ctHash, Index: r.size + 1}
	keyHash := MustPoseidon(t, 3, []*big.Int{nullifierPk, ctHash})
	r.tree.Update(int(key.Index), *registryLeaf(t, member, key.Next, keyHash))
	r.size++
	return key
}

// Path opens index under the current root.
func (r *KeyRegistry) Path(index uint64) []big.Int {
	return r.tree.GenerateProof(int(index))
}

func registryLeaf(t testing.TB, member, next, keyHash *big.Int) *big.Int {
	t.Helper()
	return KeyRegistryLeaf{Member: member, Next: next, Key: keyHash}.Hash(t)
}
