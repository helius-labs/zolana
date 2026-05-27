package spp

import (
	"fmt"
	"math/big"

	"light/light-prover/prover/poseidon"
)

var highestNullifierPlusOne = new(big.Int).Sub(poseidon.Modulus, big.NewInt(1))

func IndexedLeafHash(value, nextValue *big.Int) *big.Int {
	h, err := poseidon.HashWithT(3, []*big.Int{value, nextValue})
	if err != nil {
		panic(err)
	}
	return h
}

type NonInclusionWitness struct {
	Target     *big.Int
	LowValue   *big.Int
	NextValue  *big.Int
	Siblings   []*big.Int
	Directions []int
	Root       *big.Int
}

func VerifyNonInclusion(w NonInclusionWitness) error {
	if w.LowValue.Cmp(w.Target) >= 0 {
		return fmt.Errorf("spp: non-inclusion requires low value < target")
	}
	if w.Target.Cmp(w.NextValue) >= 0 {
		return fmt.Errorf("spp: non-inclusion requires target < next value")
	}
	if len(w.Siblings) != NullifierTreeHeight || len(w.Directions) != NullifierTreeHeight {
		return fmt.Errorf("spp: nullifier path length mismatch: siblings=%d directions=%d want=%d",
			len(w.Siblings), len(w.Directions), NullifierTreeHeight)
	}
	leafHash := IndexedLeafHash(w.LowValue, w.NextValue)
	computed := StatePathFold(leafHash, w.Siblings, w.Directions)
	if computed.Cmp(w.Root) != 0 {
		return fmt.Errorf("spp: nullifier root mismatch")
	}
	return nil
}

type IndexedElement struct {
	Index     uint64
	Value     *big.Int
	NextIndex uint64
}

type IndexedTree struct {
	Elements   map[uint64]IndexedElement
	LeafHashes map[uint64]*big.Int
	Root       *big.Int
}

func NewIndexedTree() *IndexedTree {
	t := &IndexedTree{
		Elements:   make(map[uint64]IndexedElement),
		LeafHashes: make(map[uint64]*big.Int),
	}
	t.Elements[0] = IndexedElement{
		Index:     0,
		Value:     new(big.Int),
		NextIndex: 0,
	}
	t.LeafHashes[0] = IndexedLeafHash(new(big.Int), highestNullifierPlusOne)
	t.rebuild()
	return t
}

func (t *IndexedTree) Insert(value *big.Int) {
	if value.Sign() <= 0 || value.Cmp(highestNullifierPlusOne) >= 0 {
		panic(fmt.Sprintf("spp: indexed tree value out of range: %s", value))
	}
	var tail IndexedElement
	first := true
	for _, element := range t.Elements {
		if first || element.Value.Cmp(tail.Value) > 0 {
			tail = element
			first = false
		}
	}
	if tail.Value.Cmp(value) >= 0 {
		panic(fmt.Sprintf("spp: indexed tree expects ascending inserts: tail=%s value=%s", tail.Value, value))
	}

	newIndex := uint64(len(t.Elements))
	tail.NextIndex = newIndex
	t.Elements[tail.Index] = tail
	t.LeafHashes[tail.Index] = IndexedLeafHash(tail.Value, value)

	t.Elements[newIndex] = IndexedElement{
		Index:     newIndex,
		Value:     new(big.Int).Set(value),
		NextIndex: 0,
	}
	t.LeafHashes[newIndex] = IndexedLeafHash(value, highestNullifierPlusOne)
	t.rebuild()
}

func (t *IndexedTree) NonInclusion(target *big.Int) NonInclusionWitness {
	if target.Sign() <= 0 || target.Cmp(highestNullifierPlusOne) >= 0 {
		panic(fmt.Sprintf("spp: non-inclusion target out of range: %s", target))
	}

	var low IndexedElement
	found := false
	for _, element := range t.Elements {
		if element.Value.Cmp(target) >= 0 {
			continue
		}
		if !found || element.Value.Cmp(low.Value) > 0 {
			low = element
			found = true
		}
	}
	if !found {
		panic("spp: indexed tree has no low element")
	}

	nextValue := new(big.Int)
	switch {
	case low.NextIndex == 0 && low.Index == 0 && len(t.Elements) == 1:
		nextValue.Set(highestNullifierPlusOne)
	case low.NextIndex == 0 && low.Index != 0:
		nextValue.Set(highestNullifierPlusOne)
	default:
		next, ok := t.Elements[low.NextIndex]
		if !ok {
			panic("spp: indexed tree missing next element")
		}
		nextValue.Set(next.Value)
	}
	if nextValue.Cmp(target) <= 0 {
		panic(fmt.Sprintf("spp: non-inclusion target already present or outside low range: %s", target))
	}

	entries := make(map[uint64]*big.Int, len(t.LeafHashes))
	for index, leafHash := range t.LeafHashes {
		entries[index] = leafHash
	}
	_, proofs := buildSparseBinaryStateTree(entries, NullifierTreeHeight)
	proof, ok := proofs[low.Index]
	if !ok {
		panic("spp: missing indexed tree low-element proof")
	}
	return NonInclusionWitness{
		Target:     new(big.Int).Set(target),
		LowValue:   new(big.Int).Set(low.Value),
		NextValue:  nextValue,
		Siblings:   proof.Siblings,
		Directions: proof.Directions,
		Root:       new(big.Int).Set(t.Root),
	}
}

func (t *IndexedTree) rebuild() {
	entries := make(map[uint64]*big.Int, len(t.LeafHashes))
	for index, leafHash := range t.LeafHashes {
		entries[index] = leafHash
	}
	root, _ := buildSparseBinaryStateTree(entries, NullifierTreeHeight)
	t.Root = root
}
