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
	LowIndex   uint64
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
	if err := t.InsertChecked(value); err != nil {
		panic(err)
	}
}

func (t *IndexedTree) InsertChecked(value *big.Int) error {
	if value.Sign() <= 0 || value.Cmp(highestNullifierPlusOne) >= 0 {
		return fmt.Errorf("spp: indexed tree value out of range: %s", value)
	}
	var low IndexedElement
	found := false
	for _, element := range t.Elements {
		if element.Value.Cmp(value) >= 0 {
			continue
		}
		if !found || element.Value.Cmp(low.Value) > 0 {
			low = element
			found = true
		}
	}
	if !found {
		return fmt.Errorf("spp: indexed tree has no low element")
	}
	nextValue, err := t.elementNextValue(low)
	if err != nil {
		return err
	}
	if nextValue.Cmp(value) <= 0 {
		return fmt.Errorf("spp: indexed tree value already present or outside low range: %s", value)
	}

	newIndex := uint64(len(t.Elements))
	oldNextIndex := low.NextIndex
	low.NextIndex = newIndex
	t.Elements[low.Index] = low
	t.LeafHashes[low.Index] = IndexedLeafHash(low.Value, value)

	t.Elements[newIndex] = IndexedElement{
		Index:     newIndex,
		Value:     new(big.Int).Set(value),
		NextIndex: oldNextIndex,
	}
	t.LeafHashes[newIndex] = IndexedLeafHash(value, nextValue)
	t.rebuild()
	return nil
}

func (t *IndexedTree) NonInclusion(target *big.Int) NonInclusionWitness {
	if target.Sign() <= 0 || target.Cmp(highestNullifierPlusOne) >= 0 {
		panic(fmt.Sprintf("spp: non-inclusion target out of range: %s", target))
	}

	low, err := t.lowElementForNonInclusion(target)
	if err != nil {
		panic(err)
	}

	nextValue, err := t.elementNextValue(low)
	if err != nil {
		panic(err)
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
		LowIndex:   low.Index,
		NextValue:  nextValue,
		Siblings:   proof.Siblings,
		Directions: proof.Directions,
		Root:       new(big.Int).Set(t.Root),
	}
}

func (t *IndexedTree) lowElementForNonInclusion(target *big.Int) (IndexedElement, error) {
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
		return IndexedElement{}, fmt.Errorf("spp: indexed tree has no low element")
	}
	return low, nil
}

func (t *IndexedTree) elementNextValue(element IndexedElement) (*big.Int, error) {
	if element.NextIndex == 0 {
		return new(big.Int).Set(highestNullifierPlusOne), nil
	}
	next, ok := t.Elements[element.NextIndex]
	if !ok {
		return nil, fmt.Errorf("spp: indexed tree missing next element")
	}
	return new(big.Int).Set(next.Value), nil
}

func (t *IndexedTree) rebuild() {
	entries := make(map[uint64]*big.Int, len(t.LeafHashes))
	for index, leafHash := range t.LeafHashes {
		entries[index] = leafHash
	}
	root, _ := buildSparseBinaryStateTree(entries, NullifierTreeHeight)
	t.Root = root
}
