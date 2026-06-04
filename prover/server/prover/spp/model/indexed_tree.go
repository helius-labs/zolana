package model

import (
	"fmt"
	"math/big"

	"light/light-prover/prover/poseidon"
)

var highestNullifierPlusOne = new(big.Int).Sub(poseidon.Modulus, big.NewInt(1))

func indexedLeafHash(value, nextValue *big.Int) (*big.Int, error) {
	if err := validateFieldElement("indexed leaf value", value); err != nil {
		return nil, err
	}
	if err := validateFieldElement("indexed leaf next value", nextValue); err != nil {
		return nil, err
	}
	return poseidon.HashWithT(3, []*big.Int{value, nextValue})
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
	if err := validateFieldElement("target", w.Target); err != nil {
		return err
	}
	if err := validateFieldElement("low value", w.LowValue); err != nil {
		return err
	}
	if err := validateFieldElement("next value", w.NextValue); err != nil {
		return err
	}
	if err := validateFieldElement("root", w.Root); err != nil {
		return err
	}
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
	leafHash, err := indexedLeafHash(w.LowValue, w.NextValue)
	if err != nil {
		return err
	}
	computed, err := StatePathFold(leafHash, w.Siblings, w.Directions)
	if err != nil {
		return err
	}
	if computed.Cmp(w.Root) != 0 {
		return fmt.Errorf("spp: nullifier root mismatch")
	}
	return nil
}

type indexedElement struct {
	Index     uint64
	Value     *big.Int
	NextIndex uint64
}

type IndexedTree struct {
	elements   map[uint64]indexedElement
	leafHashes map[uint64]*big.Int
	root       *big.Int
}

type BatchInsertWitness struct {
	LowValue    *big.Int
	LowIndex    uint64
	NextValue   *big.Int
	LowSiblings []*big.Int
	NewSiblings []*big.Int
}

func NewIndexedTree() (*IndexedTree, error) {
	t := &IndexedTree{
		elements:   make(map[uint64]indexedElement),
		leafHashes: make(map[uint64]*big.Int),
	}
	t.elements[0] = indexedElement{
		Index:     0,
		Value:     new(big.Int),
		NextIndex: 0,
	}
	leafHash, err := indexedLeafHash(new(big.Int), highestNullifierPlusOne)
	if err != nil {
		return nil, err
	}
	t.leafHashes[0] = leafHash
	if err := t.rebuild(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *IndexedTree) Root() *big.Int {
	return new(big.Int).Set(t.root)
}

func (t *IndexedTree) NextIndex() uint64 {
	return uint64(len(t.elements))
}

func (t *IndexedTree) InsertChecked(value *big.Int) error {
	if value == nil {
		return fmt.Errorf("spp: indexed tree value is nil")
	}
	if value.Sign() <= 0 || value.Cmp(highestNullifierPlusOne) >= 0 {
		return fmt.Errorf("spp: indexed tree value out of range: %s", value)
	}
	var low indexedElement
	found := false
	for _, element := range t.elements {
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

	newIndex := uint64(len(t.elements))
	oldNextIndex := low.NextIndex
	low.NextIndex = newIndex
	t.elements[low.Index] = low
	lowHash, err := indexedLeafHash(low.Value, value)
	if err != nil {
		return err
	}
	t.leafHashes[low.Index] = lowHash

	t.elements[newIndex] = indexedElement{
		Index:     newIndex,
		Value:     new(big.Int).Set(value),
		NextIndex: oldNextIndex,
	}
	newHash, err := indexedLeafHash(value, nextValue)
	if err != nil {
		return err
	}
	t.leafHashes[newIndex] = newHash
	return t.rebuild()
}

func (t *IndexedTree) InsertWithBatchWitness(value *big.Int, height int) (BatchInsertWitness, error) {
	if value == nil {
		return BatchInsertWitness{}, fmt.Errorf("spp: indexed tree value is nil")
	}
	if value.Sign() <= 0 || value.Cmp(highestNullifierPlusOne) >= 0 {
		return BatchInsertWitness{}, fmt.Errorf("spp: indexed tree value out of range: %s", value)
	}
	newIndex := uint64(len(t.elements))
	if height < 64 && newIndex >= 1<<height {
		return BatchInsertWitness{}, fmt.Errorf("spp: new nullifier index %d exceeds 2^%d", newIndex, height)
	}

	low, err := t.lowElementForNonInclusion(value)
	if err != nil {
		return BatchInsertWitness{}, err
	}
	nextValue, err := t.elementNextValue(low)
	if err != nil {
		return BatchInsertWitness{}, err
	}
	if nextValue.Cmp(value) <= 0 {
		return BatchInsertWitness{}, fmt.Errorf("spp: indexed tree value already present or outside low range: %s", value)
	}

	entries := make(map[uint64]*big.Int, len(t.leafHashes))
	for index, leaf := range t.leafHashes {
		entries[index] = new(big.Int).Set(leaf)
	}
	_, oldProofs, err := buildSparseBinaryStateTree(entries, height)
	if err != nil {
		return BatchInsertWitness{}, err
	}
	lowProof, ok := oldProofs[low.Index]
	if !ok {
		return BatchInsertWitness{}, fmt.Errorf("spp: missing indexed tree low-element proof")
	}

	afterLow := make(map[uint64]*big.Int, len(t.leafHashes)+1)
	for index, leaf := range t.leafHashes {
		afterLow[index] = new(big.Int).Set(leaf)
	}
	lowHash, err := indexedLeafHash(low.Value, value)
	if err != nil {
		return BatchInsertWitness{}, err
	}
	afterLow[low.Index] = lowHash
	afterLow[newIndex] = new(big.Int)
	_, afterLowProofs, err := buildSparseBinaryStateTree(afterLow, height)
	if err != nil {
		return BatchInsertWitness{}, err
	}
	newProof, ok := afterLowProofs[newIndex]
	if !ok {
		return BatchInsertWitness{}, fmt.Errorf("spp: missing empty new-leaf proof")
	}

	if err := t.InsertChecked(value); err != nil {
		return BatchInsertWitness{}, err
	}

	return BatchInsertWitness{
		LowValue:    new(big.Int).Set(low.Value),
		LowIndex:    low.Index,
		NextValue:   new(big.Int).Set(nextValue),
		LowSiblings: lowProof.Siblings,
		NewSiblings: newProof.Siblings,
	}, nil
}

func (t *IndexedTree) NonInclusionChecked(target *big.Int) (NonInclusionWitness, error) {
	if target == nil {
		return NonInclusionWitness{}, fmt.Errorf("spp: non-inclusion target is nil")
	}
	if target.Sign() <= 0 || target.Cmp(highestNullifierPlusOne) >= 0 {
		return NonInclusionWitness{}, fmt.Errorf("spp: non-inclusion target out of range: %s", target)
	}

	low, err := t.lowElementForNonInclusion(target)
	if err != nil {
		return NonInclusionWitness{}, err
	}

	nextValue, err := t.elementNextValue(low)
	if err != nil {
		return NonInclusionWitness{}, err
	}
	if nextValue.Cmp(target) <= 0 {
		return NonInclusionWitness{}, fmt.Errorf("spp: non-inclusion target already present or outside low range: %s", target)
	}

	entries := make(map[uint64]*big.Int, len(t.leafHashes))
	for index, leafHash := range t.leafHashes {
		entries[index] = leafHash
	}
	_, proofs, err := buildSparseBinaryStateTree(entries, NullifierTreeHeight)
	if err != nil {
		return NonInclusionWitness{}, err
	}
	proof, ok := proofs[low.Index]
	if !ok {
		return NonInclusionWitness{}, fmt.Errorf("spp: missing indexed tree low-element proof")
	}
	return NonInclusionWitness{
		Target:     new(big.Int).Set(target),
		LowValue:   new(big.Int).Set(low.Value),
		LowIndex:   low.Index,
		NextValue:  nextValue,
		Siblings:   proof.Siblings,
		Directions: proof.Directions,
		Root:       t.Root(),
	}, nil
}

func (t *IndexedTree) lowElementForNonInclusion(target *big.Int) (indexedElement, error) {
	var low indexedElement
	found := false
	for _, element := range t.elements {
		if element.Value.Cmp(target) >= 0 {
			continue
		}
		if !found || element.Value.Cmp(low.Value) > 0 {
			low = element
			found = true
		}
	}
	if !found {
		return indexedElement{}, fmt.Errorf("spp: indexed tree has no low element")
	}
	return low, nil
}

func (t *IndexedTree) elementNextValue(element indexedElement) (*big.Int, error) {
	if element.NextIndex == 0 {
		return new(big.Int).Set(highestNullifierPlusOne), nil
	}
	next, ok := t.elements[element.NextIndex]
	if !ok {
		return nil, fmt.Errorf("spp: indexed tree missing next element")
	}
	return new(big.Int).Set(next.Value), nil
}

func (t *IndexedTree) rebuild() error {
	entries := make(map[uint64]*big.Int, len(t.leafHashes))
	for index, leafHash := range t.leafHashes {
		entries[index] = leafHash
	}
	root, _, err := buildSparseBinaryStateTree(entries, NullifierTreeHeight)
	if err != nil {
		return err
	}
	t.root = root
	return nil
}
