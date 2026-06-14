package protocol

import (
	"fmt"
	"math/big"

	"zolana/prover/prover-test/poseidon"
)

var nullifierUpperBound = new(big.Int).Sub(poseidon.Modulus, big.NewInt(1))

func InNullifierDomain(v *big.Int) bool {
	return v.Sign() > 0 && v.Cmp(nullifierUpperBound) < 0
}

func indexedLeafHash(value, nextValue *big.Int) (*big.Int, error) {
	if err := validateFieldElement("indexed leaf value", value); err != nil {
		return nil, err
	}
	if err := validateFieldElement("indexed leaf next value", nextValue); err != nil {
		return nil, err
	}
	return poseidon.Hash([]*big.Int{value, nextValue})
}

type NonInclusionWitness struct {
	Target       *big.Int
	LowValue     *big.Int
	LowIndex     uint64
	NextValue    *big.Int
	PathElements []*big.Int
	Root         *big.Int
}

func VerifyNullifierNonInclusion(w NonInclusionWitness) error {
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
	if len(w.PathElements) != NullifierTreeHeight {
		return fmt.Errorf("spp: nullifier path length mismatch: got %d want %d",
			len(w.PathElements), NullifierTreeHeight)
	}
	leafHash, err := indexedLeafHash(w.LowValue, w.NextValue)
	if err != nil {
		return err
	}
	computed, err := MerkleRoot(leafHash, w.PathElements, w.LowIndex)
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

type NullifierTree struct {
	elements   map[uint64]indexedElement
	leafHashes map[uint64]*big.Int
	root       *big.Int
}

type NullifierInsertWitness struct {
	LowValue        *big.Int
	LowIndex        uint64
	NextValue       *big.Int
	LowElementProof []*big.Int
	NewElementProof []*big.Int
}

func NewNullifierTree() (*NullifierTree, error) {
	t := &NullifierTree{
		elements:   make(map[uint64]indexedElement),
		leafHashes: make(map[uint64]*big.Int),
	}
	t.elements[0] = indexedElement{
		Index:     0,
		Value:     new(big.Int),
		NextIndex: 0,
	}
	leafHash, err := indexedLeafHash(new(big.Int), nullifierUpperBound)
	if err != nil {
		return nil, err
	}
	t.leafHashes[0] = leafHash
	if err := t.rebuild(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *NullifierTree) Root() *big.Int {
	return new(big.Int).Set(t.root)
}

func (t *NullifierTree) NextIndex() uint64 {
	return uint64(len(t.elements))
}

func (t *NullifierTree) Insert(value *big.Int) error {
	if value == nil {
		return fmt.Errorf("spp: nullifier tree value is nil")
	}
	if !InNullifierDomain(value) {
		return fmt.Errorf("spp: nullifier tree value out of range: %s", value)
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
		return fmt.Errorf("spp: nullifier tree has no low element")
	}
	nextValue, err := t.elementNextValue(low)
	if err != nil {
		return err
	}
	if nextValue.Cmp(value) <= 0 {
		return fmt.Errorf("spp: nullifier tree value already present or outside low range: %s", value)
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

func (t *NullifierTree) InsertWithWitness(value *big.Int, height int) (NullifierInsertWitness, error) {
	if value == nil {
		return NullifierInsertWitness{}, fmt.Errorf("spp: nullifier tree value is nil")
	}
	if !InNullifierDomain(value) {
		return NullifierInsertWitness{}, fmt.Errorf("spp: nullifier tree value out of range: %s", value)
	}
	newIndex := uint64(len(t.elements))
	if height < 64 && newIndex >= 1<<height {
		return NullifierInsertWitness{}, fmt.Errorf("spp: new nullifier index %d exceeds 2^%d", newIndex, height)
	}

	low, err := t.lowElementForNonInclusion(value)
	if err != nil {
		return NullifierInsertWitness{}, err
	}
	nextValue, err := t.elementNextValue(low)
	if err != nil {
		return NullifierInsertWitness{}, err
	}
	if nextValue.Cmp(value) <= 0 {
		return NullifierInsertWitness{}, fmt.Errorf("spp: nullifier tree value already present or outside low range: %s", value)
	}

	entries := make(map[uint64]*big.Int, len(t.leafHashes))
	for index, leaf := range t.leafHashes {
		entries[index] = new(big.Int).Set(leaf)
	}
	_, oldProofs, err := buildSparseBinaryStateTree(entries, height)
	if err != nil {
		return NullifierInsertWitness{}, err
	}
	lowProof, ok := oldProofs[low.Index]
	if !ok {
		return NullifierInsertWitness{}, fmt.Errorf("spp: missing nullifier tree low-element proof")
	}

	afterLow := make(map[uint64]*big.Int, len(t.leafHashes)+1)
	for index, leaf := range t.leafHashes {
		afterLow[index] = new(big.Int).Set(leaf)
	}
	lowHash, err := indexedLeafHash(low.Value, value)
	if err != nil {
		return NullifierInsertWitness{}, err
	}
	afterLow[low.Index] = lowHash
	afterLow[newIndex] = new(big.Int)
	_, afterLowProofs, err := buildSparseBinaryStateTree(afterLow, height)
	if err != nil {
		return NullifierInsertWitness{}, err
	}
	newProof, ok := afterLowProofs[newIndex]
	if !ok {
		return NullifierInsertWitness{}, fmt.Errorf("spp: missing empty new-leaf proof")
	}

	if err := t.Insert(value); err != nil {
		return NullifierInsertWitness{}, err
	}

	return NullifierInsertWitness{
		LowValue:        new(big.Int).Set(low.Value),
		LowIndex:        low.Index,
		NextValue:       new(big.Int).Set(nextValue),
		LowElementProof: lowProof.PathElements,
		NewElementProof: newProof.PathElements,
	}, nil
}

func (t *NullifierTree) NonInclusionWitness(target *big.Int) (NonInclusionWitness, error) {
	if target == nil {
		return NonInclusionWitness{}, fmt.Errorf("spp: non-inclusion target is nil")
	}
	if !InNullifierDomain(target) {
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
		return NonInclusionWitness{}, fmt.Errorf("spp: missing nullifier tree low-element proof")
	}
	return NonInclusionWitness{
		Target:       new(big.Int).Set(target),
		LowValue:     new(big.Int).Set(low.Value),
		LowIndex:     low.Index,
		NextValue:    nextValue,
		PathElements: proof.PathElements,
		Root:         t.Root(),
	}, nil
}

func (t *NullifierTree) lowElementForNonInclusion(target *big.Int) (indexedElement, error) {
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
		return indexedElement{}, fmt.Errorf("spp: nullifier tree has no low element")
	}
	return low, nil
}

func (t *NullifierTree) elementNextValue(element indexedElement) (*big.Int, error) {
	if element.NextIndex == 0 {
		return new(big.Int).Set(nullifierUpperBound), nil
	}
	next, ok := t.elements[element.NextIndex]
	if !ok {
		return nil, fmt.Errorf("spp: nullifier tree missing next element")
	}
	return new(big.Int).Set(next.Value), nil
}

func (t *NullifierTree) rebuild() error {
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
