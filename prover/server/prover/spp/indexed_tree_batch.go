package spp

import (
	"fmt"
	"math/big"
)

// nullifierBatchInsertWitness is the per-insert witness a nullifier batch update
// proves: the bracketing low element and the sibling paths for the low-leaf
// update and the new-leaf insertion.
type nullifierBatchInsertWitness struct {
	LowValue    *big.Int
	LowIndex    uint64
	NextValue   *big.Int
	LowSiblings []*big.Int
	NewSiblings []*big.Int
}

// insertWithBatchWitness inserts value into the indexed tree and returns the
// witness the batch-update circuit checks: the low element bracketing value,
// its proof against the pre-insert root, and the empty-slot proof for the new
// leaf against the post-low-update root.
func (t *IndexedTree) insertWithBatchWitness(value *big.Int, height int) (nullifierBatchInsertWitness, error) {
	if value.Sign() <= 0 || value.Cmp(highestNullifierPlusOne) >= 0 {
		return nullifierBatchInsertWitness{}, fmt.Errorf("spp: indexed tree value out of range: %s", value)
	}
	newIndex := uint64(len(t.Elements))
	if height < 64 && newIndex >= 1<<height {
		return nullifierBatchInsertWitness{}, fmt.Errorf("spp: new nullifier index %d exceeds 2^%d", newIndex, height)
	}

	low, err := t.lowElementForNonInclusion(value)
	if err != nil {
		return nullifierBatchInsertWitness{}, err
	}
	nextValue, err := t.elementNextValue(low)
	if err != nil {
		return nullifierBatchInsertWitness{}, err
	}
	if nextValue.Cmp(value) <= 0 {
		return nullifierBatchInsertWitness{}, fmt.Errorf("spp: indexed tree value already present or outside low range: %s", value)
	}

	entries := make(map[uint64]*big.Int, len(t.LeafHashes))
	for index, leaf := range t.LeafHashes {
		entries[index] = new(big.Int).Set(leaf)
	}
	_, oldProofs := buildSparseBinaryStateTree(entries, height)
	lowProof, ok := oldProofs[low.Index]
	if !ok {
		return nullifierBatchInsertWitness{}, fmt.Errorf("spp: missing indexed tree low-element proof")
	}

	afterLow := make(map[uint64]*big.Int, len(t.LeafHashes)+1)
	for index, leaf := range t.LeafHashes {
		afterLow[index] = new(big.Int).Set(leaf)
	}
	afterLow[low.Index] = IndexedLeafHash(low.Value, value)
	afterLow[newIndex] = new(big.Int)
	_, afterLowProofs := buildSparseBinaryStateTree(afterLow, height)
	newProof, ok := afterLowProofs[newIndex]
	if !ok {
		return nullifierBatchInsertWitness{}, fmt.Errorf("spp: missing empty new-leaf proof")
	}

	if err := t.InsertChecked(value); err != nil {
		return nullifierBatchInsertWitness{}, err
	}

	return nullifierBatchInsertWitness{
		LowValue:    new(big.Int).Set(low.Value),
		LowIndex:    low.Index,
		NextValue:   new(big.Int).Set(nextValue),
		LowSiblings: lowProof.Siblings,
		NewSiblings: newProof.Siblings,
	}, nil
}
