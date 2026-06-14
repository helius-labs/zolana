package nullifiertreetest

import (
	"fmt"
	"math/big"

	merkletree "zolana/prover/merkle-tree"
	"zolana/prover/prover/nullifier_tree"
)

// BuildAddressAppendParamsFromValues builds the batch-address-append witness
// for an EXPLICIT, ordered list of values appended to a fresh AddressV2 tree
// (init element {0, 2^248-1} at index 0, next_index 1). Unlike
// BuildTestAddressTree, which fabricates sequential values, this replays the
// exact values a caller queued, so the resulting proof/new_root match what the
// on-chain light-batched-merkle-tree produces for the same queue. startIndex is
// the tree's next_index when the batch is processed (1 for the first batch
// after init); values are appended at startIndex, startIndex+1, ...
func BuildAddressAppendParamsFromValues(
	treeHeight uint32,
	values []*big.Int,
	startIndex uint64,
) (*nullifiertree.BatchAddressAppendParameters, error) {
	batchSize := uint32(len(values))
	if batchSize == 0 {
		return nil, fmt.Errorf("v2: address-append needs at least one value")
	}

	tree, err := merkletree.NewIndexedMerkleTree(treeHeight)
	if err != nil {
		return nil, fmt.Errorf("v2: new indexed tree: %w", err)
	}
	if err := tree.Init(); err != nil {
		return nil, fmt.Errorf("v2: init indexed tree: %w", err)
	}

	params := &nullifiertree.BatchAddressAppendParameters{
		StartIndex: startIndex,
		TreeHeight: treeHeight,
		BatchSize:  batchSize,
		Tree:       tree,

		LowElementValues:     make([]big.Int, batchSize),
		LowElementIndices:    make([]big.Int, batchSize),
		LowElementNextValues: make([]big.Int, batchSize),
		NewElementValues:     make([]big.Int, batchSize),
		LowElementProofs:     make([][]big.Int, batchSize),
		NewElementProofs:     make([][]big.Int, batchSize),
	}

	oldRoot := tree.Tree.Root.Value()
	params.OldRoot = &oldRoot

	for i, value := range values {
		lowElementIndex, err := tree.IndexArray.FindLowElementIndex(value)
		if err != nil {
			return nil, fmt.Errorf("v2: find low element for value %d: %w", i, err)
		}
		lowElement := tree.IndexArray.Get(lowElementIndex)

		params.LowElementValues[i].Set(lowElement.Value)
		params.LowElementIndices[i].SetUint64(uint64(lowElement.Index))
		params.LowElementNextValues[i].Set(lowElement.NextValue)
		params.NewElementValues[i].Set(value)

		lowProof, err := tree.GetProof(int(lowElement.Index))
		if err != nil {
			return nil, fmt.Errorf("v2: low element proof %d: %w", i, err)
		}
		params.LowElementProofs[i] = make([]big.Int, len(lowProof))
		copy(params.LowElementProofs[i], lowProof)

		newIndex := startIndex + uint64(i)
		if err := tree.Append(value); err != nil {
			return nil, fmt.Errorf("v2: append value %d: %w", i, err)
		}
		newProof, err := tree.GetProof(int(newIndex))
		if err != nil {
			return nil, fmt.Errorf("v2: new element proof %d: %w", i, err)
		}
		params.NewElementProofs[i] = make([]big.Int, len(newProof))
		copy(params.NewElementProofs[i], newProof)
	}

	newRoot := tree.Tree.Root.Value()
	params.NewRoot = &newRoot
	params.HashchainHash = computeNewElementsHashChain(params.NewElementValues)
	params.PublicInputHash = computePublicInputHash(
		params.OldRoot, params.NewRoot, params.HashchainHash, params.StartIndex,
	)
	return params, nil
}
