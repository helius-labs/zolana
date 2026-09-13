package nullifiertreetest

import (
	"fmt"
	"math/big"

	merkletree "zolana/prover/merkle-tree"
	"zolana/prover/prover/nullifier_tree"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

// hashChain4 mirrors gadget.HashChain4: the head is the first element and
// every later group of up to three elements is absorbed by one 4-input
// Poseidon call, a partial trailing group zero-padded.
func hashChain4(elements []*big.Int) *big.Int {
	if len(elements) == 0 {
		return big.NewInt(0)
	}
	head := elements[0]
	for start := 1; start < len(elements); start += 3 {
		inputs := []*big.Int{head, big.NewInt(0), big.NewInt(0), big.NewInt(0)}
		for offset := 0; offset < 3 && start+offset < len(elements); offset++ {
			inputs[1+offset] = elements[start+offset]
		}
		head, _ = poseidon.Hash(inputs)
	}
	return head
}

func BuildTestAddressTree(treeHeight uint32, batchSize uint32, previousTree *merkletree.IndexedMerkleTree, startIndex uint64) (*nullifiertree.BatchAddressAppendParameters, error) {
	var tree *merkletree.IndexedMerkleTree

	if previousTree == nil {
		tree, _ = merkletree.NewIndexedMerkleTree(treeHeight)

		err := tree.Init()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize tree: %v", err)
		}
	} else {
		tree = previousTree.DeepCopy()
	}

	params := &nullifiertree.BatchAddressAppendParameters{
		PublicInputHash: new(big.Int),
		OldRoot:         new(big.Int),
		NewRoot:         new(big.Int),
		HashchainHash:   new(big.Int),
		StartIndex:      startIndex,
		TreeHeight:      treeHeight,
		BatchSize:       batchSize,
		Tree:            tree,

		LowElementValues:     make([]big.Int, batchSize),
		LowElementIndices:    make([]big.Int, batchSize),
		LowElementNextValues: make([]big.Int, batchSize),
		NewElementValues:     make([]big.Int, batchSize),

		LowElementProofs: make([][]big.Int, batchSize),
		NewElementProofs: make([][]big.Int, batchSize),
	}
	for i := uint32(0); i < batchSize; i++ {
		params.LowElementProofs[i] = make([]big.Int, treeHeight)
		params.NewElementProofs[i] = make([]big.Int, treeHeight)
	}

	oldRootValue := tree.Tree.Root.Value()
	params.OldRoot = &oldRootValue

	newValues := make([]*big.Int, batchSize)
	for i := uint32(0); i < batchSize; i++ {
		newValues[i] = new(big.Int).SetUint64(startIndex + uint64(i) + 2)
		lowElementIndex, _ := tree.IndexArray.FindLowElementIndex(newValues[i])
		lowElement := tree.IndexArray.Get(lowElementIndex)

		params.LowElementValues[i].Set(lowElement.Value)
		params.LowElementIndices[i].SetUint64(uint64(lowElement.Index))
		params.LowElementNextValues[i].Set(lowElement.NextValue)
		params.NewElementValues[i].Set(newValues[i])

		if proof, err := tree.GetProof(int(lowElement.Index)); err == nil {
			params.LowElementProofs[i] = make([]big.Int, len(proof))
			copy(params.LowElementProofs[i], proof)
		} else {
			return nil, fmt.Errorf("failed to get low element proof: %v", err)
		}

		newIndex := startIndex + uint64(i)

		if err := tree.Append(newValues[i]); err != nil {
			return nil, fmt.Errorf("failed to append value: %v", err)
		}
		if proof, err := tree.GetProof(int(newIndex)); err == nil {
			params.NewElementProofs[i] = make([]big.Int, len(proof))
			copy(params.NewElementProofs[i], proof)
		} else {
			return nil, fmt.Errorf("failed to get new element proof: %v", err)
		}
	}

	newRootValue := tree.Tree.Root.Value()
	params.NewRoot = &newRootValue

	params.HashchainHash = computeNewElementsHashChain(params.NewElementValues)
	params.PublicInputHash = computePublicInputHash(params.OldRoot, params.NewRoot, params.HashchainHash, params.StartIndex)

	return params, nil
}

func computeNewElementsHashChain(values []big.Int) *big.Int {
	elements := make([]*big.Int, len(values))
	for i := range values {
		elements[i] = &values[i]
	}
	return hashChain4(elements)
}

func computePublicInputHash(oldRoot *big.Int, newRoot *big.Int, hashchainHash *big.Int, startIndex uint64) *big.Int {
	return hashChain4([]*big.Int{
		oldRoot,
		newRoot,
		hashchainHash,
		new(big.Int).SetUint64(startIndex),
	})
}
