package spp

import (
	"fmt"
	"math/big"
)

type nullifierBatchUpdateAssignment struct {
	oldRoot              *big.Int
	newRoot              *big.Int
	hashchainHash        *big.Int
	startIndex           uint64
	publicInputHash      *big.Int
	lowElementValues     []*big.Int
	lowElementNextValues []*big.Int
	lowElementIndices    []*big.Int
	lowElementProofs     [][]*big.Int
	newElementValues     []*big.Int
	newElementProofs     [][]*big.Int
}

func buildNullifierBatchUpdateAssignment(treeHeight, batchSize uint32, request NullifierBatchUpdateRequest) (*nullifierBatchUpdateAssignment, error) {
	if treeHeight != NullifierTreeHeight {
		return nil, fmt.Errorf("spp nullifier update: tree height %d does not match SPP nullifier height %d", treeHeight, NullifierTreeHeight)
	}
	if len(request.NewEntries) != int(batchSize) {
		return nil, fmt.Errorf("spp nullifier update: new_entries length %d does not match batch size %d", len(request.NewEntries), batchSize)
	}
	tree := NewIndexedTree()
	for i, entry := range request.ExistingEntries {
		value, err := parseField(entry)
		if err != nil {
			return nil, fmt.Errorf("existing_entries[%d]: %w", i, err)
		}
		if err := tree.InsertChecked(value); err != nil {
			return nil, fmt.Errorf("existing_entries[%d]: %w", i, err)
		}
	}

	oldRoot := new(big.Int).Set(tree.Root)
	startIndex := uint64(len(tree.Elements))
	if startIndex+uint64(batchSize) > 1<<treeHeight {
		return nil, fmt.Errorf("spp nullifier update: batch exceeds tree capacity")
	}

	newValues := make([]*big.Int, batchSize)
	lowValues := make([]*big.Int, batchSize)
	lowNextValues := make([]*big.Int, batchSize)
	lowIndices := make([]*big.Int, batchSize)
	lowProofs := make([][]*big.Int, batchSize)
	newProofs := make([][]*big.Int, batchSize)

	for i, entry := range request.NewEntries {
		value, err := parseField(entry)
		if err != nil {
			return nil, fmt.Errorf("new_entries[%d]: %w", i, err)
		}
		witness, err := tree.insertWithBatchWitness(value, int(treeHeight))
		if err != nil {
			return nil, fmt.Errorf("new_entries[%d]: %w", i, err)
		}
		newValues[i] = value
		lowValues[i] = witness.LowValue
		lowNextValues[i] = witness.NextValue
		lowIndices[i] = new(big.Int).SetUint64(witness.LowIndex)
		lowProofs[i] = witness.LowSiblings
		newProofs[i] = witness.NewSiblings
	}

	hashchain, err := HashChain(newValues)
	if err != nil {
		return nil, err
	}
	startIndexField := new(big.Int).SetUint64(startIndex)
	publicInputHash, err := HashChain([]*big.Int{
		oldRoot,
		tree.Root,
		hashchain,
		startIndexField,
	})
	if err != nil {
		return nil, err
	}

	return &nullifierBatchUpdateAssignment{
		oldRoot:              oldRoot,
		newRoot:              new(big.Int).Set(tree.Root),
		hashchainHash:        hashchain,
		startIndex:           startIndex,
		publicInputHash:      publicInputHash,
		lowElementValues:     lowValues,
		lowElementNextValues: lowNextValues,
		lowElementIndices:    lowIndices,
		lowElementProofs:     lowProofs,
		newElementValues:     newValues,
		newElementProofs:     newProofs,
	}, nil
}

func (a *nullifierBatchUpdateAssignment) toCircuit(treeHeight, batchSize uint32) *NullifierBatchUpdateCircuit {
	circuit := NewNullifierBatchUpdateCircuit(treeHeight, batchSize)
	circuit.PublicInputHash = a.publicInputHash
	circuit.OldRoot = a.oldRoot
	circuit.NewRoot = a.newRoot
	circuit.HashchainHash = a.hashchainHash
	circuit.StartIndex = new(big.Int).SetUint64(a.startIndex)
	for i := 0; i < int(batchSize); i++ {
		circuit.LowElementValues[i] = a.lowElementValues[i]
		circuit.LowElementNextValues[i] = a.lowElementNextValues[i]
		circuit.LowElementIndices[i] = a.lowElementIndices[i]
		circuit.NewElementValues[i] = a.newElementValues[i]
		for j := 0; j < int(treeHeight); j++ {
			circuit.LowElementProofs[i][j] = a.lowElementProofs[i][j]
			circuit.NewElementProofs[i][j] = a.newElementProofs[i][j]
		}
	}
	return circuit
}
