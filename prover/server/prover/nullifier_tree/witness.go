package nullifiertree

import (
	"fmt"

	circuit "zolana/prover/circuits"
	"zolana/prover/logging"

	"github.com/consensys/gnark/frontend"
)

func InitBatchAddressTreeAppendCircuit(treeHeight uint32, batchSize uint32) circuit.BatchAddressTreeAppendCircuit {
	logging.Logger().Info().
		Uint32("treeHeight", treeHeight).
		Uint32("batchSize", batchSize).
		Msg("Initializing batch address append circuit")

	lowElementValues := make([]frontend.Variable, batchSize)
	lowElementNextValues := make([]frontend.Variable, batchSize)
	lowElementIndices := make([]frontend.Variable, batchSize)
	lowElementProofs := make([][]frontend.Variable, batchSize)
	newElementValues := make([]frontend.Variable, batchSize)
	newElementProofs := make([][]frontend.Variable, batchSize)

	for i := uint32(0); i < batchSize; i++ {
		lowElementProofs[i] = make([]frontend.Variable, treeHeight)
		newElementProofs[i] = make([]frontend.Variable, treeHeight)
	}

	return circuit.BatchAddressTreeAppendCircuit{
		BatchSize:            batchSize,
		TreeHeight:           treeHeight,
		PublicInputHash:      frontend.Variable(0),
		OldRoot:              frontend.Variable(0),
		NewRoot:              frontend.Variable(0),
		HashchainHash:        frontend.Variable(0),
		StartIndex:           frontend.Variable(0),
		LowElementValues:     lowElementValues,
		LowElementNextValues: lowElementNextValues,
		LowElementIndices:    lowElementIndices,
		LowElementProofs:     lowElementProofs,
		NewElementValues:     newElementValues,
		NewElementProofs:     newElementProofs,
	}
}

func (params *BatchAddressAppendParameters) CreateWitness() (*circuit.BatchAddressTreeAppendCircuit, error) {
	if params.BatchSize == 0 {
		return nil, fmt.Errorf("batch size cannot be 0")
	}
	if params.TreeHeight == 0 {
		return nil, fmt.Errorf("tree height cannot be 0")
	}

	circuit := &circuit.BatchAddressTreeAppendCircuit{
		BatchSize:            params.BatchSize,
		TreeHeight:           params.TreeHeight,
		PublicInputHash:      frontend.Variable(params.PublicInputHash),
		OldRoot:              frontend.Variable(params.OldRoot),
		NewRoot:              frontend.Variable(params.NewRoot),
		HashchainHash:        frontend.Variable(params.HashchainHash),
		StartIndex:           frontend.Variable(params.StartIndex),
		LowElementValues:     make([]frontend.Variable, params.BatchSize),
		LowElementNextValues: make([]frontend.Variable, params.BatchSize),
		LowElementIndices:    make([]frontend.Variable, params.BatchSize),
		NewElementValues:     make([]frontend.Variable, params.BatchSize),
		LowElementProofs:     make([][]frontend.Variable, params.BatchSize),
		NewElementProofs:     make([][]frontend.Variable, params.BatchSize),
	}

	for i := uint32(0); i < params.BatchSize; i++ {
		circuit.LowElementProofs[i] = make([]frontend.Variable, params.TreeHeight)
		circuit.NewElementProofs[i] = make([]frontend.Variable, params.TreeHeight)
	}

	for i := uint32(0); i < params.BatchSize; i++ {
		circuit.LowElementValues[i] = frontend.Variable(&params.LowElementValues[i])
		circuit.LowElementNextValues[i] = frontend.Variable(&params.LowElementNextValues[i])
		circuit.LowElementIndices[i] = frontend.Variable(&params.LowElementIndices[i])
		circuit.NewElementValues[i] = frontend.Variable(&params.NewElementValues[i])

		for j := uint32(0); j < params.TreeHeight; j++ {
			circuit.LowElementProofs[i][j] = frontend.Variable(&params.LowElementProofs[i][j])
			circuit.NewElementProofs[i][j] = frontend.Variable(&params.NewElementProofs[i][j])
		}
	}

	return circuit, nil
}
