package spp

import (
	"fmt"

	"light/light-prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const NullifierBatchUpdateCircuitType = common.SppNullifierUpdateCircuitType

type NullifierBatchUpdateCircuit struct {
	TreeHeight uint32 `gnark:"-"`
	BatchSize  uint32 `gnark:"-"`

	PublicInputHash frontend.Variable `gnark:",public"`

	OldRoot       frontend.Variable
	NewRoot       frontend.Variable
	HashchainHash frontend.Variable
	StartIndex    frontend.Variable

	LowElementValues     []frontend.Variable
	LowElementNextValues []frontend.Variable
	LowElementIndices    []frontend.Variable
	LowElementProofs     [][]frontend.Variable

	NewElementValues []frontend.Variable
	NewElementProofs [][]frontend.Variable
}

func NewNullifierBatchUpdateCircuit(treeHeight, batchSize uint32) *NullifierBatchUpdateCircuit {
	circuit := &NullifierBatchUpdateCircuit{
		TreeHeight:           treeHeight,
		BatchSize:            batchSize,
		LowElementValues:     make([]frontend.Variable, batchSize),
		LowElementNextValues: make([]frontend.Variable, batchSize),
		LowElementIndices:    make([]frontend.Variable, batchSize),
		LowElementProofs:     make([][]frontend.Variable, batchSize),
		NewElementValues:     make([]frontend.Variable, batchSize),
		NewElementProofs:     make([][]frontend.Variable, batchSize),
	}
	for i := uint32(0); i < batchSize; i++ {
		circuit.LowElementProofs[i] = make([]frontend.Variable, treeHeight)
		circuit.NewElementProofs[i] = make([]frontend.Variable, treeHeight)
	}
	return circuit
}

func (c *NullifierBatchUpdateCircuit) Define(api frontend.API) error {
	currentRoot := c.OldRoot
	for i := uint32(0); i < c.BatchSize; i++ {
		oldLowLeaf := IndexedLeafHashCircuit(api, c.LowElementValues[i], c.LowElementNextValues[i])
		newLowLeaf := IndexedLeafHashCircuit(api, c.LowElementValues[i], c.NewElementValues[i])

		// Strict order low < new < next, without a `+1` step that could wrap at
		// the field boundary.
		api.AssertIsLessOrEqual(c.LowElementValues[i], c.NewElementValues[i])
		api.AssertIsDifferent(c.LowElementValues[i], c.NewElementValues[i])
		api.AssertIsLessOrEqual(c.NewElementValues[i], c.LowElementNextValues[i])
		api.AssertIsDifferent(c.NewElementValues[i], c.LowElementNextValues[i])

		lowIndexBits := api.ToBinary(c.LowElementIndices[i], int(c.TreeHeight))
		oldLowRoot := StatePathFoldCircuit(api, oldLowLeaf, c.LowElementProofs[i], lowIndexBits)
		api.AssertIsEqual(oldLowRoot, currentRoot)
		currentRoot = StatePathFoldCircuit(api, newLowLeaf, c.LowElementProofs[i], lowIndexBits)

		newLeaf := IndexedLeafHashCircuit(api, c.NewElementValues[i], c.LowElementNextValues[i])
		newIndexBits := api.ToBinary(api.Add(c.StartIndex, i), int(c.TreeHeight))
		emptyRoot := StatePathFoldCircuit(api, frontend.Variable(0), c.NewElementProofs[i], newIndexBits)
		api.AssertIsEqual(emptyRoot, currentRoot)
		currentRoot = StatePathFoldCircuit(api, newLeaf, c.NewElementProofs[i], newIndexBits)
	}

	api.AssertIsEqual(c.NewRoot, currentRoot)
	api.AssertIsEqual(c.HashchainHash, HashChainCircuit(api, c.NewElementValues))
	api.AssertIsEqual(
		c.PublicInputHash,
		HashChainCircuit(api, []frontend.Variable{
			c.OldRoot,
			c.NewRoot,
			c.HashchainHash,
			c.StartIndex,
		}),
	)
	return nil
}

func SetupNullifierBatchUpdate(treeHeight, batchSize uint32) (*common.BatchProofSystem, error) {
	ccs, err := CompileNullifierBatchUpdate(treeHeight, batchSize)
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &common.BatchProofSystem{
		CircuitType:      NullifierBatchUpdateCircuitType,
		TreeHeight:       treeHeight,
		BatchSize:        batchSize,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}

func CompileNullifierBatchUpdate(treeHeight, batchSize uint32) (constraint.ConstraintSystem, error) {
	if treeHeight != NullifierTreeHeight {
		return nil, fmt.Errorf("spp nullifier update: tree height %d does not match SPP nullifier height %d", treeHeight, NullifierTreeHeight)
	}
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		NewNullifierBatchUpdateCircuit(treeHeight, batchSize),
		frontend.WithCompressThreshold(300),
	)
}
