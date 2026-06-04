package nullifierbatchupdate

import (
	"fmt"

	"light/light-prover/prover/spp/circuit/gadget"
	"light/light-prover/prover/spp/model"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Circuit verifies a nullifier indexed-tree batch update.
type Circuit struct {
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

func NewCircuit(treeHeight, batchSize uint32) *Circuit {
	circuit := &Circuit{
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

func (c *Circuit) Define(api frontend.API) error {
	currentRoot := c.OldRoot
	for i := uint32(0); i < c.BatchSize; i++ {
		oldLowLeaf := gadget.IndexedLeafHash(api, c.LowElementValues[i], c.LowElementNextValues[i])
		newLowLeaf := gadget.IndexedLeafHash(api, c.LowElementValues[i], c.NewElementValues[i])

		api.AssertIsLessOrEqual(api.Add(c.LowElementValues[i], 1), c.NewElementValues[i])
		api.AssertIsLessOrEqual(api.Add(c.NewElementValues[i], 1), c.LowElementNextValues[i])

		lowIndexBits := api.ToBinary(c.LowElementIndices[i], int(c.TreeHeight))
		oldLowRoot := gadget.StatePathFold(api, oldLowLeaf, c.LowElementProofs[i], lowIndexBits)
		api.AssertIsEqual(oldLowRoot, currentRoot)
		currentRoot = gadget.StatePathFold(api, newLowLeaf, c.LowElementProofs[i], lowIndexBits)

		newLeaf := gadget.IndexedLeafHash(api, c.NewElementValues[i], c.LowElementNextValues[i])
		newIndexBits := api.ToBinary(api.Add(c.StartIndex, i), int(c.TreeHeight))
		emptyRoot := gadget.StatePathFold(api, frontend.Variable(0), c.NewElementProofs[i], newIndexBits)
		api.AssertIsEqual(emptyRoot, currentRoot)
		currentRoot = gadget.StatePathFold(api, newLeaf, c.NewElementProofs[i], newIndexBits)
	}

	api.AssertIsEqual(c.NewRoot, currentRoot)
	api.AssertIsEqual(c.HashchainHash, gadget.HashChain(api, c.NewElementValues))
	api.AssertIsEqual(
		c.PublicInputHash,
		gadget.HashChain(api, []frontend.Variable{
			c.OldRoot,
			c.NewRoot,
			c.HashchainHash,
			c.StartIndex,
		}),
	)
	return nil
}

func Compile(treeHeight, batchSize uint32) (constraint.ConstraintSystem, error) {
	if treeHeight != model.NullifierTreeHeight {
		return nil, fmt.Errorf("spp nullifier update: tree height %d does not match SPP nullifier height %d", treeHeight, model.NullifierTreeHeight)
	}
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		NewCircuit(treeHeight, batchSize),
		frontend.WithCompressThreshold(300),
	)
}
