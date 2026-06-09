package nullifierbatchupdate

import (
	"fmt"

	"light/light-prover/prover/spp/circuit/gadget"
	"light/light-prover/prover/spp/protocol"

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

// assertStrictlyOrdered constrains lo < mid < hi. It uses AssertIsLessOrEqual
// plus AssertIsDifferent rather than an `lo+1 <= mid` step: the latter adds 1
// in the field, so a value near the modulus wraps to a small one and bypasses
// the comparison. Mirrors the transaction circuit's assertStrictlyOrdered.
func assertStrictlyOrdered(api frontend.API, lo, mid, hi frontend.Variable) {
	api.AssertIsLessOrEqual(lo, mid)
	api.AssertIsDifferent(lo, mid)
	api.AssertIsLessOrEqual(mid, hi)
	api.AssertIsDifferent(mid, hi)
}

func (c *Circuit) Define(api frontend.API) error {
	if err := c.validateLayout(); err != nil {
		return err
	}

	currentRoot := c.OldRoot
	for i := uint32(0); i < c.BatchSize; i++ {
		oldLowLeaf := gadget.IndexedLeafHash(api, c.LowElementValues[i], c.LowElementNextValues[i])
		newLowLeaf := gadget.IndexedLeafHash(api, c.LowElementValues[i], c.NewElementValues[i])

		// The inserted value must sit strictly between its low element and that
		// element's current next pointer: low < new < next.
		assertStrictlyOrdered(api, c.LowElementValues[i], c.NewElementValues[i], c.LowElementNextValues[i])

		lowIndexBits := api.ToBinary(c.LowElementIndices[i], int(c.TreeHeight))
		oldLowRoot := gadget.MerkleRoot(api, oldLowLeaf, c.LowElementProofs[i], lowIndexBits)
		api.AssertIsEqual(oldLowRoot, currentRoot)
		currentRoot = gadget.MerkleRoot(api, newLowLeaf, c.LowElementProofs[i], lowIndexBits)

		newLeaf := gadget.IndexedLeafHash(api, c.NewElementValues[i], c.LowElementNextValues[i])
		newIndexBits := api.ToBinary(api.Add(c.StartIndex, i), int(c.TreeHeight))
		emptyRoot := gadget.MerkleRoot(api, frontend.Variable(0), c.NewElementProofs[i], newIndexBits)
		api.AssertIsEqual(emptyRoot, currentRoot)
		currentRoot = gadget.MerkleRoot(api, newLeaf, c.NewElementProofs[i], newIndexBits)
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

func (c *Circuit) validateLayout() error {
	if c.TreeHeight != protocol.NullifierTreeHeight {
		return fmt.Errorf("spp nullifier update: tree height %d does not match SPP nullifier height %d", c.TreeHeight, protocol.NullifierTreeHeight)
	}
	if c.BatchSize == 0 {
		return fmt.Errorf("spp nullifier update: batch size must be positive")
	}

	batchSize := int(c.BatchSize)
	if len(c.LowElementValues) != batchSize {
		return fmt.Errorf("spp nullifier update: low value count mismatch: got %d want %d", len(c.LowElementValues), batchSize)
	}
	if len(c.LowElementNextValues) != batchSize {
		return fmt.Errorf("spp nullifier update: low next-value count mismatch: got %d want %d", len(c.LowElementNextValues), batchSize)
	}
	if len(c.LowElementIndices) != batchSize {
		return fmt.Errorf("spp nullifier update: low index count mismatch: got %d want %d", len(c.LowElementIndices), batchSize)
	}
	if len(c.LowElementProofs) != batchSize {
		return fmt.Errorf("spp nullifier update: low proof count mismatch: got %d want %d", len(c.LowElementProofs), batchSize)
	}
	if len(c.NewElementValues) != batchSize {
		return fmt.Errorf("spp nullifier update: new value count mismatch: got %d want %d", len(c.NewElementValues), batchSize)
	}
	if len(c.NewElementProofs) != batchSize {
		return fmt.Errorf("spp nullifier update: new proof count mismatch: got %d want %d", len(c.NewElementProofs), batchSize)
	}

	height := int(c.TreeHeight)
	for i := 0; i < batchSize; i++ {
		if len(c.LowElementProofs[i]) != height {
			return fmt.Errorf("spp nullifier update: low proof %d height mismatch: got %d want %d", i, len(c.LowElementProofs[i]), height)
		}
		if len(c.NewElementProofs[i]) != height {
			return fmt.Errorf("spp nullifier update: new proof %d height mismatch: got %d want %d", i, len(c.NewElementProofs[i]), height)
		}
	}
	return nil
}

func Compile(treeHeight, batchSize uint32) (constraint.ConstraintSystem, error) {
	if treeHeight != protocol.NullifierTreeHeight {
		return nil, fmt.Errorf("spp nullifier update: tree height %d does not match SPP nullifier height %d", treeHeight, protocol.NullifierTreeHeight)
	}
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		NewCircuit(treeHeight, batchSize),
		frontend.WithCompressThreshold(300),
	)
}
