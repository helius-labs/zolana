package circuits

import (
	"fmt"
	"math/big"

	"zolana/prover/circuits/gadget"
	merkletree "zolana/prover/merkle-tree"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

type BatchAddressTreeAppendCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	OldRoot       frontend.Variable `gnark:",secret"`
	NewRoot       frontend.Variable `gnark:",secret"`
	HashchainHash frontend.Variable `gnark:",secret"`
	StartIndex    frontend.Variable `gnark:",secret"`

	LowElementValues     []frontend.Variable   `gnark:",secret"`
	LowElementNextValues []frontend.Variable   `gnark:",secret"`
	LowElementIndices    []frontend.Variable   `gnark:",secret"`
	LowElementProofs     [][]frontend.Variable `gnark:",secret"`

	NewElementValues []frontend.Variable   `gnark:",secret"`
	NewElementProofs [][]frontend.Variable `gnark:",secret"`
	BatchSize        uint32
	TreeHeight       uint32
}

// ValidateLayout checks the six element slices against BatchSize and each proof
// row against TreeHeight before Define adds any constraints.
//
// BatchSize and TreeHeight are template constants fixed at trusted setup. They
// size the compiled constraint system, and gnark rejects a witness whose slice
// lengths differ from the compiled schema, so only the template used for key
// generation can be malformed. HashChain commits to all of NewElementValues
// while the update loop inserts the first BatchSize elements. A template with a
// longer slice would compile into a key whose hashchain covers elements the
// tree update skips. Running the check inside Define also covers templates
// built directly rather than through the prover constructors.
func (circuit *BatchAddressTreeAppendCircuit) ValidateLayout() error {
	if circuit.BatchSize == 0 {
		return fmt.Errorf("address append: BatchSize must be >= 1")
	}
	if circuit.TreeHeight == 0 {
		return fmt.Errorf("address append: TreeHeight must be >= 1")
	}
	batchSize := int(circuit.BatchSize)
	checks := []struct {
		name string
		got  int
	}{
		{"low element value", len(circuit.LowElementValues)},
		{"low element next value", len(circuit.LowElementNextValues)},
		{"low element index", len(circuit.LowElementIndices)},
		{"low element proof", len(circuit.LowElementProofs)},
		{"new element value", len(circuit.NewElementValues)},
		{"new element proof", len(circuit.NewElementProofs)},
	}
	for _, check := range checks {
		if check.got != batchSize {
			return fmt.Errorf(
				"address append: %s count mismatch: got %d want %d",
				check.name,
				check.got,
				batchSize,
			)
		}
	}
	treeHeight := int(circuit.TreeHeight)
	for i := 0; i < batchSize; i++ {
		if got := len(circuit.LowElementProofs[i]); got != treeHeight {
			return fmt.Errorf(
				"address append: low element proof %d height: got %d want %d",
				i,
				got,
				treeHeight,
			)
		}
		if got := len(circuit.NewElementProofs[i]); got != treeHeight {
			return fmt.Errorf(
				"address append: new element proof %d height: got %d want %d",
				i,
				got,
				treeHeight,
			)
		}
	}
	return nil
}

func (circuit *BatchAddressTreeAppendCircuit) Define(api frontend.API) error {
	if err := circuit.ValidateLayout(); err != nil {
		return err
	}
	currentRoot := circuit.OldRoot

	for i := uint32(0); i < circuit.BatchSize; i++ {
		gadget.AssertStrictlyOrderedFullField(
			api,
			circuit.LowElementValues[i],
			circuit.NewElementValues[i],
			circuit.LowElementNextValues[i],
		)

		oldLowLeafHash := gadget.IndexedLeafHash(
			api,
			circuit.LowElementValues[i],
			circuit.LowElementNextValues[i],
		)

		lowLeafHash := gadget.PoseidonHash(api, []frontend.Variable{
			circuit.LowElementValues[i],
			circuit.NewElementValues[i],
		})

		pathIndexBits := api.ToBinary(circuit.LowElementIndices[i], int(circuit.TreeHeight))
		currentRoot = abstractor.Call(api, gadget.MerkleRootUpdateGadget{
			OldRoot:     currentRoot,
			OldLeaf:     oldLowLeafHash,
			NewLeaf:     lowLeafHash,
			PathIndex:   pathIndexBits,
			MerkleProof: circuit.LowElementProofs[i],
			Height:      int(circuit.TreeHeight),
		})

		// value = new value
		// next value is low leaf next value
		// next index is new value next index
		newLeafHash := gadget.PoseidonHash(api, []frontend.Variable{
			circuit.NewElementValues[i],
			circuit.LowElementNextValues[i],
		})

		indexBits := api.ToBinary(api.Add(circuit.StartIndex, i), int(circuit.TreeHeight))
		currentRoot = abstractor.Call(api, gadget.MerkleRootUpdateGadget{
			OldRoot:     currentRoot,
			OldLeaf:     getZeroValue(0),
			NewLeaf:     newLeafHash,
			PathIndex:   indexBits,
			MerkleProof: circuit.NewElementProofs[i],
			Height:      int(circuit.TreeHeight),
		})
	}

	api.AssertIsEqual(circuit.NewRoot, currentRoot)

	leavesHashChain := gadget.HashChain(api, circuit.NewElementValues)
	api.AssertIsEqual(circuit.HashchainHash, leavesHashChain)

	publicInputsHashChain := circuit.computePublicInputHash(api)
	api.AssertIsEqual(circuit.PublicInputHash, publicInputsHashChain)

	return nil
}

func (circuit *BatchAddressTreeAppendCircuit) computePublicInputHash(api frontend.API) frontend.Variable {
	hashChainInputs := []frontend.Variable{
		circuit.OldRoot,
		circuit.NewRoot,
		circuit.HashchainHash,
		circuit.StartIndex,
	}

	return gadget.HashChain(api, hashChainInputs)
}

// getZeroValue returns the zero value for a given tree level
func getZeroValue(level int) frontend.Variable {
	return frontend.Variable(new(big.Int).SetBytes(merkletree.ZERO_BYTES[level][:]))
}
