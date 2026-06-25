package circuits

import (
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

func (circuit *BatchAddressTreeAppendCircuit) Define(api frontend.API) error {
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
