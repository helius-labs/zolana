package gadget

import (
	"github.com/consensys/gnark/frontend"

	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// NullifierTree selects the tree hash: Poseidon2 for the nullifier tree,
// Poseidon for the state tree.
type ProveParentHash struct {
	Bit           frontend.Variable
	Hash          frontend.Variable
	Sibling       frontend.Variable
	NullifierTree bool
}

func (gadget ProveParentHash) DefineGadget(api frontend.API) interface{} {
	api.AssertIsBoolean(gadget.Bit)
	d1 := api.Select(gadget.Bit, gadget.Sibling, gadget.Hash)
	d2 := api.Select(gadget.Bit, gadget.Hash, gadget.Sibling)
	if gadget.NullifierTree {
		return NullifierTreeHash(api, d1, d2)
	}
	return PoseidonHash(api, []frontend.Variable{d1, d2})
}

type MerkleRootGadget struct {
	Hash          frontend.Variable
	Index         []frontend.Variable
	Path          []frontend.Variable
	Height        int
	NullifierTree bool
}

func (gadget MerkleRootGadget) DefineGadget(api frontend.API) interface{} {
	currentHash := gadget.Hash
	for i := 0; i < gadget.Height; i++ {
		currentHash = abstractor.Call(api, ProveParentHash{
			Bit:           gadget.Index[i],
			Hash:          currentHash,
			Sibling:       gadget.Path[i],
			NullifierTree: gadget.NullifierTree,
		})
	}
	return currentHash
}

// MerkleRootUpdateGadget updates the nullifier tree.
type MerkleRootUpdateGadget struct {
	OldRoot     frontend.Variable
	OldLeaf     frontend.Variable
	NewLeaf     frontend.Variable
	PathIndex   []frontend.Variable
	MerkleProof []frontend.Variable
	Height      int
}

func (gadget MerkleRootUpdateGadget) DefineGadget(api frontend.API) interface{} {
	oldRoot := abstractor.Call(api, MerkleRootGadget{
		Hash:          gadget.OldLeaf,
		Index:         gadget.PathIndex,
		Path:          gadget.MerkleProof,
		Height:        gadget.Height,
		NullifierTree: true,
	})
	api.AssertIsEqual(oldRoot, gadget.OldRoot)

	newRoot := abstractor.Call(api, MerkleRootGadget{
		Hash:          gadget.NewLeaf,
		Index:         gadget.PathIndex,
		Path:          gadget.MerkleProof,
		Height:        gadget.Height,
		NullifierTree: true,
	})
	return newRoot
}
