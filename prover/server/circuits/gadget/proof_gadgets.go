package gadget

import (
	"github.com/consensys/gnark/frontend"

	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

type ProveParentHash struct {
	Bit     frontend.Variable
	Hash    frontend.Variable
	Sibling frontend.Variable
}

func (gadget ProveParentHash) DefineGadget(api frontend.API) interface{} {
	api.AssertIsBoolean(gadget.Bit)
	d1 := api.Select(gadget.Bit, gadget.Sibling, gadget.Hash)
	d2 := api.Select(gadget.Bit, gadget.Hash, gadget.Sibling)
	hash := PoseidonHash(api, []frontend.Variable{d1, d2})
	return hash
}

type MerkleRootGadget struct {
	Hash   frontend.Variable
	Index  []frontend.Variable
	Path   []frontend.Variable
	Height int
}

func (gadget MerkleRootGadget) DefineGadget(api frontend.API) interface{} {
	currentHash := gadget.Hash
	for i := 0; i < gadget.Height; i++ {
		currentHash = abstractor.Call(api, ProveParentHash{
			Bit:     gadget.Index[i],
			Hash:    currentHash,
			Sibling: gadget.Path[i],
		})
	}
	return currentHash
}

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
		Hash:   gadget.OldLeaf,
		Index:  gadget.PathIndex,
		Path:   gadget.MerkleProof,
		Height: gadget.Height,
	})
	api.AssertIsEqual(oldRoot, gadget.OldRoot)

	newRoot := abstractor.Call(api, MerkleRootGadget{
		Hash:   gadget.NewLeaf,
		Index:  gadget.PathIndex,
		Path:   gadget.MerkleProof,
		Height: gadget.Height,
	})
	return newRoot
}
