package gadget

import (
	"github.com/consensys/gnark/frontend"

	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// The state tree and the nullifier tree hash their nodes differently
// (Poseidon and Poseidon2), so they get separate gadget types. The Lean
// extractor identifies a gadget by its type name and array lengths only; a
// field selecting the hash would extract one body for both trees.

// ProveParentHash is a state tree node.
type ProveParentHash struct {
	Bit     frontend.Variable
	Hash    frontend.Variable
	Sibling frontend.Variable
}

func (gadget ProveParentHash) DefineGadget(api frontend.API) interface{} {
	left, right := orderChildren(api, gadget.Bit, gadget.Hash, gadget.Sibling)
	return PoseidonHash(api, []frontend.Variable{left, right})
}

// NullifierParentHash is a nullifier tree node.
type NullifierParentHash struct {
	Bit     frontend.Variable
	Hash    frontend.Variable
	Sibling frontend.Variable
}

func (gadget NullifierParentHash) DefineGadget(api frontend.API) interface{} {
	left, right := orderChildren(api, gadget.Bit, gadget.Hash, gadget.Sibling)
	return NullifierTreeHash(api, left, right)
}

func orderChildren(api frontend.API, bit, hash, sibling frontend.Variable) (frontend.Variable, frontend.Variable) {
	api.AssertIsBoolean(bit)
	return api.Select(bit, sibling, hash), api.Select(bit, hash, sibling)
}

// MerkleRootGadget folds a state tree path.
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

// NullifierMerkleRootGadget folds a nullifier tree path.
type NullifierMerkleRootGadget struct {
	Hash   frontend.Variable
	Index  []frontend.Variable
	Path   []frontend.Variable
	Height int
}

func (gadget NullifierMerkleRootGadget) DefineGadget(api frontend.API) interface{} {
	currentHash := gadget.Hash
	for i := 0; i < gadget.Height; i++ {
		currentHash = abstractor.Call(api, NullifierParentHash{
			Bit:     gadget.Index[i],
			Hash:    currentHash,
			Sibling: gadget.Path[i],
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
	oldRoot := abstractor.Call(api, NullifierMerkleRootGadget{
		Hash:   gadget.OldLeaf,
		Index:  gadget.PathIndex,
		Path:   gadget.MerkleProof,
		Height: gadget.Height,
	})
	api.AssertIsEqual(oldRoot, gadget.OldRoot)

	newRoot := abstractor.Call(api, NullifierMerkleRootGadget{
		Hash:   gadget.NewLeaf,
		Index:  gadget.PathIndex,
		Path:   gadget.MerkleProof,
		Height: gadget.Height,
	})
	return newRoot
}
