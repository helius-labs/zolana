package registry

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	merkletree "zolana/prover/merkle-tree"
)

// Leaf links members in ascending order, Key is Poseidon(nullifierPk, ctHash).
type Leaf struct {
	Member frontend.Variable
	Next   frontend.Variable
	Key    frontend.Variable
}

// Insertion places Member between Low and its successor at the append slot NewIndex.
type Insertion struct {
	OldRoot  frontend.Variable
	Low      Leaf
	LowIndex frontend.Variable
	LowProof []frontend.Variable
	Member   frontend.Variable
	Key      frontend.Variable
	NewIndex frontend.Variable
	NewProof []frontend.Variable
}

func (l Leaf) Hash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{l.Member, l.Next, l.Key})
}

// NewRoot preserves the ordered member chain across both root updates.
func (r Insertion) NewRoot(api frontend.API) frontend.Variable {
	// 1. Prove absence between adjacent members and update their link.
	api.AssertIsDifferent(r.NewIndex, 0)
	gadget.AssertStrictlyOrderedFullField(api, r.Low.Member, r.Member, r.Low.Next)
	root := abstractor.Call(api, gadget.MerkleRootUpdateGadget{
		OldRoot:     r.OldRoot,
		OldLeaf:     r.Low.Hash(api),
		NewLeaf:     Leaf{Member: r.Low.Member, Next: r.Member, Key: r.Low.Key}.Hash(api),
		PathIndex:   api.ToBinary(r.LowIndex, Height),
		MerkleProof: r.LowProof,
		Height:      Height,
	})
	// 2. Prove the append slot empty under the updated predecessor root.
	return abstractor.Call(api, gadget.MerkleRootUpdateGadget{
		OldRoot:     root,
		OldLeaf:     emptyLeaf(),
		NewLeaf:     Leaf{Member: r.Member, Next: r.Low.Next, Key: r.Key}.Hash(api),
		PathIndex:   api.ToBinary(r.NewIndex, Height),
		MerkleProof: r.NewProof,
		Height:      Height,
	})
}

func emptyLeaf() frontend.Variable {
	return frontend.Variable(new(big.Int).SetBytes(merkletree.ZERO_BYTES[0][:]))
}
