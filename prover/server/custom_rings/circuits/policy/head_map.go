package policy

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	merkletree "zolana/prover/merkle-tree"
)

const HeadMapHeight = 40

type headLeaf struct {
	member    frontend.Variable
	next      frontend.Variable
	nullifier frontend.Variable
}

type headRegistration struct {
	oldRoot  frontend.Variable
	low      headLeaf
	lowIndex frontend.Variable
	lowProof []frontend.Variable
	member   frontend.Variable
	genesis  frontend.Variable
	newIndex frontend.Variable
	newProof []frontend.Variable
}

func headMapEmptyLeaf() frontend.Variable {
	return frontend.Variable(new(big.Int).SetBytes(merkletree.ZERO_BYTES[0][:]))
}

func (l headLeaf) hash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{l.member, l.next, l.nullifier})
}

// Registration preserves the ordered member chain across both root updates.
func (r headRegistration) newRoot(api frontend.API) frontend.Variable {
	// 1. Prove absence between adjacent members and update their link.
	api.AssertIsDifferent(r.newIndex, 0)
	gadget.AssertStrictlyOrderedFullField(api, r.low.member, r.member, r.low.next)
	root := abstractor.Call(api, gadget.MerkleRootUpdateGadget{
		OldRoot:     r.oldRoot,
		OldLeaf:     r.low.hash(api),
		NewLeaf:     headLeaf{member: r.low.member, next: r.member, nullifier: r.low.nullifier}.hash(api),
		PathIndex:   api.ToBinary(r.lowIndex, HeadMapHeight),
		MerkleProof: r.lowProof,
		Height:      HeadMapHeight,
	})
	// 2. Prove the append slot empty under the updated predecessor root.
	return abstractor.Call(api, gadget.MerkleRootUpdateGadget{
		OldRoot:     root,
		OldLeaf:     headMapEmptyLeaf(),
		NewLeaf:     headLeaf{member: r.member, next: r.low.next, nullifier: r.genesis}.hash(api),
		PathIndex:   api.ToBinary(r.newIndex, HeadMapHeight),
		MerkleProof: r.newProof,
		Height:      HeadMapHeight,
	})
}
