package policy

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	merkletree "zolana/prover/merkle-tree"
)

// Member ordering is independent of the physical append position.
const HeadMapHeight = 40

// headMapEmptyLeaf is the value at an unoccupied position, the insert target.
func headMapEmptyLeaf() frontend.Variable {
	return frontend.Variable(new(big.Int).SetBytes(merkletree.ZERO_BYTES[0][:]))
}

// headMapLeaf binds a member to its successor pointer and current nullifier.
func headMapLeaf(api frontend.API, member, next, nullifier frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{member, next, nullifier})
}

// Membership authenticates the consumed nullifier while preserving member ordering.
func constrainHeadTransition(
	api frontend.API,
	oldRoot, member, next, spent, successor, index frontend.Variable,
	proof []frontend.Variable,
) frontend.Variable {
	// 1. Exclude the sentinel and require canonical member ordering.
	api.AssertIsDifferent(index, 0)
	gadget.AssertStrictlyOrderedFullField(api, 0, member, next)
	// 2. Replace only the authenticated record nullifier at the same position.
	return abstractor.Call(api, gadget.MerkleRootUpdateGadget{
		OldRoot:     oldRoot,
		OldLeaf:     headMapLeaf(api, member, next, spent),
		NewLeaf:     headMapLeaf(api, member, next, successor),
		PathIndex:   api.ToBinary(index, HeadMapHeight),
		MerkleProof: proof,
		Height:      HeadMapHeight,
	})
}

// Registration preserves the ordered member chain across both root updates.
func constrainHeadRegistration(
	api frontend.API,
	oldRoot frontend.Variable,
	lowMember, lowNext, lowNullifier, lowIndex frontend.Variable,
	lowProof []frontend.Variable,
	member, genesis, newIndex frontend.Variable,
	newProof []frontend.Variable,
) frontend.Variable {
	// 1. Prove absence between the authenticated predecessor and its successor.
	api.AssertIsDifferent(newIndex, 0)
	gadget.AssertStrictlyOrderedFullField(api, lowMember, member, lowNext)
	// 2. Point the predecessor at the new member without changing its head.
	root := abstractor.Call(api, gadget.MerkleRootUpdateGadget{
		OldRoot:     oldRoot,
		OldLeaf:     headMapLeaf(api, lowMember, lowNext, lowNullifier),
		NewLeaf:     headMapLeaf(api, lowMember, member, lowNullifier),
		PathIndex:   api.ToBinary(lowIndex, HeadMapHeight),
		MerkleProof: lowProof,
		Height:      HeadMapHeight,
	})
	// 3. Prove the append slot empty under the intermediate root.
	return abstractor.Call(api, gadget.MerkleRootUpdateGadget{
		OldRoot:     root,
		OldLeaf:     headMapEmptyLeaf(),
		NewLeaf:     headMapLeaf(api, member, lowNext, genesis),
		PathIndex:   api.ToBinary(newIndex, HeadMapHeight),
		MerkleProof: newProof,
		Height:      HeadMapHeight,
	})
}
