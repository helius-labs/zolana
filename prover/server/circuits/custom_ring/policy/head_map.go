// The member -> current-record-nullifier map, an indexed Merkle tree whose leaf
// carries the successor pointer and the member's current nullifier. Registration
// proves the member absent and inserts its genesis, a transfer replaces the
// member's nullifier with its successor. Only the root is on chain, advanced in
// lockstep with the SPP transfer against the exact current root.

package policy

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	merkletree "zolana/prover/merkle-tree"
)

// HeadMapHeight is the indexed-tree height, the member key space folds into the
// sorted linked list the same way the nullifier tree folds addresses.
const HeadMapHeight = 40

// headMapEmptyLeaf is the value at an unoccupied position, the insert target.
func headMapEmptyLeaf() frontend.Variable {
	return frontend.Variable(new(big.Int).SetBytes(merkletree.ZERO_BYTES[0][:]))
}

// headMapLeaf binds a member to its successor pointer and current nullifier.
func headMapLeaf(api frontend.API, member, next, nullifier frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{member, next, nullifier})
}

// headMapTransfer proves the member's leaf holds spent under oldRoot and returns
// the root after writing successor, the member and its successor pointer fixed.
func headMapTransfer(
	api frontend.API,
	oldRoot, member, next, spent, successor, index frontend.Variable,
	proof []frontend.Variable,
) frontend.Variable {
	return abstractor.Call(api, gadget.MerkleRootUpdateGadget{
		OldRoot:     oldRoot,
		OldLeaf:     headMapLeaf(api, member, next, spent),
		NewLeaf:     headMapLeaf(api, member, next, successor),
		PathIndex:   api.ToBinary(index, HeadMapHeight),
		MerkleProof: proof,
		Height:      HeadMapHeight,
	})
}

// headMapRegister proves the member absent between the low leaf and its
// successor, splices the low leaf to it, and writes the genesis at an empty leaf.
func headMapRegister(
	api frontend.API,
	oldRoot frontend.Variable,
	lowMember, lowNext, lowNullifier, lowIndex frontend.Variable,
	lowProof []frontend.Variable,
	member, genesis, newIndex frontend.Variable,
	newProof []frontend.Variable,
) frontend.Variable {
	gadget.AssertStrictlyOrderedFullField(api, lowMember, member, lowNext)
	root := abstractor.Call(api, gadget.MerkleRootUpdateGadget{
		OldRoot:     oldRoot,
		OldLeaf:     headMapLeaf(api, lowMember, lowNext, lowNullifier),
		NewLeaf:     headMapLeaf(api, lowMember, member, lowNullifier),
		PathIndex:   api.ToBinary(lowIndex, HeadMapHeight),
		MerkleProof: lowProof,
		Height:      HeadMapHeight,
	})
	return abstractor.Call(api, gadget.MerkleRootUpdateGadget{
		OldRoot:     root,
		OldLeaf:     headMapEmptyLeaf(),
		NewLeaf:     headMapLeaf(api, member, lowNext, genesis),
		PathIndex:   api.ToBinary(newIndex, HeadMapHeight),
		MerkleProof: newProof,
		Height:      HeadMapHeight,
	})
}
