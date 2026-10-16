// Package registry proves member records of a ring's member registry, an indexed
// Merkle tree keyed by owner tag, and the batched updates that rewrite them.
package registry

import (
	"math/big"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	merkletree "github.com/helius-labs/zolana/prover/server/merkle-tree"
)

const (
	Height = 20
	// MaxBatch is the item capacity of one update proof.
	MaxBatch = 16
	// ListBits is the width of a record's list bitmap, bit i marks list id i+1.
	ListBits = 64
)

// Record is one leaf, the sentinel (0, FIELD_MAX, 0, 0) sits at index 0.
type Record struct {
	Member    frontend.Variable
	Next      frontend.Variable
	Lists     frontend.Variable
	EscrowKey frontend.Variable
}

func (r Record) Hash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{r.Member, r.Next, r.Lists, r.EscrowKey})
}

// AssertMode requires a boolean escrow flag and a zero root when it is off.
func AssertMode(api frontend.API, escrow, root frontend.Variable) {
	api.AssertIsBoolean(escrow)
	api.AssertIsEqual(api.Mul(root, api.Sub(1, escrow)), 0)
}

func emptyLeaf() frontend.Variable {
	return frontend.Variable(new(big.Int).SetBytes(merkletree.ZERO_BYTES[0][:]))
}
