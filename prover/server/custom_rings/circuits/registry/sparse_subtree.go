package registry

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

const SparseSubtreeDepth = 3

// SparseSubtree is a private frontier for eight consecutive registry records.
// Nodes use heap order, root at 0, children at 2*i+1 and 2*i+2. An opaque node
// carries an authenticated sibling hash. Queried leaves require every ancestor
// to be expanded, so no opaque node can hide a forged queried record.
type SparseSubtree struct {
	Nodes    [15]frontend.Variable
	Expanded [7]frontend.Variable
}

func (s *SparseSubtree) check(api frontend.API) [8]frontend.Variable {
	for i, expanded := range s.Expanded {
		api.AssertIsBoolean(expanded)
		hash := gadget.PoseidonHash(api, []frontend.Variable{s.Nodes[2*i+1], s.Nodes[2*i+2]})
		api.AssertIsEqual(api.Mul(expanded, api.Sub(hash, s.Nodes[i])), 0)
	}
	var authenticated [15]frontend.Variable
	authenticated[0] = 1
	for i, expanded := range s.Expanded {
		child := api.Mul(authenticated[i], expanded)
		authenticated[2*i+1], authenticated[2*i+2] = child, child
	}
	var leaves [8]frontend.Variable
	copy(leaves[:], authenticated[7:])
	return leaves
}

func selectLeaf(api frontend.API, bits []frontend.Variable, values []frontend.Variable) frontend.Variable {
	for _, bit := range bits {
		next := make([]frontend.Variable, len(values)/2)
		for i := range next {
			next[i] = api.Select(bit, values[2*i+1], values[2*i])
		}
		values = next
	}
	return values[0]
}
