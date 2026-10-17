package registry

import (
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

type SparseOpening struct {
	Index uint64
	Leaf  *big.Int
	Path  []big.Int
}

// BuildSparseSubtree joins existing Merkle openings. It never needs to fetch
// unrelated records or invert a sibling subtree hash. Unopened siblings remain
// opaque. Ineligible batches keep using the unrestricted proof path.
func BuildSparseSubtree(openings []SparseOpening) (SparseSubtree, error) {
	var out SparseSubtree
	for i := range out.Nodes {
		out.Nodes[i] = 0
	}
	for i := range out.Expanded {
		out.Expanded[i] = 0
	}
	var nodes [15]*big.Int
	set := func(index int, value *big.Int) error {
		if nodes[index] != nil && nodes[index].Cmp(value) != 0 {
			return fmt.Errorf("registry subtree: conflicting node %d", index)
		}
		nodes[index] = new(big.Int).Set(value)
		out.Nodes[index] = nodes[index]
		return nil
	}
	for _, opening := range openings {
		if len(opening.Path) != Height || opening.Index >= 1<<Height || opening.Leaf == nil {
			return out, fmt.Errorf("registry subtree: invalid opening")
		}
		if opening.Index>>SparseSubtreeDepth != openings[0].Index>>SparseSubtreeDepth {
			return out, fmt.Errorf("registry subtree: records span different subtrees")
		}
		node := 7 + int(opening.Index&7)
		if err := set(node, opening.Leaf); err != nil {
			return out, err
		}
		for level := 0; level < SparseSubtreeDepth; level++ {
			sibling := node - 1
			if node%2 == 1 {
				sibling = node + 1
			}
			if err := set(sibling, &opening.Path[level]); err != nil {
				return out, err
			}
			parent := (node - 1) / 2
			hash, err := poseidon.Hash([]*big.Int{nodes[2*parent+1], nodes[2*parent+2]})
			if err != nil {
				return out, err
			}
			if err := set(parent, hash); err != nil {
				return out, err
			}
			out.Expanded[parent] = 1
			node = parent
		}
	}
	return out, nil
}
