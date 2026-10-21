// Package records proves records of a ring's member registry, a 4-ary Poseidon
// tree whose records form one list sorted by member.
package records

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// The tree shape mirrors custom-rings/interface/src/member_registry.rs and must stay in sync with it.
const (
	Height       = 10
	Arity        = 4
	IndexBits    = 2 * Height
	Capacity     = 1 << IndexBits
	PathSiblings = Height * (Arity - 1)
	// ListBits is the width of a record's list bitmap, bit id-1 marks list id.
	ListBits = 64
)

// The empty leaf is 0, and the sentinel (0, q-1, 0, 0) at index 0 brackets every member in [1, q-2].
type Record struct {
	Member    frontend.Variable
	Next      frontend.Variable
	Lists     frontend.Variable
	EscrowKey frontend.Variable
}

func (r Record) Hash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{r.Member, r.Next, r.Lists, r.EscrowKey})
}

// EscrowKey is Poseidon(nullifier_pk, ct_hash), the record field RegisterKey fills, mirrored by
// EscrowKey::hash in custom-rings/interface/src/member_registry.rs.
func EscrowKey(api frontend.API, nullifierPk, ciphertextHash frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{nullifierPk, ciphertextHash})
}

type QuadPath struct {
	Index    frontend.Variable
	Siblings [Height][Arity - 1]frontend.Variable // each level's other three children in child order, leaf level first
}

func (p QuadPath) Root(api frontend.API, leaf frontend.Variable) frontend.Variable {
	return p.fold(api, p.digits(api), leaf)
}

func (p QuadPath) Update(api frontend.API, oldLeaf, newLeaf frontend.Variable) (oldRoot, newRoot frontend.Variable) {
	digits := p.digits(api)
	return p.fold(api, digits, oldLeaf), p.fold(api, digits, newLeaf)
}

func (p QuadPath) digits(api frontend.API) []frontend.Variable {
	// IndexBits bits bound Index below Capacity, one index per leaf and no alias Index + Capacity.
	return api.ToBinary(p.Index, IndexBits)
}

func (p QuadPath) fold(api frontend.API, digits []frontend.Variable, leaf frontend.Variable) frontend.Variable {
	node := leaf
	for level, siblings := range p.Siblings {
		node = gadget.PoseidonHash(api, quadChildren(api, node, siblings, digits[2*level], digits[2*level+1]))
	}
	return node
}

func quadChildren(api frontend.API, node frontend.Variable, siblings [Arity - 1]frontend.Variable, b0, b1 frontend.Variable) []frontend.Variable {
	// The digit bits are boolean, so exactly one of the four position flags is set.
	three := api.Mul(b0, b1)
	one := api.Sub(b0, three)
	two := api.Sub(b1, three)
	zero := api.Sub(api.Sub(1, b0), two)
	return []frontend.Variable{
		api.Select(zero, node, siblings[0]),
		api.Select(zero, siblings[0], api.Select(one, node, siblings[1])),
		api.Select(three, siblings[2], api.Select(two, node, siblings[1])),
		api.Select(three, node, siblings[2]),
	}
}
