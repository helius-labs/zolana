package registry

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// SubtreeBatch authenticates openings whose record indices share an upper
// prefix. The entire height-20 root stays unchanged. The circuit proves both
// the common subtree and its path to that root. A scattered batch must use
// the unrestricted circuit. The prefix and all indices remain private.
type SubtreeBatch struct {
	depth         int
	root          frontend.Variable
	queries       []subtreeQuery
	sparse        *SparseSubtree
	authenticated [8]frontend.Variable
}

func NewSparseSubtreeBatch(api frontend.API, root frontend.Variable, witness *SparseSubtree) *SubtreeBatch {
	return &SubtreeBatch{depth: SparseSubtreeDepth, root: root, sparse: witness, authenticated: witness.check(api)}
}

type subtreeQuery struct {
	active, root, index frontend.Variable
	path                []frontend.Variable
}

func NewSubtreeBatch(depth int, root frontend.Variable) *SubtreeBatch {
	if depth < 1 || depth >= Height {
		panic("registry subtree depth must be between 1 and 19")
	}
	return &SubtreeBatch{depth: depth, root: root}
}

func (b *SubtreeBatch) Resolve(api frontend.API, o MemberOpening, active, member frontend.Variable) (lists, escrowKey frontend.Variable) {
	if value, ok := api.Compiler().ConstantValue(active); ok && value.Sign() == 0 {
		return 0, 0
	}
	api.AssertIsBoolean(active)
	index := api.ToBinary(o.Index, Height)
	leaf := o.compactLeaf(api, active, member)
	var root frontend.Variable
	if b.sparse == nil {
		root = abstractor.Call(api, gadget.MerkleRootGadget{
			Hash: leaf, Index: index[:b.depth], Path: o.Path[:b.depth], Height: b.depth,
		})
	} else {
		root = b.sparse.Nodes[0]
		opened := selectLeaf(api, index[:b.depth], b.sparse.Nodes[7:])
		authenticated := selectLeaf(api, index[:b.depth], b.authenticated[:])
		api.AssertIsEqual(api.Mul(active, api.Sub(opened, leaf)), 0)
		api.AssertIsEqual(api.Mul(active, api.Sub(1, authenticated)), 0)
	}
	b.queries = append(b.queries, subtreeQuery{
		active: active, root: root, index: api.FromBinary(index[b.depth:]...), path: o.Path[b.depth:],
	})
	return api.Mul(active, o.Lists), api.Mul(active, o.EscrowKey)
}

func (b *SubtreeBatch) Check(api frontend.API) {
	var active, root, index frontend.Variable = 0, 0, 0
	path := make([]frontend.Variable, Height-b.depth)
	for i := range path {
		path[i] = 0
	}
	for _, q := range b.queries {
		active = api.Or(active, q.active)
		root = api.Select(q.active, q.root, root)
		index = api.Select(q.active, q.index, index)
		for i := range path {
			path[i] = api.Select(q.active, q.path[i], path[i])
		}
	}
	for _, q := range b.queries {
		api.AssertIsEqual(api.Mul(q.active, api.Sub(q.root, root)), 0)
		api.AssertIsEqual(api.Mul(q.active, api.Sub(q.index, index)), 0)
	}
	opened := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash: root, Index: api.ToBinary(index, Height-b.depth), Path: path, Height: Height - b.depth,
	})
	api.AssertIsEqual(api.Mul(active, api.Sub(opened, b.root)), 0)
}
