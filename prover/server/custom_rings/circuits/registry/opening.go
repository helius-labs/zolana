package registry

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// RecordOpening opens the record of a member that is in the registry.
type RecordOpening struct {
	Next      frontend.Variable
	Lists     frontend.Variable
	EscrowKey frontend.Variable
	Index     frontend.Variable
	Path      [Height]frontend.Variable
}

func (o RecordOpening) root(api frontend.API, leaf frontend.Variable) frontend.Variable {
	return abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:   leaf,
		Index:  api.ToBinary(o.Index, Height),
		Path:   o.Path[:],
		Height: Height,
	})
}

// AssertPresent requires the member's record under root while cond is set.
func (o RecordOpening) AssertPresent(api frontend.API, cond, root, member frontend.Variable) {
	opened := o.root(api, Record{Member: member, Next: o.Next, Lists: o.Lists, EscrowKey: o.EscrowKey}.Hash(api))
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: cond, A: opened, B: root})
}

// MemberOpening proves a member present or absent with one path. An absent member
// is bracketed by the low record and carries no lists and no key.
type MemberOpening struct {
	Present frontend.Variable
	RecordOpening
	LowMember frontend.Variable
	LowNext   frontend.Variable
	LowLists  frontend.Variable
	LowEscrow frontend.Variable
}

// Resolve returns the member's lists and escrow key, zero unless cond is set, and
// binds the opening to root while cond is set.
func (o MemberOpening) Resolve(api frontend.API, cond, root, member frontend.Variable) (lists, escrowKey frontend.Variable) {
	api.AssertIsBoolean(o.Present)
	present := Record{Member: member, Next: o.Next, Lists: o.Lists, EscrowKey: o.EscrowKey}.Hash(api)
	low := Record{Member: o.LowMember, Next: o.LowNext, Lists: o.LowLists, EscrowKey: o.LowEscrow}.Hash(api)
	opened := o.root(api, api.Select(o.Present, present, low))
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: cond, A: opened, B: root})
	absent := api.Mul(cond, api.Sub(1, o.Present))
	shared.AssertWhen(api, absent, gadget.IsStrictlyOrderedFullField(api, o.LowMember, member, o.LowNext))
	api.AssertIsEqual(api.Mul(absent, o.Lists), 0)
	api.AssertIsEqual(api.Mul(absent, o.EscrowKey), 0)
	return api.Mul(cond, o.Lists), api.Mul(cond, o.EscrowKey)
}
