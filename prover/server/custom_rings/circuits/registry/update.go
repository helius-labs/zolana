package registry

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// RecordUpdate rewrites one member's record, inserting the member when Exists is off.
// An insert relinks the low record and appends at Index, the slot the program hands out.
type RecordUpdate struct {
	Exists    frontend.Variable
	Next      frontend.Variable
	Index     frontend.Variable
	Path      [Height]frontend.Variable
	LowMember frontend.Variable
	LowNext   frontend.Variable
	LowLists  frontend.Variable
	LowEscrow frontend.Variable
	LowIndex  frontend.Variable
	LowPath   [Height]frontend.Variable
}

// Apply returns the root after replacing before with after while active, else root. Both
// records share Next, an insert takes it from the low record and proves the slot empty.
func (u RecordUpdate) Apply(api frontend.API, active, root frontend.Variable, before, after Record) frontend.Variable {
	api.AssertIsBoolean(u.Exists)
	insert := api.Mul(active, api.Sub(1, u.Exists))
	shared.AssertWhen(api, insert, gadget.IsStrictlyOrderedFullField(api, u.LowMember, after.Member, u.LowNext))
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: insert, A: u.Next, B: u.LowNext})
	api.AssertIsEqual(api.Mul(insert, before.Lists), 0)
	api.AssertIsEqual(api.Mul(insert, before.EscrowKey), 0)

	lowIndex := api.ToBinary(u.LowIndex, Height)
	lowOpened := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:  Record{Member: u.LowMember, Next: u.LowNext, Lists: u.LowLists, EscrowKey: u.LowEscrow}.Hash(api),
		Index: lowIndex, Path: u.LowPath[:], Height: Height,
	})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: insert, A: lowOpened, B: root})
	relinked := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:  Record{Member: u.LowMember, Next: after.Member, Lists: u.LowLists, EscrowKey: u.LowEscrow}.Hash(api),
		Index: lowIndex, Path: u.LowPath[:], Height: Height,
	})
	linked := api.Select(insert, relinked, root)

	index := api.ToBinary(u.Index, Height)
	opened := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash:  api.Select(u.Exists, before.Hash(api), emptyLeaf()),
		Index: index, Path: u.Path[:], Height: Height,
	})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: active, A: opened, B: linked})
	updated := abstractor.Call(api, gadget.MerkleRootGadget{Hash: after.Hash(api), Index: index, Path: u.Path[:], Height: Height})
	return api.Select(active, updated, root)
}

// MemberUpdateWires is one batch item. The program authorizes list changes and
// requires an unchanged escrow commitment. This circuit authenticates the tree
// transition. Encryption is a separate obligation enforced only by RegisterKey.
type MemberUpdateWires struct {
	Member       frontend.Variable
	OldLists     frontend.Variable
	OldEscrowKey frontend.Variable
	Lists        frontend.Variable
	EscrowKey    frontend.Variable
	RecordUpdate
}

// Properties: the first ItemCount items rewrite the registry in order from OldRoot to
// NewRoot, every other item leaves the root and hashes as zeros. The chain mirrors
// UpdateMembersPublicInput on chain.

type UpdateMembersCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	OldRoot         frontend.Variable
	NewRoot         frontend.Variable
	ItemCount       frontend.Variable
	Items           [MaxBatch]MemberUpdateWires
}

func (c *UpdateMembersCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	count := base.SelectCount(api, c.ItemCount, 1, MaxBatch)
	root := c.OldRoot
	items := []frontend.Variable{c.ItemCount}
	for i, item := range c.Items {
		active := count.Active[i]
		rc.Check(item.OldLists, ListBits)
		rc.Check(item.Lists, ListBits)
		before := Record{Member: item.Member, Next: item.Next, Lists: item.OldLists, EscrowKey: item.OldEscrowKey}
		after := Record{Member: item.Member, Next: item.Next, Lists: item.Lists, EscrowKey: item.EscrowKey}
		root = item.Apply(api, active, root, before, after)
		for _, value := range []frontend.Variable{item.Member, item.OldLists, item.OldEscrowKey, item.Lists, item.EscrowKey, item.Index} {
			items = append(items, api.Mul(active, value))
		}
	}
	api.AssertIsEqual(root, c.NewRoot)
	chain := []frontend.Variable{c.OldRoot, c.NewRoot, gadget.HashChain(api, items)}
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
