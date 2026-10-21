// Package registry proves the queued member record writes a ring program applies to its registry.
package registry

import (
	"fmt"
	"math/big"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/records"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// Properties:
// 1. NewRoot, NewNextIndex and ChainEnd follow from applying, in queue order, exactly
// the Count writes whose chain runs from ChainStart to ChainEnd.
// 2. A write keeps every list bit outside its mask while the program keeps Value inside
// Mask, and never replaces a registered escrow key.
// 3. An absent member is inserted after its low record at exactly the next index, and a
// write that would leave its record empty inserts nothing.
// 4. The statement binds both roots, both next indexes, both chain ends and the count.

// ApplyBatch is the write capacity of the wide apply key, mirrored by APPLY_BATCH in
// custom-rings/interface/src/member_registry.rs.
const ApplyBatch = 16

// ApplyWidths are the write capacities the apply keys ship.
var ApplyWidths = []int{1, ApplyBatch}

// QueueEntry is one queued write, EscrowKey zero but for a RegisterKey write.
type QueueEntry struct {
	Member    frontend.Variable
	Mask      frontend.Variable
	Value     frontend.Variable
	EscrowKey frontend.Variable
}

// Hash is the entry the program chains at write time in custom-rings/interface/src/member_registry.rs.
func (e QueueEntry) Hash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{base.QueueWriteDomain, e.Member, e.Mask, e.Value, e.EscrowKey})
}

// RecordWrite applies one entry, Slot opening the member's leaf or the empty leaf an insert takes.
type RecordWrite struct {
	Entry     QueueEntry
	Exists    frontend.Variable
	OldNext   frontend.Variable
	OldLists  frontend.Variable
	OldEscrow frontend.Variable
	Slot      records.QuadPath
	LowMember frontend.Variable
	LowNext   frontend.Variable
	LowLists  frontend.Variable
	LowEscrow frontend.Variable
	Low       records.QuadPath
}

// ApplyRecordsCircuit applies the first Count of NumWrites queued writes to OldRoot.
type ApplyRecordsCircuit struct {
	NumWrites int `gnark:"-"`

	PublicInputHash frontend.Variable `gnark:",public"`

	OldRoot      frontend.Variable
	NewRoot      frontend.Variable
	OldNextIndex frontend.Variable
	NewNextIndex frontend.Variable
	ChainStart   frontend.Variable
	ChainEnd     frontend.Variable
	Count        frontend.Variable
	Writes       []RecordWrite
}

// NewApplyRecordsCircuit allocates the circuit of one apply key, Define refuses any
// width outside ApplyWidths.
func NewApplyRecordsCircuit(n int) *ApplyRecordsCircuit {
	return &ApplyRecordsCircuit{NumWrites: n, Writes: make([]RecordWrite, n)}
}

func (c *ApplyRecordsCircuit) Define(api frontend.API) error {
	if !slices.Contains(ApplyWidths, c.NumWrites) {
		return fmt.Errorf("registry: unsupported write capacity %d, want one of %v", c.NumWrites, ApplyWidths)
	}
	if len(c.Writes) != c.NumWrites {
		return fmt.Errorf("registry: write count mismatch: got %d want %d", len(c.Writes), c.NumWrites)
	}
	// 1. Count selects a prefix of one write up to the capacity, the writes past it act on nothing.
	count := base.SelectCount(api, c.Count, 1, c.NumWrites)
	// 2. Every active write moves the running root, next index and chain in queue order.
	state := registryState{root: c.OldRoot, next: c.OldNextIndex, chain: c.ChainStart}
	for i, w := range c.Writes {
		state = w.apply(api, count.Active[i], state)
	}
	// 3. The registry after the batch and the queue segment it consumed are the statement's.
	api.AssertIsEqual(state.root, c.NewRoot)
	api.AssertIsEqual(state.next, c.NewNextIndex)
	api.AssertIsEqual(state.chain, c.ChainEnd)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement()))
	return nil
}

type registryState struct {
	root, next, chain frontend.Variable
}

// apply moves s by w while active is set, an unset active leaves it.
func (w RecordWrite) apply(api frontend.API, active frontend.Variable, s registryState) registryState {
	// 1. List bits outside the mask keep their old value, the chain binds Value to the
	// program's write and the program keeps it inside the mask.
	lists := api.Add(keptLists(api, w.OldLists, w.Entry.Mask), w.Entry.Value)
	// 2. A registered escrow key is final, a later key leaves it.
	escrow := api.Select(api.IsZero(w.OldEscrow), w.Entry.EscrowKey, w.OldEscrow)
	// 3. An absent member lies strictly inside its low record's link under the running root,
	// no such link exists for a present member, and its old fields are empty.
	api.AssertIsBoolean(w.Exists)
	absent := api.Mul(active, api.Sub(1, w.Exists))
	gadget.AssertOrderedWhen(api, absent, w.LowMember, w.Entry.Member, w.LowNext)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: absent, V: w.OldLists})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: absent, V: w.OldEscrow})
	low := records.Record{Member: w.LowMember, Next: w.LowNext, Lists: w.LowLists, EscrowKey: w.LowEscrow}
	relinked := records.Record{Member: w.LowMember, Next: w.Entry.Member, Lists: w.LowLists, EscrowKey: w.LowEscrow}
	lowRoot, relinkedRoot := w.Low.Update(api, low.Hash(api), relinked.Hash(api))
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: absent, A: lowRoot, B: s.root})
	// 4. Only a nonempty new record is inserted, an empty one leaves the member absent.
	insert := api.Mul(absent, api.Or(base.IsNonZero(api, lists), base.IsNonZero(api, escrow)))
	update := api.Mul(active, w.Exists)
	// 5. An insert relinks the low record to the member and takes the empty leaf at exactly
	// the next index, linking on to the low record's old next.
	linked := api.Select(insert, relinkedRoot, s.root)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: insert, A: w.Slot.Index, B: s.next})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: insert, A: w.OldNext, B: w.LowNext})
	// 6. An update or insert replaces the slot's old leaf under the running root, a no-op
	// leaves the root, and an insert's old leaf is the empty leaf 0.
	before := api.Select(w.Exists, records.Record{Member: w.Entry.Member, Next: w.OldNext, Lists: w.OldLists, EscrowKey: w.OldEscrow}.Hash(api), 0)
	after := records.Record{Member: w.Entry.Member, Next: w.OldNext, Lists: lists, EscrowKey: escrow}.Hash(api)
	opened, written := w.Slot.Update(api, before, after)
	changes := api.Add(insert, update)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: changes, A: opened, B: linked})
	// 7. The chain absorbs every active entry, no write is skipped, added or reordered.
	chain := gadget.PoseidonHash(api, []frontend.Variable{s.chain, w.Entry.Hash(api)})
	return registryState{
		root:  api.Select(changes, written, s.root),
		next:  api.Add(s.next, insert),
		chain: api.Select(active, chain, s.chain),
	}
}

func keptLists(api frontend.API, old, mask frontend.Variable) frontend.Variable {
	// Both bitmaps hold ListBits bits, the width of every record and queued mask.
	oldBits := api.ToBinary(old, records.ListBits)
	maskBits := api.ToBinary(mask, records.ListBits)
	kept := frontend.Variable(0)
	for i := range oldBits {
		kept = api.Add(kept, api.Mul(oldBits[i], api.Sub(1, maskBits[i]), new(big.Int).Lsh(big.NewInt(1), uint(i))))
	}
	return kept
}

// statement is [CRAP, old_root, new_root, old_next, new_next, chain_start, chain_end,
// count], rebuilt by the program through custom-rings/interface/src/statement.rs.
func (c *ApplyRecordsCircuit) statement() []frontend.Variable {
	return []frontend.Variable{
		base.ApplyRecordsDomain, c.OldRoot, c.NewRoot, c.OldNextIndex, c.NewNextIndex, c.ChainStart, c.ChainEnd, c.Count,
	}
}
