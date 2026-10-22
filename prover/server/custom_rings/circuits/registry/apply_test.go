package registry_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover-test/refusal"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringrecords"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// batch is a host application of entries at one capacity, the statement bound.
type batch struct {
	circuit *registry.ApplyRecordsCircuit
	writes  []ringrecords.Write
	// chain[k] is the chain value after k entries, chain[0] the start.
	chain []*big.Int
}

func entry(member, mask, value, escrowKey int64) ringrecords.Entry {
	return ringrecords.Entry{Member: big.NewInt(member), Mask: big.NewInt(mask), Value: big.NewInt(value), EscrowKey: big.NewInt(escrowKey)}
}

// applyBatch applies entries to members and assigns the capacity-n circuit, padding writes all zero.
func applyBatch(t *testing.T, members *ringrecords.Registry, n int, chainStart *big.Int, entries ...ringrecords.Entry) *batch {
	t.Helper()
	c := registry.NewApplyRecordsCircuit(n)
	c.OldRoot, c.OldNextIndex, c.ChainStart, c.Count = members.Root(), new(big.Int).SetUint64(members.NextIndex()), chainStart, len(entries)
	b := &batch{circuit: c, chain: []*big.Int{chainStart}}
	for i := range c.Writes {
		c.Writes[i] = zeroWrite()
	}
	for i, e := range entries {
		w := members.Apply(t, e)
		b.writes = append(b.writes, w)
		c.Writes[i] = writeWires(w)
		b.chain = append(b.chain, spptest.MustPoseidon(t, 3, []*big.Int{b.chain[i], entryHash(t, e)}))
	}
	c.NewRoot, c.NewNextIndex, c.ChainEnd = members.Root(), new(big.Int).SetUint64(members.NextIndex()), b.chain[len(entries)]
	b.bind(t)
	return b
}

// bind hashes the statement from the circuit's current values, as the program rebuilds it.
func (b *batch) bind(t *testing.T) {
	t.Helper()
	c := b.circuit
	statement := []*big.Int{big.NewInt(base.ApplyRecordsDomain)}
	for _, v := range []frontend.Variable{c.OldRoot, c.NewRoot, c.OldNextIndex, c.NewNextIndex, c.ChainStart, c.ChainEnd, c.Count} {
		statement = append(statement, spptest.AsBigInt(v))
	}
	c.PublicInputHash = spptest.MustHashChain4(t, statement)
}

// entryHash mirrors registry.QueueEntry.Hash.
func entryHash(t *testing.T, e ringrecords.Entry) *big.Int {
	t.Helper()
	return spptest.MustPoseidon(t, 6, []*big.Int{big.NewInt(base.QueueWriteDomain), e.Member, e.Mask, e.Value, e.EscrowKey})
}

func writeWires(w ringrecords.Write) registry.RecordWrite {
	e := w.Entry
	exists := 0
	if w.Exists {
		exists = 1
	}
	return registry.RecordWrite{
		Entry:     registry.QueueEntry{Member: e.Member, Mask: e.Mask, Value: e.Value, EscrowKey: e.EscrowKey},
		Exists:    exists,
		OldNext:   w.OldNext,
		OldLists:  w.OldLists,
		OldEscrow: w.OldEscrow,
		Slot:      w.Slot.Wires(),
		LowMember: w.Low.Member,
		LowNext:   w.Low.Next,
		LowLists:  w.Low.Lists,
		LowEscrow: w.Low.EscrowKey,
		Low:       w.LowPath.Wires(),
	}
}

func zeroWrite() registry.RecordWrite {
	zero := ringrecords.Write{
		Entry:   entry(0, 0, 0, 0),
		OldNext: big.NewInt(0), OldLists: big.NewInt(0), OldEscrow: big.NewInt(0),
		Low: ringrecords.Record{Member: big.NewInt(0), Next: big.NewInt(0), Lists: big.NewInt(0), EscrowKey: big.NewInt(0)},
	}
	for level := range zero.Slot.Siblings {
		for k := range zero.Slot.Siblings[level] {
			zero.Slot.Siblings[level][k], zero.LowPath.Siblings[level][k] = big.NewInt(0), big.NewInt(0)
		}
	}
	return writeWires(zero)
}

func solve(t *testing.T, c *registry.ApplyRecordsCircuit) error {
	t.Helper()
	return test.IsSolved(registry.NewApplyRecordsCircuit(c.NumWrites), c, ecc.BN254.ScalarField())
}

// seeded holds alice (0x10) with the allow list and carol (0x30) with a registered key.
func seeded(t *testing.T) *ringrecords.Registry {
	t.Helper()
	members := ringrecords.New(t)
	members.Apply(t, entry(0x10, ringrecords.AllowBit, ringrecords.AllowBit, 0))
	members.Apply(t, entry(0x30, ringrecords.EscrowBit, ringrecords.EscrowBit, 0xc1))
	return members
}

func TestApplyRecordsAppliesTheQueueInOrder(t *testing.T) {
	members := seeded(t)
	b := applyBatch(t, members, registry.ApplyBatch, big.NewInt(0x5eed),
		entry(0x20, ringrecords.AllowBit|ringrecords.BlockBit, ringrecords.BlockBit, 0),                      // insert between alice and carol
		entry(0x10, ringrecords.BlockBit, ringrecords.BlockBit, 0),                                           // alice keeps allow, gains block
		entry(0x10, ringrecords.AllowBit, 0, 0),                                                              // alice drops allow, keeps block
		entry(0x40, ringrecords.AllowBit, 0, 0),                                                              // an empty record is never inserted
		entry(0x30, ringrecords.EscrowBit, ringrecords.EscrowBit, 0xc2),                                      // carol keeps her first key
		entry(0x50, ringrecords.EscrowBit, ringrecords.EscrowBit, 0xc3),                                      // RegisterKey inserts a new member
		entry(0x05, ringrecords.AllowBit|ringrecords.BlockBit, ringrecords.AllowBit|ringrecords.BlockBit, 0), // insert below every member
	)
	if err := solve(t, b.circuit); err != nil {
		t.Fatal(err)
	}
	for member, want := range map[int64][2]int64{0x10: {ringrecords.BlockBit, 0}, 0x20: {ringrecords.BlockBit, 0}, 0x30: {ringrecords.EscrowBit, 0xc1}, 0x50: {ringrecords.EscrowBit, 0xc3}, 0x05: {ringrecords.AllowBit | ringrecords.BlockBit, 0}} {
		record := members.Opening(big.NewInt(member))
		if !record.Present || record.Record.Lists.Int64() != want[0] || record.Record.EscrowKey.Int64() != want[1] {
			t.Fatalf("member %#x: present=%v lists=%v escrow=%v", member, record.Present, record.Record.Lists, record.Record.EscrowKey)
		}
	}
	if members.Opening(big.NewInt(0x40)).Present || members.NextIndex() != 6 {
		t.Fatalf("next index %d, an empty record was inserted", members.NextIndex())
	}
	full := ringrecords.New(t)
	var entries []ringrecords.Entry
	for i := range registry.ApplyBatch {
		entries = append(entries, entry(int64(0x100+i), ringrecords.AllowBit, ringrecords.AllowBit, 0))
	}
	if err := solve(t, applyBatch(t, full, registry.ApplyBatch, big.NewInt(0), entries...).circuit); err != nil {
		t.Fatalf("full batch: %v", err)
	}
}

// Each case forges a batch consistent with every rule but the one it names, whose frames refuse it.
func TestApplyRecordsRefusals(t *testing.T) {
	gate := []string{"gadget.AssertEqualWhen", "registry.RecordWrite.apply"}
	empty := []string{"gadget.AssertZeroWhen", "registry.RecordWrite.apply"}
	bracket := []string{"gadget.AssertOrderedWhen", "registry.RecordWrite.apply"}
	define := []string{"[assertIsEqual]", "registry.(*ApplyRecordsCircuit).Define"}
	insert := entry(0x20, ringrecords.AllowBit, ringrecords.AllowBit, 0)
	tests := []struct {
		name    string
		members func(*testing.T) *ringrecords.Registry
		n       int
		entries []ringrecords.Entry
		tamper  func(*testing.T, *batch)
		frames  []string
	}{
		{"insert at next_index + 1", fourRecords, 1, []ringrecords.Entry{insert}, func(t *testing.T, b *batch) {
			// Both empty leaves of the group share their siblings, the root folds the record one leaf on.
			slot := b.writes[0].Slot
			slot.Index++
			b.circuit.Writes[0].Slot = slot.Wires()
			b.circuit.NewRoot = slot.Root(t, newRecord(b.writes[0], ringrecords.AllowBit).Hash(t))
			b.bind(t)
		}, gate},
		{"absence proven with the low record of another gap", seeded, 1, []ringrecords.Entry{insert}, func(t *testing.T, b *batch) {
			// carol's record opens under the old root, its link starts above 0x20.
			opening := seeded(t).Opening(big.NewInt(0x30))
			w := &b.circuit.Writes[0]
			w.LowMember, w.LowNext, w.LowLists, w.LowEscrow = opening.Record.Member, opening.Record.Next, opening.Record.Lists, opening.Record.EscrowKey
			w.Low = opening.Path.Wires()
		}, bracket},
		{"a present member inserted again through the record linking to it", seeded, 1, []ringrecords.Entry{entry(0x10, ringrecords.BlockBit, ringrecords.BlockBit, 0)}, func(t *testing.T, b *batch) {
			// The sentinel links to alice, so its relink changes nothing and a second alice record follows.
			members := seeded(t)
			sentinel := members.Opening(big.NewInt(1))
			duplicate := ringrecords.Write{Entry: b.writes[0].Entry, OldNext: big.NewInt(0x10), OldLists: big.NewInt(0), OldEscrow: big.NewInt(0),
				Slot: members.Path(members.NextIndex()), Low: sentinel.Record, LowPath: sentinel.Path}
			b.circuit.Writes[0] = writeWires(duplicate)
			b.circuit.NewRoot = duplicate.Slot.Root(t, newRecord(duplicate, ringrecords.BlockBit).Hash(t))
			b.circuit.NewNextIndex = new(big.Int).SetUint64(members.NextIndex() + 1)
			b.bind(t)
		}, bracket},
		{"a low record under another root", seeded, 1, []ringrecords.Entry{insert}, func(t *testing.T, b *batch) {
			// The batch is honest for a registry holding 0x1f in alice's place.
			forged := applyBatch(t, replaced(t, 0x1f), 1, b.chain[0], insert)
			forged.circuit.OldRoot = b.circuit.OldRoot
			forged.bind(t)
			*b = *forged
		}, gate},
		{"an old list bit on an absent member", seeded, 1, []ringrecords.Entry{entry(0x20, ringrecords.BlockBit, ringrecords.BlockBit, 0)}, func(t *testing.T, b *batch) {
			listed := seeded(t)
			listed.Apply(t, entry(0x20, ringrecords.AllowBit|ringrecords.BlockBit, ringrecords.AllowBit|ringrecords.BlockBit, 0))
			b.circuit.Writes[0].OldLists = big.NewInt(ringrecords.AllowBit)
			b.circuit.NewRoot = listed.Root()
			b.bind(t)
		}, empty},
		{"an insert carrying an escrow key the queue never held", seeded, 1, []ringrecords.Entry{insert}, func(t *testing.T, b *batch) {
			keyed := seeded(t)
			keyed.Apply(t, entry(0x20, ringrecords.AllowBit, ringrecords.AllowBit, 0x99))
			b.circuit.Writes[0].OldEscrow = big.NewInt(0x99)
			b.circuit.NewRoot = keyed.Root()
			b.bind(t)
		}, empty},
		{"an insert linking past the low record's next", seeded, 1, []ringrecords.Entry{insert}, func(t *testing.T, b *batch) {
			w := b.writes[0]
			w.OldNext = big.NewInt(0x40)
			b.circuit.Writes[0].OldNext = w.OldNext
			b.circuit.NewRoot = w.Slot.Root(t, newRecord(w, ringrecords.AllowBit).Hash(t))
			b.bind(t)
		}, gate},
		{"an absent member claimed present", seeded, 1, []ringrecords.Entry{insert}, func(t *testing.T, b *batch) {
			w := b.writes[0]
			w.Exists, w.Slot = true, seeded(t).Path(w.Slot.Index)
			b.circuit.Writes[0] = writeWires(w)
			b.circuit.NewRoot, b.circuit.NewNextIndex = w.Slot.Root(t, newRecord(w, ringrecords.AllowBit).Hash(t)), b.circuit.OldNextIndex
			b.bind(t)
		}, gate},
		{"an update over another old record", seeded, 1, []ringrecords.Entry{entry(0x10, ringrecords.BlockBit, ringrecords.BlockBit, 0)}, func(t *testing.T, b *batch) {
			// alice holds allow, the forged witness says she held nothing.
			w := b.writes[0]
			w.OldLists = big.NewInt(0)
			b.circuit.Writes[0].OldLists = w.OldLists
			b.circuit.NewRoot = w.Slot.Root(t, newRecord(w, ringrecords.BlockBit).Hash(t))
			b.bind(t)
		}, gate},
		{"an insert over a record at a stale next index", seeded, 1, []ringrecords.Entry{insert}, func(t *testing.T, b *batch) {
			// The statement names carol's leaf as the next one, the insert would overwrite it.
			w := b.writes[0]
			w.Slot = seeded(t).Path(2)
			b.circuit.Writes[0].Slot = w.Slot.Wires()
			b.circuit.OldNextIndex, b.circuit.NewNextIndex = big.NewInt(2), big.NewInt(3)
			b.circuit.NewRoot = w.Slot.Root(t, newRecord(w, ringrecords.AllowBit).Hash(t))
			b.bind(t)
		}, gate},
		{"second escrow key replaces the first", seeded, 1, []ringrecords.Entry{entry(0x30, ringrecords.EscrowBit, ringrecords.EscrowBit, 0xc2)}, func(t *testing.T, b *batch) {
			b.circuit.NewRoot = replacedKeyRoot(t)
			b.bind(t)
		}, define},
		{"a bit outside the mask changes", seeded, 1, []ringrecords.Entry{entry(0x10, ringrecords.BlockBit, ringrecords.BlockBit, 0)}, func(t *testing.T, b *batch) {
			cleared := ringrecords.New(t)
			cleared.Apply(t, entry(0x10, ringrecords.AllowBit|ringrecords.BlockBit, ringrecords.BlockBit, 0))
			cleared.Apply(t, entry(0x30, ringrecords.EscrowBit, ringrecords.EscrowBit, 0xc1))
			b.circuit.NewRoot = cleared.Root()
			b.bind(t)
		}, define},
		{"an empty record is inserted", seeded, 1, []ringrecords.Entry{entry(0x40, ringrecords.AllowBit, 0, 0)}, func(t *testing.T, b *batch) {
			forged := seeded(t)
			b.circuit.Writes[0] = writeWires(forged.Insert(t, b.writes[0].Entry))
			b.circuit.NewRoot, b.circuit.NewNextIndex = forged.Root(), new(big.Int).SetUint64(forged.NextIndex())
			b.bind(t)
		}, define},
		{"a next index advanced past a no-op", seeded, 1, []ringrecords.Entry{entry(0x40, ringrecords.AllowBit, 0, 0)}, func(t *testing.T, b *batch) {
			b.circuit.NewNextIndex = new(big.Int).Add(spptest.AsBigInt(b.circuit.NewNextIndex), big.NewInt(1))
			b.bind(t)
		}, define},
		{"an entry the chain never held", seeded, 1, []ringrecords.Entry{entry(0x30, ringrecords.EscrowBit, ringrecords.EscrowBit, 0xc2)}, func(_ *testing.T, b *batch) {
			// carol keeps her first key either way, only the chain sees the other entry.
			b.circuit.Writes[0].Entry.EscrowKey = big.NewInt(0xc3)
		}, define},
		{"the queue applied out of order", seeded, registry.ApplyBatch, []ringrecords.Entry{entry(0x10, ringrecords.BlockBit, ringrecords.BlockBit, 0), entry(0x10, ringrecords.BlockBit, 0, 0)}, func(t *testing.T, b *batch) {
			// The writes and the root follow the swapped order, the chain end the queued one.
			swapped := applyBatch(t, seeded(t), registry.ApplyBatch, b.chain[0], b.writes[1].Entry, b.writes[0].Entry)
			swapped.circuit.ChainEnd = b.circuit.ChainEnd
			swapped.bind(t)
			*b = *swapped
		}, define},
		{"a chain end short of the applied writes", seeded, registry.ApplyBatch, []ringrecords.Entry{insert, entry(0x10, ringrecords.BlockBit, ringrecords.BlockBit, 0)}, func(t *testing.T, b *batch) {
			b.circuit.ChainEnd = b.chain[1]
			b.bind(t)
		}, define},
		{"an empty batch", seeded, 1, []ringrecords.Entry{insert}, func(t *testing.T, b *batch) {
			b.circuit.Count = 0
			b.bind(t)
		}, []string{"gadget.SelectCount"}},
		{"the statement of another batch", seeded, 1, []ringrecords.Entry{insert}, func(_ *testing.T, b *batch) {
			b.circuit.PublicInputHash = big.NewInt(1)
		}, define},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := applyBatch(t, tt.members(t), tt.n, big.NewInt(0x5eed), tt.entries...)
			if err := solve(t, b.circuit); err != nil {
				t.Fatalf("honest batch: %v", err)
			}
			tt.tamper(t, b)
			refusal.Require(t, solve(t, b.circuit), tt.frames...)
		})
	}
}

// newRecord is the record w writes for a member whose old bits outside the mask are kept.
func newRecord(w ringrecords.Write, lists int64) ringrecords.Record {
	escrow := w.OldEscrow
	if escrow.Sign() == 0 {
		escrow = w.Entry.EscrowKey
	}
	return ringrecords.Record{Member: w.Entry.Member, Next: w.OldNext, Lists: big.NewInt(lists), EscrowKey: escrow}
}

// replaced is the seeded registry with low in alice's place.
func replaced(t *testing.T, low int64) *ringrecords.Registry {
	t.Helper()
	members := ringrecords.New(t)
	members.Apply(t, entry(low, ringrecords.AllowBit, ringrecords.AllowBit, 0))
	members.Apply(t, entry(0x30, ringrecords.EscrowBit, ringrecords.EscrowBit, 0xc1))
	return members
}

// fourRecords is the seeded registry with 0x40 on the allow list, its next index the first of a leaf group.
func fourRecords(t *testing.T) *ringrecords.Registry {
	t.Helper()
	members := seeded(t)
	members.Apply(t, entry(0x40, ringrecords.AllowBit, ringrecords.AllowBit, 0))
	return members
}

// replacedKeyRoot is the seeded registry with carol's key replaced by 0xc2, a root no
// fill-once write reaches.
func replacedKeyRoot(t *testing.T) *big.Int {
	t.Helper()
	members := ringrecords.New(t)
	members.Apply(t, entry(0x10, ringrecords.AllowBit, ringrecords.AllowBit, 0))
	members.Apply(t, entry(0x30, ringrecords.EscrowBit, ringrecords.EscrowBit, 0xc2))
	return members.Root()
}

func compile(t *testing.T, n int) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, registry.NewApplyRecordsCircuit(n), frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// The ring program verifies both keys with one BSB22 commitment over private wires.
func TestApplyRecordsKeys(t *testing.T) {
	pinned := map[int]int{1: 15492, registry.ApplyBatch: 232892}
	for _, n := range registry.ApplyWidths {
		cs := compile(t, n)
		if got := cs.GetNbConstraints(); got != pinned[n] {
			t.Errorf("apply %d constraints=%d, pinned %d", n, got, pinned[n])
		}
		commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
		if !ok || len(commitments) != 1 || commitments[0].NbPublicCommitted != 0 {
			t.Errorf("apply %d commitments %v", n, cs.GetCommitments())
		}
	}
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, registry.NewApplyRecordsCircuit(2)); err == nil {
		t.Fatal("compiled a capacity no apply key ships")
	}
}
